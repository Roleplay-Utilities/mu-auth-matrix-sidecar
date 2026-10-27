package main

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

const (
	deviceCookieName   = "mu_matrix_device_id"
	deviceCookieMaxAge = 365 * 24 * time.Hour
)

// Both the current and the original MSC-numbered Matrix device-scope prefixes are recognised, so
// the sidecar keeps working whichever one a given MU Auth / Zendrite version uses.
var deviceScopePrefixes = []string{
	"urn:matrix:client:device:",
	"urn:matrix:org.matrix.msc2967.client:device:",
}

// preferredDeviceScopePrefix is used whenever the sidecar itself has to mint a device scope.
const preferredDeviceScopePrefix = "urn:matrix:org.matrix.msc2967.client:device:"

var deviceIDRe = regexp.MustCompile(`^[A-Za-z0-9._~-]{1,64}$`)

// ───────────────────────────── cookie sealing ─────────────────────────────

// sealer provides authenticated, encrypted cookie values, so all per-login state (PKCE
// verifiers, the dashboard's own session tokens, the stable device id) can live entirely in the
// browser. Nothing is ever held server-side.
type sealer struct {
	gcm cipher.AEAD
}

func newSealer(key []byte) (*sealer, error) {
	block, err := aes.NewCipher(key) // Config guarantees key is exactly 32 bytes (AES-256)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &sealer{gcm: gcm}, nil
}

// seal serialises v to JSON, encrypts it, and returns a value safe to put directly in a cookie.
func (sl *sealer) seal(v any) (string, error) {
	plain, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, sl.gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	ct := sl.gcm.Seal(nonce, nonce, plain, nil)
	return base64.RawURLEncoding.EncodeToString(ct), nil
}

// open reverses seal and reports an error if the value is missing, malformed, expired-looking, or
// tampered with. GCM's authentication tag is what detects tampering; no separate HMAC is needed.
func (sl *sealer) open(value string, v any) error {
	ct, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil {
		return fmt.Errorf("bad cookie encoding: %w", err)
	}
	ns := sl.gcm.NonceSize()
	if len(ct) < ns {
		return errors.New("cookie value too short")
	}
	nonce, body := ct[:ns], ct[ns:]
	plain, err := sl.gcm.Open(nil, nonce, body, nil)
	if err != nil {
		return fmt.Errorf("cookie failed authentication: %w", err)
	}
	return json.Unmarshal(plain, v)
}

func clearCookie(w http.ResponseWriter, name, path string) {
	http.SetCookie(w, &http.Cookie{Name: name, Value: "", Path: path, MaxAge: -1, HttpOnly: true})
}

// ───────────────────────────── stable device id ─────────────────────────────

type deviceCookieValue struct {
	DeviceID string `json:"d"`
}

func randomDeviceID() string {
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	raw := make([]byte, 10)
	if _, err := rand.Read(raw); err != nil {
		panic(err) // crypto/rand failing indicates a broken system; nothing sensible to do here
	}
	out := make([]byte, 10)
	for i, v := range raw {
		out[i] = alphabet[int(v)%len(alphabet)]
	}
	return string(out)
}

// ensureDeviceID returns the stable device ID bound to this browser, creating and setting the
// cookie on first use. The ID itself is not secret; it's sealed only for consistency with the
// service's other cookies and so a client can't set an arbitrary value of its own choosing.
func (s *Server) ensureDeviceID(w http.ResponseWriter, r *http.Request) string {
	if c, err := r.Cookie(deviceCookieName); err == nil {
		var v deviceCookieValue
		if s.sealer.open(c.Value, &v) == nil && deviceIDRe.MatchString(v.DeviceID) {
			return v.DeviceID
		}
	}
	id := randomDeviceID()
	sealed, err := s.sealer.seal(deviceCookieValue{DeviceID: id})
	if err != nil {
		s.log.WithError(err).Error("failed to seal device cookie; continuing without persistence")
		return id
	}
	http.SetCookie(w, &http.Cookie{
		Name: deviceCookieName, Value: sealed, Path: "/", MaxAge: int(deviceCookieMaxAge.Seconds()),
		HttpOnly: true, Secure: s.cfg.PublicURL.Scheme == "https", SameSite: http.SameSiteLaxMode,
	})
	return id
}

// injectDeviceScope adds a stable Matrix device scope to scope only if the caller did not already
// request one of its own. An explicit device scope from a native client is never overridden:
// doing so could hand two different users of the same browser the same device ID, or break a
// native app that persists its own device ID outside of cookies entirely.
func injectDeviceScope(scope, deviceID string) string {
	for _, f := range strings.Fields(scope) {
		for _, p := range deviceScopePrefixes {
			if strings.HasPrefix(f, p) {
				return scope // caller already specified a device; leave it alone
			}
		}
	}
	return strings.TrimSpace(scope + " " + preferredDeviceScopePrefix + deviceID)
}

// ───────────────────────────── /oauth2/authorize, /oauth2/token ─────────────────────────────

func (s *Server) upstreamAuthorizeURL(ctx context.Context) (*url.URL, error) {
	doc, err := s.fetchDiscovery(ctx)
	if err != nil {
		return nil, err
	}
	raw := docString(doc, "authorization_endpoint")
	if raw == "" {
		return nil, errors.New("identity provider publishes no authorization_endpoint")
	}
	return url.Parse(raw)
}

// handleAuthorize is a transparent redirect to MU Auth's real authorization endpoint. The only
// thing it changes is the scope parameter, to bind this browser to a stable device id. The
// browser's eventual redirect back goes straight to whatever redirect_uri the caller supplied
// (Zendrite's SSO callback, or a native client's own) — never back through the sidecar.
func (s *Server) handleAuthorize(w http.ResponseWriter, r *http.Request) {
	target, err := s.upstreamAuthorizeURL(r.Context())
	if err != nil {
		s.log.WithError(err).Error("authorize: discovery fetch failed")
		http.Error(w, "identity provider unavailable", http.StatusBadGateway)
		return
	}
	q := r.URL.Query()
	deviceID := s.ensureDeviceID(w, r)

	// Catch the display name passed by the Matrix client
	displayName := q.Get("initial_device_display_name")
	if displayName == "" {
		displayName = q.Get("device_name") // Fallback alias some clients use
	}

	// If the client provided a custom name, stash it in a secure cookie so the sidecar remembers it
	if displayName != "" {
		s.storeDeviceDisplayName(w, deviceID, displayName)
	}

	q.Set("scope", injectDeviceScope(q.Get("scope"), deviceID))
	target.RawQuery = q.Encode()
	http.Redirect(w, r, target.String(), http.StatusFound)
}

// Helper to seal the display name into a temporary cookie
func (s *Server) storeDeviceDisplayName(w http.ResponseWriter, deviceID, displayName string) {
	payload := map[string]string{
		"device_id":    deviceID,
		"display_name": displayName,
	}
	sealed, err := s.sealer.seal(payload)
	if err != nil {
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "mu_dev_name_" + deviceID,
		Value:    sealed,
		Path:     "/",
		MaxAge:   3600, // 1 hour lifespan, plenty of time to finish login
		HttpOnly: true,
		Secure:   s.cfg.PublicURL.Scheme == "https",
		SameSite: http.SameSiteLaxMode,
	})
}

// handleToken is a pure reverse proxy to MU Auth's real token endpoint. No rewriting is needed
// here: the scope (and therefore the device) was already locked in at the authorize step, and the
// authorization code itself carries that forward.
func (s *Server) handleToken(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxReqBytes))
	if err != nil {
		writeOAuthError(w, http.StatusRequestEntityTooLarge, "invalid_request", "request body too large")
		return
	}
	doc, err := s.fetchDiscovery(r.Context())
	if err != nil {
		s.log.WithError(err).Error("token: discovery fetch failed")
		writeOAuthError(w, http.StatusBadGateway, "server_error", "identity provider unavailable")
		return
	}
	upstream := docString(doc, "token_endpoint")
	if upstream == "" {
		writeOAuthError(w, http.StatusBadGateway, "server_error", "identity provider publishes no token_endpoint")
		return
	}
	up, err := s.forwardForm(r.Context(), r, upstream, body)
	if err != nil {
		s.log.WithError(err).Error("token: upstream request failed")
		writeOAuthError(w, http.StatusBadGateway, "server_error", "identity provider unavailable")
		return
	}
	writeUpstream(w, up)
}
