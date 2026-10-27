package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"net/http"
	"net/url"
	"runtime/debug"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
)

// accountManagementActions are the MSC2965 account-management action identifiers
// (https://github.com/matrix-org/matrix-spec-proposals/pull/2965) this dashboard understands via
// its ?action=&device_id= query parameters, advertised in discovery so Matrix clients know which
// deep links are safe to send. These are the canonical values used by matrix-rust-sdk / MAS —
// note they are sessions_list / session_view / session_end, not devices_list / device_view /
// device_delete.
var accountManagementActions = []string{
	"org.matrix.profile",
	"org.matrix.sessions_list",
	"org.matrix.session_view",
	"org.matrix.session_end",
	"org.matrix.account_deactivate",
	"org.matrix.cross_signing_reset",
}

const (
	pendingCookieName   = "mu_dash_pending"
	sessionCookieName   = "mu_dash_session"
	pendingCookieMaxAge = 10 * time.Minute
	sessionCookieMaxAge = 30 * 24 * time.Hour // the cookie outlives the access token; refreshSession renews it
)

type pendingLogin struct {
	State    string `json:"s"`
	Verifier string `json:"v"`
}

type dashboardSession struct {
	AccessToken  string    `json:"a"`
	RefreshToken string    `json:"r"`
	ExpiresAt    time.Time `json:"e"`
}

func generatePKCE() (verifier, challenge string, err error) {
	raw := make([]byte, 32)
	if _, err = rand.Read(raw); err != nil {
		return
	}
	verifier = base64.RawURLEncoding.EncodeToString(raw)
	sum := sha256.Sum256([]byte(verifier))
	challenge = base64.RawURLEncoding.EncodeToString(sum[:])
	return
}

func randomState() string {
	raw := make([]byte, 24)
	if _, err := rand.Read(raw); err != nil {
		panic(err) // crypto/rand failing indicates a broken system; nothing sensible to do here
	}
	return base64.RawURLEncoding.EncodeToString(raw)
}

// ───────────────────────────── login / session ─────────────────────────────

// handleAccountPage serves the dashboard shell if the browser has a valid session, or starts a
// login otherwise. The device list itself is fetched client-side from /api/devices.
func (s *Server) handleAccountPage(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.readSession(r); ok {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		dashboardPage.Execute(w, nil)
		return
	}
	s.beginDashboardLogin(w, r)
}

func (s *Server) beginDashboardLogin(w http.ResponseWriter, r *http.Request) {
	target, err := s.upstreamAuthorizeURL(r.Context())
	if err != nil {
		s.log.WithError(err).Error("account: discovery fetch failed")
		http.Error(w, "identity provider unavailable", http.StatusBadGateway)
		return
	}
	verifier, challenge, err := generatePKCE()
	if err != nil {
		s.log.WithError(err).Error("account: failed to generate PKCE verifier")
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	state := randomState()
	sealed, err := s.sealer.seal(pendingLogin{State: state, Verifier: verifier})
	if err != nil {
		s.log.WithError(err).Error("account: failed to seal pending-login cookie")
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name: pendingCookieName, Value: sealed, Path: "/account", MaxAge: int(pendingCookieMaxAge.Seconds()),
		HttpOnly: true, Secure: s.cfg.PublicURL.Scheme == "https", SameSite: http.SameSiteLaxMode,
	})

	deviceID := s.ensureDeviceID(w, r)
	q := url.Values{
		"response_type":         {"code"},
		"client_id":             {s.cfg.DashboardClientID},
		"redirect_uri":          {s.dashboardRedirectURI()},
		"scope":                 {"urn:matrix:client:api:* " + preferredDeviceScopePrefix + deviceID},
		"state":                 {state},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
	}
	target.RawQuery = q.Encode()
	http.Redirect(w, r, target.String(), http.StatusFound)
}

func (s *Server) dashboardRedirectURI() string {
	return strings.TrimRight(s.cfg.PublicURL.String(), "/") + "/account/callback"
}

func (s *Server) handleAccountCallback(w http.ResponseWriter, r *http.Request) {
	clearCookie(w, pendingCookieName, "/account")

	q := r.URL.Query()
	if errCode := q.Get("error"); errCode != "" {
		s.log.WithField("error", errCode).Warn("account: login denied or failed at identity provider")
		http.Error(w, "login failed: "+errCode, http.StatusBadGateway)
		return
	}
	c, err := r.Cookie(pendingCookieName)
	if err != nil {
		http.Error(w, "login session expired, please try again", http.StatusBadRequest)
		return
	}
	var pending pendingLogin
	if s.sealer.open(c.Value, &pending) != nil || pending.State == "" ||
		subtle.ConstantTimeCompare([]byte(pending.State), []byte(q.Get("state"))) != 1 {
		http.Error(w, "login session expired, please try again", http.StatusBadRequest)
		return
	}

	doc, err := s.fetchDiscovery(r.Context())
	if err != nil {
		s.log.WithError(err).Error("account: discovery fetch failed")
		http.Error(w, "identity provider unavailable", http.StatusBadGateway)
		return
	}
	tokenEndpoint := docString(doc, "token_endpoint")
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {q.Get("code")},
		"redirect_uri":  {s.dashboardRedirectURI()},
		"code_verifier": {pending.Verifier},
		"client_id":     {s.cfg.DashboardClientID},
		"client_secret": {s.cfg.DashboardClientSecret},
	}
	up, err := s.postForm(r.Context(), tokenEndpoint, form)
	if err != nil {
		s.log.WithError(err).Error("account: token exchange request failed")
		http.Error(w, "login failed", http.StatusBadGateway)
		return
	}
	if up.status != http.StatusOK {
		s.log.WithField("status", up.status).Error("account: token exchange was rejected")
		http.Error(w, "login failed", http.StatusBadGateway)
		return
	}

	var tok struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		ExpiresIn    int    `json:"expires_in"`
	}
	if json.Unmarshal(up.body, &tok) != nil || tok.AccessToken == "" {
		s.log.Error("account: malformed token response from identity provider")
		http.Error(w, "login failed", http.StatusBadGateway)
		return
	}
	sess := dashboardSession{
		AccessToken: tok.AccessToken, RefreshToken: tok.RefreshToken,
		ExpiresAt: time.Now().Add(time.Duration(tok.ExpiresIn) * time.Second),
	}
	if err := s.writeSession(w, sess); err != nil {
		s.log.WithError(err).Error("account: failed to seal session cookie")
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, strings.TrimRight(s.cfg.PublicURL.String(), "/")+"/account", http.StatusFound)
}

func (s *Server) handleAccountLogout(w http.ResponseWriter, r *http.Request) {
	if sess, ok := s.readSession(r); ok {
		if doc, err := s.fetchDiscovery(r.Context()); err == nil {
			if rev := docString(doc, "revocation_endpoint"); rev != "" {
				form := url.Values{
					"token": {sess.AccessToken}, "token_type_hint": {"access_token"},
					"client_id": {s.cfg.DashboardClientID}, "client_secret": {s.cfg.DashboardClientSecret},
				}
				if _, err := s.postForm(r.Context(), rev, form); err != nil {
					s.log.WithError(err).Warn("account: revoking session at logout failed")
				}
			}
		}
	}
	clearCookie(w, sessionCookieName, "/")
	w.WriteHeader(http.StatusOK)
}

func (s *Server) readSession(r *http.Request) (dashboardSession, bool) {
	c, err := r.Cookie(sessionCookieName)
	if err != nil {
		return dashboardSession{}, false
	}
	var sess dashboardSession
	if s.sealer.open(c.Value, &sess) != nil || sess.AccessToken == "" {
		return dashboardSession{}, false
	}
	return sess, true
}

func (s *Server) writeSession(w http.ResponseWriter, sess dashboardSession) error {
	sealed, err := s.sealer.seal(sess)
	if err != nil {
		return err
	}
	http.SetCookie(w, &http.Cookie{
		Name: sessionCookieName, Value: sealed, Path: "/", MaxAge: int(sessionCookieMaxAge.Seconds()),
		HttpOnly: true, Secure: s.cfg.PublicURL.Scheme == "https", SameSite: http.SameSiteLaxMode,
	})
	return nil
}

// refreshSession renews the access token if it's at or near expiry, persisting the result.
func (s *Server) refreshSession(ctx context.Context, w http.ResponseWriter, sess dashboardSession) (dashboardSession, bool) {
	if time.Until(sess.ExpiresAt) > 30*time.Second {
		return sess, true
	}
	if sess.RefreshToken == "" {
		return sess, false
	}
	doc, err := s.fetchDiscovery(ctx)
	if err != nil {
		s.log.WithError(err).Error("account: discovery fetch failed during refresh")
		return sess, false
	}
	form := url.Values{
		"grant_type": {"refresh_token"}, "refresh_token": {sess.RefreshToken},
		"client_id": {s.cfg.DashboardClientID}, "client_secret": {s.cfg.DashboardClientSecret},
	}
	up, err := s.postForm(ctx, docString(doc, "token_endpoint"), form)
	if err != nil || up.status != http.StatusOK {
		return sess, false
	}
	var tok struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		ExpiresIn    int    `json:"expires_in"`
	}
	if json.Unmarshal(up.body, &tok) != nil || tok.AccessToken == "" {
		return sess, false
	}
	next := dashboardSession{
		AccessToken: tok.AccessToken, RefreshToken: tok.RefreshToken,
		ExpiresAt: time.Now().Add(time.Duration(tok.ExpiresIn) * time.Second),
	}
	if next.RefreshToken == "" {
		next.RefreshToken = sess.RefreshToken // not every provider rotates the refresh token
	}
	if err := s.writeSession(w, next); err != nil {
		s.log.WithError(err).Error("account: failed to persist refreshed session")
	}
	return next, true
}

// authenticatedSession reads the session cookie, refreshes it if needed, and confirms the
// resulting access token is still good by calling the homeserver's own whoami endpoint.
func (s *Server) authenticatedSession(w http.ResponseWriter, r *http.Request) (dashboardSession, string, bool) {
	sess, ok := s.readSession(r)
	if !ok {
		writeMatrixError(w, http.StatusUnauthorized, "M_MISSING_TOKEN", "not logged in")
		return dashboardSession{}, "", false
	}
	sess, ok = s.refreshSession(r.Context(), w, sess)
	if !ok {
		clearCookie(w, sessionCookieName, "/")
		writeMatrixError(w, http.StatusUnauthorized, "M_UNKNOWN_TOKEN", "session expired, please log in again")
		return dashboardSession{}, "", false
	}
	userID, err := s.whoami(r.Context(), sess.AccessToken)
	if err != nil {
		s.log.WithError(err).Error("account: whoami failed")
		writeMatrixError(w, http.StatusBadGateway, "M_UNKNOWN", "homeserver unreachable")
		return dashboardSession{}, "", false
	}
	return sess, userID, true
}

func (s *Server) whoami(ctx context.Context, accessToken string) (string, error) {
	target := strings.TrimRight(s.cfg.ZendriteURL.String(), "/") + "/_matrix/client/v3/account/whoami"
	ctx, cancel := context.WithTimeout(ctx, upstreamTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	resp, err := s.http.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("whoami returned status %d", resp.StatusCode)
	}
	var out struct {
		UserID string `json:"user_id"`
	}
	if json.NewDecoder(io.LimitReader(resp.Body, maxRespBytes)).Decode(&out) != nil || out.UserID == "" {
		return "", errors.New("malformed whoami response")
	}
	return out.UserID, nil
}

// localpartOf extracts "alice" from "@alice:example.com".
func localpartOf(userID string) string {
	userID = strings.TrimPrefix(userID, "@")
	if i := strings.IndexByte(userID, ':'); i >= 0 {
		return userID[:i]
	}
	return userID
}

// ───────────────────────────── /api/devices ─────────────────────────────

// handleListDevices lists the authenticated user's own devices, straight from Zendrite's normal
// (non-admin) client-server API using the user's own access token. This is read-only and scoped
// to "my own devices" automatically, by definition of whose bearer token is used.
func (s *Server) handleListDevices(w http.ResponseWriter, r *http.Request) {
	sess, _, ok := s.authenticatedSession(w, r)
	if !ok {
		return
	}
	target := strings.TrimRight(s.cfg.ZendriteURL.String(), "/") + "/_matrix/client/v3/devices"
	ctx, cancel := context.WithTimeout(r.Context(), upstreamTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		writeMatrixError(w, http.StatusInternalServerError, "M_UNKNOWN", "internal error")
		return
	}
	req.Header.Set("Authorization", "Bearer "+sess.AccessToken)
	resp, err := s.http.Do(req)
	if err != nil {
		s.log.WithError(err).Error("account: list devices failed")
		writeMatrixError(w, http.StatusBadGateway, "M_UNKNOWN", "homeserver unreachable")
		return
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, maxRespBytes))
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(resp.StatusCode)
	w.Write(body)
}

// handleDeleteDevice deletes one of the authenticated user's own devices. Zendrite rejects device
// deletion through its normal client-server API under delegated auth (device management is meant
// to happen at the provider), so this goes through the privileged MAS admin API instead — but
// only after confirming, using the user's own access token, that the device actually belongs to
// them. The admin API itself has no such check: it will act on any localpart/device_id it's
// given, so skipping this confirmation would let any logged-in dashboard user delete any device
// belonging to any user on the server.
func (s *Server) handleDeleteDevice(w http.ResponseWriter, r *http.Request) {
	deviceID := r.PathValue("device_id")
	if !deviceIDRe.MatchString(deviceID) {
		writeMatrixError(w, http.StatusBadRequest, "M_INVALID_PARAM", "invalid device_id")
		return
	}
	sess, userID, ok := s.authenticatedSession(w, r)
	if !ok {
		return
	}
	owns, err := s.userOwnsDevice(r.Context(), sess.AccessToken, deviceID)
	if err != nil {
		s.log.WithError(err).Error("account: device ownership check failed")
		writeMatrixError(w, http.StatusBadGateway, "M_UNKNOWN", "homeserver unreachable")
		return
	}
	if !owns {
		// The same response Zendrite itself would give for a device that isn't yours: this never
		// confirms or denies that the device ID exists on someone else's account.
		writeMatrixError(w, http.StatusNotFound, "M_NOT_FOUND", "device not found")
		return
	}
	localpart := localpartOf(userID)
	if err := s.zendriteAdminOK(r.Context(), "delete_device", map[string]any{"localpart": localpart, "device_id": deviceID}); err != nil {
		s.log.WithError(err).WithFields(logrus.Fields{"localpart": localpart, "device": deviceID}).Error("account: delete_device failed")
		writeMatrixError(w, http.StatusBadGateway, "M_UNKNOWN", "homeserver unreachable")
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte("{}"))
}

func (s *Server) userOwnsDevice(ctx context.Context, accessToken, deviceID string) (bool, error) {
	target := strings.TrimRight(s.cfg.ZendriteURL.String(), "/") + "/_matrix/client/v3/devices/" + url.PathEscape(deviceID)
	ctx, cancel := context.WithTimeout(ctx, upstreamTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	resp, err := s.http.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, io.LimitReader(resp.Body, maxRespBytes))
	switch resp.StatusCode {
	case http.StatusOK:
		return true, nil
	case http.StatusNotFound:
		return false, nil
	default:
		return false, fmt.Errorf("device lookup returned status %d", resp.StatusCode)
	}
}

// ───────────────────────────── /api/profile ─────────────────────────────

// handleProfileGet returns the authenticated user's own profile, straight from Zendrite's normal
// client-server API using the user's own access token.
func (s *Server) handleProfileGet(w http.ResponseWriter, r *http.Request) {
	sess, userID, ok := s.authenticatedSession(w, r)
	if !ok {
		return
	}
	target := strings.TrimRight(s.cfg.ZendriteURL.String(), "/") + "/_matrix/client/v3/profile/" + url.PathEscape(userID)
	ctx, cancel := context.WithTimeout(r.Context(), upstreamTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		writeMatrixError(w, http.StatusInternalServerError, "M_UNKNOWN", "internal error")
		return
	}
	req.Header.Set("Authorization", "Bearer "+sess.AccessToken)
	resp, err := s.http.Do(req)
	if err != nil {
		s.log.WithError(err).Error("account: fetch profile failed")
		writeMatrixError(w, http.StatusBadGateway, "M_UNKNOWN", "homeserver unreachable")
		return
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, maxRespBytes))
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(resp.StatusCode)
	w.Write(body)
}

// handleProfilePut sets the authenticated user's own display name, straight through to Zendrite's
// normal client-server API using the user's own access token.
func (s *Server) handleProfilePut(w http.ResponseWriter, r *http.Request) {
	sess, userID, ok := s.authenticatedSession(w, r)
	if !ok {
		return
	}
	raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxReqBytes))
	if err != nil {
		writeMatrixError(w, http.StatusRequestEntityTooLarge, "M_TOO_LARGE", "request body too large")
		return
	}
	var in struct {
		DisplayName string `json:"displayname"`
	}
	if json.Unmarshal(raw, &in) != nil {
		writeMatrixError(w, http.StatusBadRequest, "M_NOT_JSON", "body must be a JSON object")
		return
	}
	if len(in.DisplayName) > 256 {
		writeMatrixError(w, http.StatusBadRequest, "M_INVALID_PARAM", "display name too long")
		return
	}
	target := strings.TrimRight(s.cfg.ZendriteURL.String(), "/") + "/_matrix/client/v3/profile/" + url.PathEscape(userID) + "/displayname"
	payload, _ := json.Marshal(map[string]string{"displayname": in.DisplayName})
	ctx, cancel := context.WithTimeout(r.Context(), upstreamTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, target, bytes.NewReader(payload))
	if err != nil {
		writeMatrixError(w, http.StatusInternalServerError, "M_UNKNOWN", "internal error")
		return
	}
	req.Header.Set("Authorization", "Bearer "+sess.AccessToken)
	req.Header.Set("Content-Type", "application/json")
	resp, err := s.http.Do(req)
	if err != nil {
		s.log.WithError(err).Error("account: update profile failed")
		writeMatrixError(w, http.StatusBadGateway, "M_UNKNOWN", "homeserver unreachable")
		return
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, maxRespBytes))
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(resp.StatusCode)
	w.Write(body)
}

// ───────────────────────────── /api/account/* ─────────────────────────────

// handleDeactivateAccount deactivates the authenticated user's own account. Zendrite's normal
// client-server deactivation endpoint is blocked under delegated auth ("handled at the
// provider"), so this goes through the privileged MAS admin API instead — always for the caller's
// own localpart, derived from their own authenticated session via whoami, never anything the
// browser could supply directly.
func (s *Server) handleDeactivateAccount(w http.ResponseWriter, r *http.Request) {
	sess, userID, ok := s.authenticatedSession(w, r)
	if !ok {
		return
	}
	localpart := localpartOf(userID)
	if err := s.zendriteAdminOK(r.Context(), "delete_user", map[string]any{"localpart": localpart}); err != nil {
		s.log.WithError(err).WithField("localpart", localpart).Error("account: deactivation failed")
		writeMatrixError(w, http.StatusBadGateway, "M_UNKNOWN", "homeserver unreachable")
		return
	}
	if doc, err := s.fetchDiscovery(r.Context()); err == nil {
		if rev := docString(doc, "revocation_endpoint"); rev != "" {
			form := url.Values{
				"token": {sess.AccessToken}, "token_type_hint": {"access_token"},
				"client_id": {s.cfg.DashboardClientID}, "client_secret": {s.cfg.DashboardClientSecret},
			}
			if _, err := s.postForm(r.Context(), rev, form); err != nil {
				s.log.WithError(err).Warn("account: revoking session after deactivation failed")
			}
		}
	}
	clearCookie(w, sessionCookieName, "/")
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Write([]byte("{}"))
}

// handleConfirmCrossSigningReset confirms a pending cross-signing reset for the authenticated
// user's own account via Zendrite's admin API. Zendrite's own confirmation window is single-use
// and valid for 10 minutes; this just relays the confirmation once the user has agreed in the
// dashboard UI, always for the caller's own localpart.
func (s *Server) handleConfirmCrossSigningReset(w http.ResponseWriter, r *http.Request) {
	_, userID, ok := s.authenticatedSession(w, r)
	if !ok {
		return
	}
	localpart := localpartOf(userID)
	if err := s.zendriteAdminOK(r.Context(), "allow_cross_signing_reset", map[string]any{"localpart": localpart}); err != nil {
		s.log.WithError(err).WithField("localpart", localpart).Error("account: cross-signing reset confirmation failed")
		writeMatrixError(w, http.StatusBadGateway, "M_UNKNOWN", "homeserver unreachable")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Write([]byte("{}"))
}

// ───────────────────────────── /_synapse/mas/* admin passthrough ─────────────────────────────

// handleManage returns a handler that authenticates the caller with the shared admin bearer
// token and forwards one specific, whitelisted action to Zendrite's MAS admin API. Each of the 12
// actions is registered under its own exact path and method in routes() — there is no wildcard
// matching here, so nothing outside this explicit set is ever reachable.
func (s *Server) handleManage(action, method string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !s.checkAdminBearer(r) {
			w.Header().Set("WWW-Authenticate", "Bearer")
			writeMatrixError(w, http.StatusUnauthorized, "M_UNAUTHORIZED", "invalid credentials")
			return
		}

		var body map[string]any
		if method == http.MethodGet {
			body = map[string]any{}
			for k, v := range r.URL.Query() {
				if len(v) > 0 {
					body[k] = v[0]
				}
			}
		} else {
			raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxReqBytes))
			if err != nil {
				writeMatrixError(w, http.StatusRequestEntityTooLarge, "M_TOO_LARGE", "request body too large")
				return
			}
			if len(raw) > 0 {
				if json.Unmarshal(raw, &body) != nil {
					writeMatrixError(w, http.StatusBadRequest, "M_NOT_JSON", "body must be a JSON object")
					return
				}
			}
		}
		if msg := validateManageBody(body); msg != "" {
			writeMatrixError(w, http.StatusBadRequest, "M_INVALID_PARAM", msg)
			return
		}

		up, err := s.zendriteAdmin(r.Context(), method, action, body)
		if err != nil {
			s.log.WithError(err).WithField("action", action).Error("manage: zendrite unreachable")
			writeMatrixError(w, http.StatusBadGateway, "M_UNKNOWN", "homeserver unreachable")
			return
		}
		s.log.WithFields(logrus.Fields{"action": action, "status": up.status}).Info("manage call")
		writeUpstream(w, up)
	}
}

func (s *Server) checkAdminBearer(r *http.Request) bool {
	h := r.Header.Get("Authorization")
	got := strings.TrimPrefix(h, "Bearer ")
	if got == h || got == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(got), []byte(s.cfg.ZendriteAdminToken)) == 1
}

func validateManageBody(m map[string]any) string {
	if v, ok := m["localpart"]; ok {
		str, ok := v.(string)
		if !ok || !localpartRe.MatchString(str) {
			return "invalid localpart"
		}
	}
	if v, ok := m["device_id"]; ok {
		str, ok := v.(string)
		if !ok || !deviceIDRe.MatchString(str) {
			return "invalid device_id"
		}
	}
	return ""
}

// ───────────────────────────── dashboard HTML ─────────────────────────────

var dashboardPage = template.Must(template.New("account").Parse(`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Your Matrix account</title>
<style>
  :root { color-scheme: light dark; --fg:#1a1a1a; --bg:#fafafa; --card:#fff; --border:#ddd; --danger:#c0392b; }
  @media (prefers-color-scheme: dark) { :root { --fg:#eee; --bg:#121212; --card:#1e1e1e; --border:#333; } }
  body { font-family: system-ui, sans-serif; max-width: 640px; margin: 2rem auto; padding: 0 1rem; color: var(--fg); background: var(--bg); }
  h1 { font-size: 1.4rem; }
  h2 { font-size: 1.05rem; margin: 0 0 .6rem; }
  section { margin-bottom: 2rem; }
  label { display: block; font-size: .9rem; margin-bottom: .6rem; }
  input[type="text"] { display: block; width: 100%; max-width: 320px; margin-top: .3rem; padding: .4rem .6rem; box-sizing: border-box; border-radius: 6px; border: 1px solid var(--border); background: var(--card); color: inherit; font: inherit; }
  .hint { font-size: .85rem; opacity: .75; margin-left: .6rem; }
  .device { background: var(--card); border: 1px solid var(--border); border-radius: 8px; padding: .75rem 1rem; margin-bottom: .6rem; display: flex; justify-content: space-between; align-items: center; gap: 1rem; }
  .device.highlight { border-color: var(--danger); box-shadow: 0 0 0 2px var(--danger); }
  .device .meta { min-width: 0; }
  .device .name { font-weight: 600; }
  .device .id, .device .seen { font-size: .8rem; opacity: .7; word-break: break-all; }
  button { border: 1px solid var(--border); background: transparent; color: inherit; border-radius: 6px; padding: .4rem .8rem; cursor: pointer; font: inherit; }
  button.danger { color: var(--danger); border-color: var(--danger); }
  button:disabled { opacity: .5; cursor: default; }
  #status { font-size: .9rem; opacity: .8; }
  #logout { float: right; }
  #reset-banner { background: var(--card); border: 1px solid var(--danger); border-radius: 8px; padding: 1rem; }
  #reset-banner p { font-size: .9rem; }
  .danger-zone { border-top: 1px solid var(--border); padding-top: 1.2rem; }
  .danger-zone p { font-size: .9rem; opacity: .85; }
</style>
</head>
<body>
  <form id="logout" method="post" action="/account/logout" onsubmit="return confirm('Log out of the dashboard?')">
    <button type="submit">Log out</button>
  </form>
  <h1>Your Matrix account</h1>

  <section id="reset-banner" hidden>
    <h2>Reset cross-signing keys?</h2>
    <p>A Matrix client has asked to reset your cross-signing keys. Only confirm this if you started this yourself, from one of your own devices.</p>
    <button id="confirm-reset" class="danger">Confirm reset</button>
    <button id="dismiss-reset">Dismiss</button>
  </section>

  <section id="profile-section">
    <h2>Profile</h2>
    <label>Display name
      <input id="displayname-input" type="text" maxlength="256">
    </label>
    <button id="save-profile">Save</button>
    <span id="profile-status" class="hint"></span>
  </section>

  <section id="sessions-section">
    <h2>Sessions</h2>
    <p id="status">Loading devices…</p>
    <div id="devices"></div>
  </section>

  <section class="danger-zone">
    <h2>Danger zone</h2>
    <p>Deactivating your account is permanent and cannot be undone.</p>
    <button id="deactivate" class="danger">Deactivate account</button>
  </section>

<script>
const params = new URLSearchParams(location.search);
const action = params.get('action');
const targetDevice = params.get('device_id');
let autoEndTriggered = false;

// ---- profile ----
async function loadProfile() {
  try {
    const resp = await fetch('/api/profile', { credentials: 'same-origin' });
    if (resp.ok) {
      const data = await resp.json();
      document.getElementById('displayname-input').value = data.displayname || '';
    }
  } catch (e) {}
}
document.getElementById('save-profile').onclick = async () => {
  const btn = document.getElementById('save-profile');
  const status = document.getElementById('profile-status');
  btn.disabled = true;
  status.textContent = 'Saving…';
  try {
    const resp = await fetch('/api/profile', {
      method: 'PUT', credentials: 'same-origin',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ displayname: document.getElementById('displayname-input').value }),
    });
    status.textContent = resp.ok ? 'Saved.' : 'Could not save (' + resp.status + ').';
  } catch (e) {
    status.textContent = 'Could not save.';
  }
  btn.disabled = false;
};
loadProfile();
if (action === 'org.matrix.profile') {
  document.getElementById('displayname-input').focus();
}

// ---- cross-signing reset banner ----
if (action === 'org.matrix.cross_signing_reset') {
  document.getElementById('reset-banner').hidden = false;
}
document.getElementById('dismiss-reset').onclick = () => {
  document.getElementById('reset-banner').hidden = true;
};
document.getElementById('confirm-reset').onclick = async () => {
  const btn = document.getElementById('confirm-reset');
  btn.disabled = true;
  try {
    const resp = await fetch('/api/account/confirm-cross-signing-reset', { method: 'POST', credentials: 'same-origin' });
    if (resp.ok) {
      document.getElementById('reset-banner').innerHTML = '<h2>Done</h2><p>Your cross-signing keys can now be reset from the client that asked for it.</p>';
    } else {
      alert('Could not confirm the reset (' + resp.status + ').');
      btn.disabled = false;
    }
  } catch (e) {
    alert('Could not confirm the reset.');
    btn.disabled = false;
  }
};

// ---- sessions ----
async function removeDevice(id, btn) {
  if (!confirm('Sign out this device?')) return;
  btn.disabled = true;
  try {
    const resp = await fetch('/api/devices/' + encodeURIComponent(id), { method: 'DELETE', credentials: 'same-origin' });
    if (resp.ok) { load(); } else { alert('Could not sign out that device (' + resp.status + ').'); btn.disabled = false; }
  } catch (e) {
    alert('Could not sign out that device.');
    btn.disabled = false;
  }
}

async function load() {
  const status = document.getElementById('status');
  const list = document.getElementById('devices');
  try {
    const resp = await fetch('/api/devices', { credentials: 'same-origin' });
    if (resp.status === 401) { location.reload(); return; }
    if (!resp.ok) { status.textContent = 'Could not load devices (' + resp.status + ').'; return; }
    const data = await resp.json();
    const devices = data.devices || [];
    status.textContent = devices.length + ' device' + (devices.length === 1 ? '' : 's');
    list.innerHTML = '';
    for (const d of devices) {
      const row = document.createElement('div');
      row.className = 'device' + (d.device_id === targetDevice ? ' highlight' : '');
      row.id = 'device-' + d.device_id;
      const meta = document.createElement('div');
      meta.className = 'meta';
      const name = document.createElement('div');
      name.className = 'name';
      name.textContent = d.display_name || '(unnamed device)';
      const id = document.createElement('div');
      id.className = 'id';
      id.textContent = d.device_id;
      meta.append(name, id);
      if (d.last_seen_ts) {
        const seen = document.createElement('div');
        seen.className = 'seen';
        seen.textContent = 'Last seen ' + new Date(d.last_seen_ts).toLocaleString();
        meta.append(seen);
      }
      const btn = document.createElement('button');
      btn.className = 'danger';
      btn.textContent = 'Sign out';
      btn.onclick = () => removeDevice(d.device_id, btn);
      row.append(meta, btn);
      list.append(row);
    }
    if (targetDevice) {
      const row = document.getElementById('device-' + targetDevice);
      if (row) row.scrollIntoView({ behavior: 'smooth', block: 'center' });
      if (action === 'org.matrix.session_end' && !autoEndTriggered) {
        autoEndTriggered = true;
        const btn = row ? row.querySelector('button') : null;
        if (btn) removeDevice(targetDevice, btn);
      }
    }
  } catch (e) {
    status.textContent = 'Could not load devices.';
  }
}
load();

// ---- danger zone ----
document.getElementById('deactivate').onclick = async () => {
  if (!confirm('Deactivate your account? This cannot be undone.')) return;
  if (!confirm('Are you absolutely sure? You will be signed out everywhere and this cannot be reversed.')) return;
  const btn = document.getElementById('deactivate');
  btn.disabled = true;
  try {
    const resp = await fetch('/api/account/deactivate', { method: 'POST', credentials: 'same-origin' });
    if (resp.ok) {
      document.body.innerHTML = '<h1>Account deactivated</h1><p>Your account has been deactivated.</p>';
    } else {
      alert('Could not deactivate your account (' + resp.status + ').');
      btn.disabled = false;
    }
  } catch (e) {
    alert('Could not deactivate your account.');
    btn.disabled = false;
  }
};
</script>
</body>
</html>
`))

func (s *Server) handleLandingPage(w http.ResponseWriter, r *http.Request) {
    if r.URL.Path != "/" {
        http.NotFound(w, r)
        return
    }

    // Version lookup logic...
    version := Version
    if version == "v1.0.0" {
        if info, ok := debug.ReadBuildInfo(); ok {
            for _, setting := range info.Settings {
                if setting.Key == "vcs.revision" && len(setting.Value) >= 7 {
                    version = setting.Value[:7]
                    break
                }
            }
        }
    }

    // Calculate live uptime
    uptimeStr := formatUptime(time.Since(s.startTime))

    html := fmt.Sprintf(`<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>MU Matrix Sidecar</title>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            background-color: #0f172a;
            color: #e2e8f0;
            display: flex;
            justify-content: center;
            align-items: center;
            height: 100vh;
            margin: 0;
        }
        .card {
            background-color: #1e293b;
            padding: 2.5rem;
            border-radius: 12px;
            box-shadow: 0 10px 25px -5px rgba(0, 0, 0, 0.3);
            max-width: 480px;
            width: 100%%;
            border: 1px solid #334155;
            text-align: center;
        }
        h1 {
            font-size: 1.5rem;
            margin-top: 0;
            color: #f8fafc;
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 8px;
        }
        .badge {
            background-color: #0284c7;
            color: #ffffff;
            font-size: 0.75rem;
            padding: 2px 8px;
            border-radius: 9999px;
            font-weight: 600;
        }
        p {
            color: #94a3b8;
            font-size: 0.95rem;
            line-height: 1.5;
        }
        .jab {
            font-style: italic;
            color: #cbd5e1;
            background: #0f172a;
            padding: 12px;
            border-radius: 8px;
            border-left: 3px solid #0ea5e9;
            margin: 1.5rem 0;
            text-align: left;
            font-size: 0.85rem;
        }
        .meta {
            font-size: 0.8rem;
            color: #64748b;
            margin-top: 1.5rem;
            border-top: 1px solid #334155;
            padding-top: 1rem;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        .links {
            margin-top: 1rem;
            display: flex;
            justify-content: center;
            gap: 12px;
            font-size: 0.9rem;
        }
        a {
            color: #38bdf8;
            text-decoration: none;
        }
        a:hover {
            text-decoration: underline;
        }
        .dot {
            color: #475569;
        }
    </style>
</head>
<body>
    <div class="card">
        <h1>Running Sidecar <span class="badge">%s</span></h1>
        <p>A lightweight MAS alternative built for OIDC with MU Auth on Zendrite homeservers.</p>
        
        <div class="jab">
            Because configuring standard MAS and Matrix OIDC shouldn't require a master's degree in OAuth voodoo, dark magic, and prayer.
        </div>

        <p style="font-size: 0.8rem; color: #64748b;">
            <em>Note: Other homeservers may technically work, but only Zendrite is officially validated.</em>
        </p>

        <div class="links">
            <a href="https://mega-utilities.com" target="_blank">Mega Utilities</a>
            <span class="dot">•</span>
            <a href="https://matrix.to/#/#mu:matrix.mega-utilities.com" target="_blank">MU Matrix Space</a>
            <span class="dot">•</span>
            <a href="https://github.com/Roleplay-Utilities/mu-auth-matrix-sidecar" target="_blank">GitHub</a>
        </div>

        <div class="meta">
            <span>Created by Mega Utilities</span>
            <span>Uptime: <strong>%s</strong></span>
        </div>
    </div>
</body>
</html>`, version, uptimeStr)

    w.Header().Set("Content-Type", "text/html; charset=utf-8")
    w.WriteHeader(http.StatusOK)
    w.Write([]byte(html))
}