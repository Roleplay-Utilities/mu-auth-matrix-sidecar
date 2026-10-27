package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
)

// provisionCache remembers which (localpart, device) pairs were provisioned recently, so a
// Zendrite re-checking introspection every ~30 seconds (its own documented cache interval)
// doesn't cause a repeat call to Zendrite's admin API on every single check. This is purely an
// in-process performance optimisation: it holds no session data, is safe to lose on restart (the
// next introspection just re-provisions, which is idempotent), and is not shared across replicas.
type provisionCache struct {
	mu      sync.Mutex
	entries map[string]time.Time // "localpart\x00device" -> expiry
}

func (c *provisionCache) fresh(key string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	exp, ok := c.entries[key]
	return ok && time.Now().Before(exp)
}

func (c *provisionCache) mark(key string, ttl time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.entries) > 100000 { // crude guard against unbounded growth if sweep falls behind
		c.entries = make(map[string]time.Time)
	}
	c.entries[key] = time.Now().Add(ttl)
}

func (c *provisionCache) sweep() {
	now := time.Now()
	c.mu.Lock()
	defer c.mu.Unlock()
	for k, exp := range c.entries {
		if now.After(exp) {
			delete(c.entries, k)
		}
	}
}

// adminScope is the scope value Zendrite's own account-type check looks for
// (strings.Contains(introspection.Scope, "urn:synapse:admin:*")) to treat a session as an admin.
const adminScope = "urn:synapse:admin:*"

// injectAdminScope appends adminScope to scope when isAdmin is true and it isn't already present
// (MU Auth itself might already grant it to some accounts), so Zendrite's own scope-based
// account-type check promotes the session — with no database write, on this or any other
// instance, and nothing for the operator to do beyond listing a username in config.
func injectAdminScope(scope string, isAdmin bool) string {
	if !isAdmin {
		return scope
	}
	for _, f := range strings.Fields(scope) {
		if f == adminScope {
			return scope // already present
		}
	}
	return strings.TrimSpace(scope + " " + adminScope)
}


// handleIntrospect forwards an RFC 7662 introspection request to MU Auth, then — if and only if
// the token is active — lazily provisions the user and device on Zendrite, and promotes the
// session to admin if the username is in the operator's configured ADMIN_USERNAMES list, before
// relaying the response back. The response is decoded into a generic map rather than a narrow
// struct, so every field MU Auth returns (exp, client_id, token_type, iat, aud, and anything this
// service doesn't otherwise look at) survives being re-encoded, and only "scope" is ever changed.
func (s *Server) handleIntrospect(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxReqBytes))
	if err != nil {
		writeOAuthError(w, http.StatusRequestEntityTooLarge, "invalid_request", "request body too large")
		return
	}
	doc, err := s.fetchDiscovery(r.Context())
	if err != nil {
		s.log.WithError(err).Error("introspect: discovery fetch failed")
		writeOAuthError(w, http.StatusBadGateway, "server_error", "identity provider unavailable")
		return
	}
	upstream := docString(doc, "introspection_endpoint")
	if upstream == "" {
		writeOAuthError(w, http.StatusBadGateway, "server_error", "identity provider publishes no introspection_endpoint")
		return
	}
	up, err := s.forwardForm(r.Context(), r, upstream, body)
	if err != nil {
		s.log.WithError(err).Error("introspect: upstream request failed")
		writeOAuthError(w, http.StatusBadGateway, "server_error", "identity provider unavailable")
		return
	}
	if up.status != http.StatusOK {
		writeUpstream(w, up)
		return
	}

	var payload map[string]any
	if json.Unmarshal(up.body, &payload) != nil {
		s.log.Error("introspect: upstream response was not valid JSON")
		writeOAuthError(w, http.StatusBadGateway, "server_error", "identity provider returned a malformed response")
		return
	}
	active, _ := payload["active"].(bool)
	if !active {
		writeUpstream(w, up) // {"active": false, ...}: nothing to provision or promote
		return
	}
	rawUsername, _ := payload["preferred_username"].(string)
	if strings.TrimSpace(rawUsername) == "" {
		rawUsername, _ = payload["username"].(string)
	}

	username := strings.ToLower(strings.TrimSpace(rawUsername))

	if !localpartRe.MatchString(username) {
		s.log.WithField("username", username).Error("introspect: upstream username is not a valid Matrix localpart")
		writeInactive(w)
		return
	}
	scope, _ := payload["scope"].(string)
	device := extractDeviceScope(scope)

	if err := s.ensureProvisioned(r.Context(), username, device); err != nil {
		// Fail closed: Zendrite must never treat a token as valid for a user or device that may
		// not actually exist on the homeserver yet.
		s.log.WithError(err).WithFields(logrus.Fields{"username": username, "device": device}).
			Error("introspect: provisioning failed, reporting token as inactive")
		writeInactive(w)
		return
	}

	payload["scope"] = injectAdminScope(scope, s.cfg.AdminUsernames[username])

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	json.NewEncoder(w).Encode(payload)
}

func writeInactive(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]bool{"active": false})
}

func extractDeviceScope(scope string) string {
	for _, f := range strings.Fields(scope) {
		for _, p := range deviceScopePrefixes {
			if strings.HasPrefix(f, p) {
				id := strings.TrimPrefix(f, p)
				if deviceIDRe.MatchString(id) {
					return id
				}
			}
		}
	}
	return ""
}

func (s *Server) getStoredDisplayName(deviceID string) string {
    s.deviceNames.mu.Lock()
    defer s.deviceNames.mu.Unlock()
    return s.deviceNames.entries[deviceID]
}

func (s *Server) ensureProvisioned(ctx context.Context, localpart, device string) error {
	key := localpart + "\x00" + device
	if s.provisioned.fresh(key) {
		return nil
	}

	if err := s.zendriteAdminOK(ctx, "provision_user", map[string]any{"localpart": localpart}); err != nil {
		return err
	}

	if device != "" {
		// Look up the display name the client passed during authorization
		displayName := s.getStoredDisplayName(device)
		if displayName == "" {
			displayName = "Matrix Client" // Final fallback only if nothing was passed
		}

		if err := s.zendriteAdminOK(ctx, "upsert_device", map[string]any{
			"localpart":    localpart,
			"device_id":    device,
			"display_name": displayName,
		}); err != nil {
			return err
		}
	}

	s.provisioned.mark(key, s.cfg.ProvisionCacheTTL)
	return nil
}
