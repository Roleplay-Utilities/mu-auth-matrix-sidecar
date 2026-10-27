package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

// jwksCacheTTL mirrors the 30-minute cache Zendrite documents for its own JWKS proxy.
const jwksCacheTTL = 30 * time.Minute

// discoveryCache holds the last-fetched upstream discovery document, keyed by nothing (there's
// only ever one, MU_AUTH_ISSUER). A stale copy is served if a refresh fails, same as Zendrite's
// own documented behaviour for its JWKS proxy.
type discoveryCache struct {
	mu      sync.RWMutex
	doc     map[string]any
	fetched time.Time
}

// jwksCache holds the last-fetched upstream JWKS document as raw bytes: the sidecar never parses
// it, only relays it, so there is nothing here that can be a JWT/JOSE correctness bug.
type jwksCache struct {
	mu          sync.RWMutex
	body        []byte
	contentType string
	fetched     time.Time
}

func (s *Server) fetchDiscovery(ctx context.Context) (map[string]any, error) {
	s.discovery.mu.RLock()
	doc, fetched := s.discovery.doc, s.discovery.fetched
	s.discovery.mu.RUnlock()
	if doc != nil && time.Since(fetched) < s.cfg.DiscoveryCacheTTL {
		return doc, nil
	}
	fresh, err := s.fetchDiscoveryUncached(ctx)
	if err != nil {
		if doc != nil {
			s.log.WithError(err).Warn("discovery refresh failed, serving cached copy")
			return doc, nil
		}
		return nil, err
	}
	s.discovery.mu.Lock()
	s.discovery.doc, s.discovery.fetched = fresh, time.Now()
	s.discovery.mu.Unlock()
	return fresh, nil
}

func (s *Server) fetchDiscoveryUncached(ctx context.Context) (map[string]any, error) {
	target := strings.TrimRight(s.cfg.MUIssuer.String(), "/") + "/.well-known/openid-configuration"
	ctx, cancel := context.WithTimeout(ctx, upstreamTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return nil, err
	}
	resp, err := s.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("MU Auth discovery returned status %d", resp.StatusCode)
	}
	var doc map[string]any
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxRespBytes)).Decode(&doc); err != nil {
		return nil, fmt.Errorf("bad discovery document: %w", err)
	}
	issuer := docString(doc, "issuer")
	if strings.TrimRight(issuer, "/") != strings.TrimRight(s.cfg.MUIssuer.String(), "/") {
		return nil, fmt.Errorf("discovery issuer %q does not match MU_AUTH_ISSUER %q", issuer, s.cfg.MUIssuer.String())
	}
	return doc, nil
}

func docString(doc map[string]any, key string) string {
	v, _ := doc[key].(string)
	return v
}

// handleDiscovery serves this service's own discovery document to Zendrite. The upstream
// document is passed through largely unchanged, except that issuer, authorization_endpoint,
// token_endpoint, introspection_endpoint and jwks_uri are rewritten to point at the sidecar, so
// Zendrite never needs to talk to MU Auth directly at all.
func (s *Server) handleDiscovery(w http.ResponseWriter, r *http.Request) {
	doc, err := s.fetchDiscovery(r.Context())
	if err != nil {
		s.log.WithError(err).Error("discovery fetch failed")
		writeOAuthError(w, http.StatusBadGateway, "server_error", "identity provider unavailable")
		return
	}
	out := make(map[string]any, len(doc)+4)
	for k, v := range doc {
		out[k] = v
	}
	base := strings.TrimRight(s.cfg.PublicURL.String(), "/")
	out["issuer"] = base
	out["authorization_endpoint"] = base + "/oauth2/authorize"
	out["token_endpoint"] = base + "/oauth2/token"
	out["introspection_endpoint"] = base + "/oauth2/introspect"
	out["jwks_uri"] = base + "/oauth2/jwks"

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", fmt.Sprintf("public, max-age=%d", int(s.cfg.DiscoveryCacheTTL.Seconds())))
	json.NewEncoder(w).Encode(out)
}

// handleJWKS relays MU Auth's signing keys byte-for-byte, with permissive CORS so browser clients
// can fetch them without depending on MU Auth's own CORS policy.
func (s *Server) handleJWKS(w http.ResponseWriter, r *http.Request) {
	body, ct, err := s.fetchJWKS(r.Context())
	if err != nil {
		s.log.WithError(err).Error("jwks fetch failed")
		writeOAuthError(w, http.StatusBadGateway, "server_error", "identity provider unavailable")
		return
	}
	if ct == "" {
		ct = "application/json"
	}
	w.Header().Set("Content-Type", ct)
	w.Header().Set("Access-Control-Allow-Origin", "*") // keys are public; no credential is ever sent here
	w.Header().Set("Cache-Control", fmt.Sprintf("public, max-age=%d", int(jwksCacheTTL.Seconds())))
	w.Write(body)
}

func (s *Server) fetchJWKS(ctx context.Context) ([]byte, string, error) {
	s.jwks.mu.RLock()
	body, ct, fetched := s.jwks.body, s.jwks.contentType, s.jwks.fetched
	s.jwks.mu.RUnlock()
	if body != nil && time.Since(fetched) < jwksCacheTTL {
		return body, ct, nil
	}

	doc, err := s.fetchDiscovery(ctx)
	if err != nil {
		if body != nil {
			s.log.WithError(err).Warn("jwks refresh failed (discovery unreachable), serving stale copy")
			return body, ct, nil
		}
		return nil, "", err
	}
	jwksURI := docString(doc, "jwks_uri")
	if jwksURI == "" {
		return nil, "", errors.New("MU Auth publishes no jwks_uri")
	}

	freshBody, freshCT, err := s.fetchJWKSUncached(ctx, jwksURI)
	if err != nil {
		if body != nil {
			s.log.WithError(err).Warn("jwks refresh failed, serving stale copy")
			return body, ct, nil
		}
		return nil, "", err
	}
	s.jwks.mu.Lock()
	s.jwks.body, s.jwks.contentType, s.jwks.fetched = freshBody, freshCT, time.Now()
	s.jwks.mu.Unlock()
	return freshBody, freshCT, nil
}

func (s *Server) fetchJWKSUncached(ctx context.Context, target string) ([]byte, string, error) {
	ctx, cancel := context.WithTimeout(ctx, upstreamTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return nil, "", err
	}
	resp, err := s.http.Do(req)
	if err != nil {
		return nil, "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, "", fmt.Errorf("MU Auth jwks_uri returned status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxRespBytes))
	if err != nil {
		return nil, "", err
	}
	return body, resp.Header.Get("Content-Type"), nil
}
