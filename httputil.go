package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	maxReqBytes     = 64 << 10 // 64 KiB: generous for form-encoded OAuth requests and JSON bodies
	maxRespBytes    = 1 << 20  // 1 MiB: generous for JSON responses and JWKS documents
	upstreamTimeout = 10 * time.Second
)

// upstreamResponse is a fully-read copy of an upstream HTTP response, so it can be inspected and
// then relayed to our own caller without a second round trip.
type upstreamResponse struct {
	status int
	header http.Header
	body   []byte
}

// forwardForm POSTs body to target, copying the caller's client-authentication headers
// (Authorization, Content-Type, Accept, DPoP) unchanged, so MU Auth sees the original client's
// credentials exactly as sent — the sidecar never substitutes its own identity here.
func (s *Server) forwardForm(ctx context.Context, r *http.Request, target string, body []byte) (*upstreamResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, upstreamTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, target, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	for _, h := range []string{"Content-Type", "Authorization", "Accept", "DPoP"} {
		if v := r.Header.Get(h); v != "" {
			req.Header.Set(h, v)
		}
	}
	if req.Header.Get("Content-Type") == "" {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	return s.do(req)
}

// postForm is like forwardForm, but for requests the sidecar itself originates as an OAuth
// client (the dashboard's own login, token refresh, and logout), rather than ones it is relaying
// on behalf of a caller. form is always application/x-www-form-urlencoded.
func (s *Server) postForm(ctx context.Context, target string, form url.Values) (*upstreamResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, upstreamTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, target, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return s.do(req)
}

func (s *Server) do(req *http.Request) (*upstreamResponse, error) {
	resp, err := s.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, maxRespBytes))
	if err != nil {
		return nil, err
	}
	return &upstreamResponse{status: resp.StatusCode, header: resp.Header.Clone(), body: b}, nil
}

func writeUpstream(w http.ResponseWriter, up *upstreamResponse) {
	w.Header().Set("Cache-Control", "no-store")
	for _, h := range []string{"Content-Type", "WWW-Authenticate", "DPoP-Nonce"} {
		if v := up.header.Get(h); v != "" {
			w.Header().Set(h, v)
		}
	}
	w.WriteHeader(up.status)
	w.Write(up.body)
}

func writeOAuthError(w http.ResponseWriter, status int, code, desc string) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]string{"error": code, "error_description": desc})
}

func writeMatrixError(w http.ResponseWriter, status int, errcode, errMsg string) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]string{"errcode": errcode, "error": errMsg})
}
