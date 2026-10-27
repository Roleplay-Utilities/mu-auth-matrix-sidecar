package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
)

var localpartRe = regexp.MustCompile(`^[a-z0-9._=/+-]{1,255}$`)

// zendriteAdmin calls one of Zendrite's /_synapse/mas/<action> endpoints with the sidecar's
// configured admin token. For GET actions, body's values are sent as query parameters; for POST
// actions, body is marshalled as the JSON request body.
func (s *Server) zendriteAdmin(ctx context.Context, method, action string, body map[string]any) (*upstreamResponse, error) {
	target := strings.TrimRight(s.cfg.ZendriteURL.String(), "/") + "/_synapse/mas/" + action
	var reqBody io.Reader
	if method == http.MethodGet {
		q := url.Values{}
		for k, v := range body {
			if str, ok := v.(string); ok {
				q.Set(k, str)
			}
		}
		target += "?" + q.Encode()
	} else {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		reqBody = bytes.NewReader(b)
	}

	ctx, cancel := context.WithTimeout(ctx, upstreamTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, method, target, reqBody)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+s.cfg.ZendriteAdminToken)
	if method != http.MethodGet {
		req.Header.Set("Content-Type", "application/json")
	}
	return s.do(req)
}

// zendriteAdminOK is a convenience for callers that only care whether a POST action succeeded.
func (s *Server) zendriteAdminOK(ctx context.Context, action string, body map[string]any) error {
	up, err := s.zendriteAdmin(ctx, http.MethodPost, action, body)
	if err != nil {
		return err
	}
	if up.status >= 300 {
		return fmt.Errorf("zendrite %s returned status %d: %s", action, up.status, strings.TrimSpace(string(up.body)))
	}
	return nil
}
