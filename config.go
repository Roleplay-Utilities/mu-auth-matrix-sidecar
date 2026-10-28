package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"
	"time"
)

const DefaultMUIssuer = "https://accounts.mega-utilities.com"

// Config holds every setting the sidecar needs, read once at startup from the environment.
type Config struct {
	Port string // bare port number, e.g. "8080"

	PublicURL           *url.URL // SIDECAR_PUBLIC_URL: this service's own public base URL
	MUIssuer            *url.URL // MU_AUTH_ISSUER
	ZendriteURL         *url.URL // ZENDRITE_URL: Zendrite's listener as reachable from this process
	MatrixHomeserverURL *url.URL // MATRIX_HOMESERVER_URL: the homeserver's public name, display only

	ZendriteAdminToken string // shared secret, equal to Zendrite's msc3861.admin_token

	CookieSecret []byte // 32 bytes; used to encrypt/sign every cookie. Must be identical
	// across replicas if you run more than one instance behind a load balancer.

	// The dashboard (/account) is a confidential OAuth client of its own, separate from any
	// Matrix client's. Optional: if unset, /account and /api/devices are not registered.
	DashboardClientID     string
	DashboardClientSecret string

	ProvisionCacheTTL time.Duration // how long a (localpart, device) pair is remembered as "already provisioned"
	DiscoveryCacheTTL time.Duration // how long the upstream discovery document is cached

	// AdminUsernames is a set of lowercased Matrix localparts that are automatically granted
	// Zendrite's urn:synapse:admin:* scope on every introspection, regardless of whatever MU Auth
	// itself returns. This is operator-controlled configuration, not anything a client or the
	// token itself can influence.
	AdminUsernames map[string]bool

	// Debug
	Debug bool // default false
}

func env(k, d string) string {
	if v := strings.TrimSpace(os.Getenv(k)); v != "" {
		return v
	}
	return d
}

func requireEnv(k string) (string, error) {
	v := strings.TrimSpace(os.Getenv(k))
	if v == "" {
		return "", fmt.Errorf("missing required environment variable %s", k)
	}
	return v, nil
}

func isLoopbackHost(h string) bool { return h == "localhost" || h == "127.0.0.1" || h == "::1" }

// parsePublicURL parses an absolute URL that must be https (or http on loopback, for local dev).
func parsePublicURL(name, raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return nil, fmt.Errorf("%s=%q is not a valid absolute URL", name, raw)
	}
	switch {
	case u.Scheme == "https":
	case u.Scheme == "http" && isLoopbackHost(u.Hostname()):
	default:
		return nil, fmt.Errorf("%s=%q must use https (http only allowed on localhost/127.0.0.1)", name, raw)
	}
	return u, nil
}

// parseInternalURL parses a URL used only for server-to-server calls (Zendrite's listener),
// which is commonly plain http on a private network, so https is not required.
func parseInternalURL(name, raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
		return nil, fmt.Errorf("%s=%q is not a valid http(s) URL", name, raw)
	}
	return u, nil
}

// decodeSecret accepts COOKIE_SECRET as base64 (standard or URL-safe, padded or not) or hex, and
// requires at least 32 bytes of entropy either way. Anything else is hashed down to 32 bytes with
// SHA-256 as a last resort, so a human-chosen passphrase still works, just less ideally.
func decodeSecret(raw string) ([]byte, error) {
	if raw == "" {
		return nil, errors.New("empty secret")
	}
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		if b, err := enc.DecodeString(raw); err == nil && len(b) >= 32 {
			return b[:32], nil
		}
	}
	if b, err := hex.DecodeString(raw); err == nil && len(b) >= 32 {
		return b[:32], nil
	}
	sum := sha256.Sum256([]byte(raw))
	return sum[:], nil
}

func parseDuration(name, raw string, def time.Duration) (time.Duration, error) {
	if raw == "" {
		return def, nil
	}
	d, err := time.ParseDuration(raw)
	if err != nil {
		return 0, fmt.Errorf("%s=%q is not a valid Go duration (e.g. \"60s\")", name, raw)
	}
	return d, nil
}

// LoadConfig reads and validates every setting from the environment.
func LoadConfig() (*Config, error) {
	c := &Config{Port: env("PORT", "8080")}

	publicURL, err := requireEnv("SIDECAR_PUBLIC_URL")
	if err != nil {
		return nil, err
	}
	if c.PublicURL, err = parsePublicURL("SIDECAR_PUBLIC_URL", publicURL); err != nil {
		return nil, err
	}

	issuerRaw := env("MU_AUTH_ISSUER", DefaultMUIssuer)
	if c.MUIssuer, err = parsePublicURL("MU_AUTH_ISSUER", issuerRaw); err != nil {
		return nil, err
	}

	zendriteURL, err := requireEnv("ZENDRITE_URL")
	if err != nil {
		return nil, err
	}
	if c.ZendriteURL, err = parseInternalURL("ZENDRITE_URL", zendriteURL); err != nil {
		return nil, err
	}

	// MATRIX_HOMESERVER_URL is used for display only, so it's validated the same lenient way as
	// ZENDRITE_URL (no https requirement) rather than as a public-facing URL: it commonly defaults
	// straight to ZENDRITE_URL, which is very often a plain-http internal address (e.g.
	// "http://zendrite:8008" in Docker) that would otherwise fail validation even though the
	// operator never set this variable at all.
	hsURL := env("MATRIX_HOMESERVER_URL", zendriteURL)
	if c.MatrixHomeserverURL, err = parseInternalURL("MATRIX_HOMESERVER_URL", hsURL); err != nil {
		return nil, err
	}

	// ZENDRITE_ADMIN_TOKEN is the corrected spelling; ZENDRIITE_ADMIN_TOKEN (as given in the
	// original spec) is still accepted for compatibility if that's what you already deployed.
	if v := strings.TrimSpace(os.Getenv("ZENDRITE_ADMIN_TOKEN")); v != "" {
		c.ZendriteAdminToken = v
	} else if v := strings.TrimSpace(os.Getenv("ZENDRIITE_ADMIN_TOKEN")); v != "" {
		c.ZendriteAdminToken = v
	} else {
		return nil, errors.New("missing required environment variable ZENDRITE_ADMIN_TOKEN")
	}

	cookieSecret, err := requireEnv("COOKIE_SECRET")
	if err != nil {
		return nil, fmt.Errorf("%w (generate one with: openssl rand -base64 32)", err)
	}
	if c.CookieSecret, err = decodeSecret(cookieSecret); err != nil {
		return nil, fmt.Errorf("COOKIE_SECRET: %w", err)
	}

	c.DashboardClientID = env("DASHBOARD_CLIENT_ID", "")
	c.DashboardClientSecret = env("DASHBOARD_CLIENT_SECRET", "")
	if (c.DashboardClientID == "") != (c.DashboardClientSecret == "") {
		return nil, errors.New("DASHBOARD_CLIENT_ID and DASHBOARD_CLIENT_SECRET must be set together")
	}

	if c.ProvisionCacheTTL, err = parseDuration("PROVISION_CACHE_TTL", env("PROVISION_CACHE_TTL", ""), 60*time.Minute); err != nil {
		return nil, err
	}
	if c.DiscoveryCacheTTL, err = parseDuration("DISCOVERY_CACHE_TTL", env("DISCOVERY_CACHE_TTL", ""), 60*time.Minute); err != nil {
		return nil, err
	}

	c.AdminUsernames = map[string]bool{}
	for _, u := range strings.Split(env("ADMIN_USERNAMES", ""), ",") {
		if u = strings.ToLower(strings.TrimSpace(u)); u != "" {
			c.AdminUsernames[u] = true
		}
	}

	c.Debug = strings.EqualFold(env("DEBUG", "false"), "true") || env("DEBUG", "") == "1"

	return c, nil
}

// DashboardEnabled reports whether /account has the credentials it needs to run.
func (c *Config) DashboardEnabled() bool {
	return strings.ToLower(env("DISABLE_DASHBOARD", "false")) != "true"
}
