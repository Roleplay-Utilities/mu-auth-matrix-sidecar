package main

import (
	"crypto/rand"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func newBearerRequest(token string) *http.Request {
	req := httptest.NewRequest(http.MethodPost, "/_synapse/mas/provision_user", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	return req
}

func randomKey(t *testing.T) []byte {
	t.Helper()
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return b
}

func TestSealerRoundTrip(t *testing.T) {
	sl, err := newSealer(randomKey(t))
	if err != nil {
		t.Fatal(err)
	}
	type payload struct {
		A string
		B int
	}
	in := payload{A: "hello", B: 42}
	sealed, err := sl.seal(in)
	if err != nil {
		t.Fatal(err)
	}
	var out payload
	if err := sl.open(sealed, &out); err != nil {
		t.Fatalf("open failed: %v", err)
	}
	if out != in {
		t.Fatalf("got %+v, want %+v", out, in)
	}
}

func TestSealerRejectsTampering(t *testing.T) {
	sl, err := newSealer(randomKey(t))
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := sl.seal(map[string]string{"a": "b"})
	if err != nil {
		t.Fatal(err)
	}
	tampered := []byte(sealed)
	// Flip a byte well inside the ciphertext (past the nonce) to corrupt the authenticated payload.
	idx := len(tampered) - 5
	if tampered[idx] == 'A' {
		tampered[idx] = 'B'
	} else {
		tampered[idx] = 'A'
	}
	var out map[string]string
	if err := sl.open(string(tampered), &out); err == nil {
		t.Fatal("expected tampered cookie to fail authentication")
	}
}

func TestSealerRejectsWrongKey(t *testing.T) {
	a, err := newSealer(randomKey(t))
	if err != nil {
		t.Fatal(err)
	}
	b, err := newSealer(randomKey(t))
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := a.seal(map[string]string{"a": "b"})
	if err != nil {
		t.Fatal(err)
	}
	var out map[string]string
	if err := b.open(sealed, &out); err == nil {
		t.Fatal("expected a cookie sealed with one key to fail authentication under another")
	}
}

func TestInjectDeviceScopeAddsWhenAbsent(t *testing.T) {
	got := injectDeviceScope("urn:matrix:client:api:* openid", "ABCDEFGHIJ")
	want := "urn:matrix:client:api:* openid " + preferredDeviceScopePrefix + "ABCDEFGHIJ"
	if got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestInjectDeviceScopeLeavesExistingAlone(t *testing.T) {
	cases := []string{
		"urn:matrix:client:api:* urn:matrix:client:device:NATIVEOWNID",
		"urn:matrix:client:api:* urn:matrix:org.matrix.msc2967.client:device:NATIVEOWNID",
	}
	for _, scope := range cases {
		if got := injectDeviceScope(scope, "SHOULDNOTAPPEAR"); got != scope {
			t.Fatalf("scope %q was modified: got %q", scope, got)
		}
	}
}

func TestInjectDeviceScopeHandlesEmptyScope(t *testing.T) {
	got := injectDeviceScope("", "ABCDEFGHIJ")
	want := preferredDeviceScopePrefix + "ABCDEFGHIJ"
	if got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestExtractDeviceScope(t *testing.T) {
	cases := []struct {
		name, scope, want string
	}{
		{"current prefix", "urn:matrix:client:api:* urn:matrix:client:device:ABCDEFGHIJ", "ABCDEFGHIJ"},
		{"legacy msc prefix", "urn:matrix:client:api:* urn:matrix:org.matrix.msc2967.client:device:ABCDEFGHIJ", "ABCDEFGHIJ"},
		{"no device scope", "urn:matrix:client:api:* openid", ""},
		{"invalid device id rejected", "urn:matrix:client:device:bad!id", ""},
		{"empty scope", "", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := extractDeviceScope(c.scope); got != c.want {
				t.Fatalf("got %q, want %q", got, c.want)
			}
		})
	}
}

func TestLocalpartOf(t *testing.T) {
	cases := map[string]string{
		"@alice:example.com": "alice",
		"@bob.smith:matrix.mega-utilities.com": "bob.smith",
		"alice:example.com":  "alice",
		"@alice":              "alice",
		"alice":                "alice",
	}
	for in, want := range cases {
		if got := localpartOf(in); got != want {
			t.Fatalf("localpartOf(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestLocalpartAndDeviceIDPatterns(t *testing.T) {
	validLocalparts := []string{"alice", "bob.smith", "a1-2_3=4/5+6"}
	for _, lp := range validLocalparts {
		if !localpartRe.MatchString(lp) {
			t.Errorf("expected localpart %q to be valid", lp)
		}
	}
	invalidLocalparts := []string{"Alice", "ALICE", "alice!", "", strings.Repeat("a", 256)}
	for _, lp := range invalidLocalparts {
		if localpartRe.MatchString(lp) {
			t.Errorf("expected localpart %q to be invalid", lp)
		}
	}

	validDevices := []string{"ABCDEFGHIJ", "a_b-c.d~e"}
	for _, d := range validDevices {
		if !deviceIDRe.MatchString(d) {
			t.Errorf("expected device id %q to be valid", d)
		}
	}
	invalidDevices := []string{"bad id", "bad!id", "", strings.Repeat("a", 65)}
	for _, d := range invalidDevices {
		if deviceIDRe.MatchString(d) {
			t.Errorf("expected device id %q to be invalid", d)
		}
	}
}

func TestValidateManageBody(t *testing.T) {
	cases := []struct {
		name string
		body map[string]any
		ok   bool
	}{
		{"empty body", map[string]any{}, true},
		{"valid localpart and device", map[string]any{"localpart": "alice", "device_id": "ABCDEFGHIJ"}, true},
		{"invalid localpart", map[string]any{"localpart": "Alice"}, false},
		{"invalid device", map[string]any{"device_id": "bad id"}, false},
		{"localpart wrong type", map[string]any{"localpart": 123}, false},
		{"unrelated fields pass through", map[string]any{"display_name": "My Phone"}, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			msg := validateManageBody(c.body)
			if (msg == "") != c.ok {
				t.Fatalf("validateManageBody(%+v) = %q, want ok=%v", c.body, msg, c.ok)
			}
		})
	}
}

func TestDecodeSecretAcceptsBase64AndHexAndFallsBackToHash(t *testing.T) {
	b64 := "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=" // 32 zero bytes, base64 std
	if got, err := decodeSecret(b64); err != nil || len(got) != 32 {
		t.Fatalf("base64 secret: got %v, err %v", got, err)
	}
	hex64 := strings.Repeat("ab", 32) // 32 bytes of hex
	if got, err := decodeSecret(hex64); err != nil || len(got) != 32 {
		t.Fatalf("hex secret: got %v, err %v", got, err)
	}
	// A short human passphrase doesn't decode as base64/hex into 32+ bytes, so it's hashed instead
	// of rejected outright.
	if got, err := decodeSecret("a short passphrase"); err != nil || len(got) != 32 {
		t.Fatalf("passphrase fallback: got %v, err %v", got, err)
	}
	if _, err := decodeSecret(""); err == nil {
		t.Fatal("expected an empty secret to be rejected")
	}
}

func TestInjectAdminScope(t *testing.T) {
	cases := []struct {
		name    string
		scope   string
		isAdmin bool
		want    string
	}{
		{"not admin, scope unchanged", "urn:matrix:client:api:*", false, "urn:matrix:client:api:*"},
		{"admin, scope appended", "urn:matrix:client:api:*", true, "urn:matrix:client:api:* " + adminScope},
		{"admin, empty scope", "", true, adminScope},
		{"admin, already present", "urn:matrix:client:api:* " + adminScope, true, "urn:matrix:client:api:* " + adminScope},
		{"not admin, empty scope stays empty", "", false, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := injectAdminScope(c.scope, c.isAdmin); got != c.want {
				t.Fatalf("got %q, want %q", got, c.want)
			}
		})
	}
}

func TestAccountManagementActionsAreCanonical(t *testing.T) {
	// Guards against the non-standard names (devices_list/device_view/device_delete) creeping
	// back in: these are the exact identifiers matrix-rust-sdk / MAS expect.
	want := []string{
		"org.matrix.profile",
		"org.matrix.sessions_list",
		"org.matrix.session_view",
		"org.matrix.session_end",
		"org.matrix.account_deactivate",
		"org.matrix.cross_signing_reset",
	}
	if len(accountManagementActions) != len(want) {
		t.Fatalf("got %d actions, want %d: %v", len(accountManagementActions), len(want), accountManagementActions)
	}
	for i, w := range want {
		if accountManagementActions[i] != w {
			t.Fatalf("action %d: got %q, want %q", i, accountManagementActions[i], w)
		}
	}
}

func TestCheckAdminBearerConstantTimeCompareIsCorrect(t *testing.T) {
	s := &Server{cfg: &Config{ZendriteAdminToken: "correct-token"}}
	req := newBearerRequest("correct-token")
	if !s.checkAdminBearer(req) {
		t.Fatal("expected the correct token to be accepted")
	}
	for _, bad := range []string{"wrong-token", "", "correct-token-but-longer", "correct-toke"} {
		if s.checkAdminBearer(newBearerRequest(bad)) {
			t.Fatalf("expected token %q to be rejected", bad)
		}
	}
	noAuth := newBearerRequest("")
	noAuth.Header.Del("Authorization")
	if s.checkAdminBearer(noAuth) {
		t.Fatal("expected a missing Authorization header to be rejected")
	}
}
