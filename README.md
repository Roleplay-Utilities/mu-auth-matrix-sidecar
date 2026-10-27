# mu-auth-matrix-sidecar

A stateless Go sidecar that lets any standard Matrix homeserver (Zendrite, or anything else
implementing MSC3861/MSC4191) use **MU Auth** — or any standalone public OIDC provider that issues
tokens with Matrix scopes — as its delegated-auth provider, without running the full Matrix
Authentication Service (MAS) stack.

Zendrite is told and the sidecar itself is the OIDC provider (`issuer` points at the sidecar). The
sidecar transparently relays everything to the real provider, and does the two things a standalone
OIDC server structurally can't do on its own: reach the homeserver's private admin listener, and
bind a browser to a stable device across repeated logins.

```
Matrix client / Zendrite ──discovery, authorize, token, introspect──► sidecar ──► MU Auth
                                                                          │
                                                                          │ on a successful login:
                                                                          │  provision_user + upsert_device
                                                                          ▼
                                                                       Zendrite (/_synapse/mas/*)
```

Nothing is stored on disk or in a database. All per-login state (PKCE verifiers, the dashboard's
own session tokens, the stable per-browser device id) lives in encrypted, authenticated cookies in
the browser. The only server-side state is a few in-process caches (the discovery document, JWKS,
and a short-lived "already provisioned" dedup cache) — purely performance optimizations that are
safe to lose on restart and aren't shared if you run more than one replica.

## What each file does

| File | Responsibility |
|---|---|
| `config.go` | Reads and validates every environment variable. |
| `discovery.go` | Serves the sidecar's own `/.well-known/openid-configuration` (MU Auth's document, with `issuer`, `authorization_endpoint`, `token_endpoint`, `introspection_endpoint`, and `jwks_uri` rewritten to the sidecar) and a byte-for-byte JWKS proxy. Both cached, with stale-serving on upstream failure. |
| `device_cookie.go` | The cookie-sealing primitive (AES-GCM) used by every cookie in the service; the stable per-browser device id; `/oauth2/authorize` (a transparent redirect that only adds a device scope if the caller didn't supply one) and `/oauth2/token` (a pure reverse proxy). |
| `introspection.go` | `/oauth2/introspect`: forwards to MU Auth, and — only if the token comes back active — provisions the user and device on Zendrite before relaying the (otherwise untouched) response. Fails closed: if provisioning fails, Zendrite is told the token is inactive rather than risking a session for a user/device that doesn't exist yet. |
| `zendrite.go` | The client for Zendrite's `/_synapse/mas/*` admin API. |
| `account.go` | The optional `/account` dashboard: its own confidential-client OIDC login (separate from any Matrix client's), session cookie, device list/delete, and the 12-route MAS admin passthrough. |
| `httputil.go` | Shared plumbing: forwarding a request upstream, writing OAuth/Matrix-shaped error bodies. |
| `main.go` | The `Server` struct, route table, middleware, startup/shutdown. |

## No JWT/JOSE library, anywhere

The sidecar never locally verifies a signature. Everything that matters — whether a token is
still valid, who it belongs to, what device it's for — is established by calling MU Auth's own
`introspection_endpoint`, the same source of truth Zendrite itself would use. The JWKS proxy exists
only so browser clients can fetch MU Auth's public keys without a CORS dependency; the sidecar
relays those bytes without ever parsing them.

## Build, test, run

```sh
go mod tidy
go vet ./...
go build -o sidecar.exe
go test ./...
# or: docker build -t mu-auth-matrix-sidecar .
```

`go mod tidy` will fetch `github.com/sirupsen/logrus` and pin its transitive dependencies; this
environment has no network access, so none of this has actually been compiled — do this before
trusting it.

`main_test.go` covers the pure logic with no network or mocks required: cookie sealing (round trip,
tamper rejection, wrong-key rejection), device-scope injection and extraction (both the current and
legacy MSC-numbered prefixes, and that an explicit client-supplied device scope is never
overridden), localpart/device-id validation, the MAS-body validator, `COOKIE_SECRET` decoding, and
the admin-bearer constant-time comparison.

## Configuration

| Variable | Required | Description |
|---|---|---|
| `PORT` | no | Default `8080`. |
| `SIDECAR_PUBLIC_URL` | yes | This service's own public base URL, e.g. `https://sidecar.mega-utilities.com`. Must be https (loopback excepted). |
| `MU_AUTH_ISSUER` | no | Default `https://accounts.mega-utilities.com`. The real OIDC provider. |
| `ZENDRITE_URL` | yes | Zendrite's listener as reachable from this process, e.g. `http://localhost:8008`. Plain http is fine (internal). |
| `MATRIX_HOMESERVER_URL` | no | Display-only; defaults to `ZENDRITE_URL`. |
| `ZENDRITE_ADMIN_TOKEN` | yes | Shared secret, equal to Zendrite's `msc3861.admin_token`. (`ZENDRIITE_ADMIN_TOKEN`, the original spelling, is still accepted.) |
| `COOKIE_SECRET` | yes | 32+ bytes of entropy (base64 or hex), used to encrypt/authenticate every cookie. **Must be identical across replicas** if you run more than one instance — this is what makes the service both stateless and horizontally scalable. Generate with `openssl rand -base64 32`. |
| `DASHBOARD_CLIENT_ID` / `DASHBOARD_CLIENT_SECRET` | no, together | The same confidential OIDC client you already configured in Zendrite for the `/account` dashboard. If unset, `/account` and `/api/devices` are not registered at all. |
| `PROVISION_CACHE_TTL` | no | Default `60s`. How long a (localpart, device) pair is remembered as already-provisioned. |
| `DISCOVERY_CACHE_TTL` | no | Default `10m`. |
| `ADMIN_USERNAMES` | no

## Additional Configuration
create `sidecar_settings.json`
```json
{
  "prereleases": false,
  "auto_restart": true
}
```
prereleases allows downloads of prereleases and auto_restart controls automatic restarts to install new updates

## Registering clients at MU Auth

Two separate confidential clients:

1. **Zendrite's own client** (whatever `client_id`/`client_secret` Zendrite is configured with) — used transparently; the sidecar never substitutes its own credentials when relaying `/oauth2/token` or `/oauth2/introspect`, it only copies through whatever the caller sent.
2. **The dashboard's client** (`DASHBOARD_CLIENT_ID`/`SECRET`), redirect URI `https://sidecar.example.com/account/callback`, if you want `/account`.

## Zendrite config

```yaml
mscs:
  mscs: [msc3861]
  msc3861:
    issuer: "https://sidecar.example.com"      # the SIDECAR, not MU Auth — byte-exact vs its own discovery document
    client_id: "<your client id at MU Auth>"
    client_secret: "<your client secret at MU Auth>"
    admin_token: "<same value as the sidecar's ZENDRITE_ADMIN_TOKEN>"
    public_base_url: "https://matrix.example.com"
```

Zendrite never talks to MU Auth directly in this design — only to the sidecar, whose discovery
document points every endpoint back at itself.

## Corrections made to the original spec (flagged, not silent)

- **Device deletion.** Zendrite returns `403 M_FORBIDDEN` on its own client-server device-deletion
  endpoint under delegated auth — device management is meant to happen at the provider — so
  `DELETE /api/devices/{id}` goes through the privileged MAS admin API instead. But that admin API
  has no ownership check of its own (it will act on whatever `localpart`/`device_id` it's given),
  so the handler first confirms, using the *user's own* access token against
  `GET /_matrix/client/v3/devices/{id}`, that the device actually belongs to them, before calling
  `delete_device`. Listing devices uses the same approach — the user's own token against the normal
  client-server API — never the admin token.
- **Device-scope injection.** `/oauth2/authorize` only adds a device scope when the caller didn't
  supply one of their own. A native client's explicit device scope is never overridden: doing so
  could hand two different users of the same browser the same device id, or break a client that
  persists its own device id outside of cookies.
- **`ZENDRIITE_ADMIN_TOKEN`.** Read as a typo (`ZENDRITE_URL` is spelled correctly elsewhere in the
  spec). `ZENDRITE_ADMIN_TOKEN` is primary; the original spelling still works.

## Known limitation

Cross-signing reset confirmation (`allow_cross_signing_reset`) is exposed on the admin passthrough,
but nothing in this service calls it automatically — that has to come from wherever the user
confirms the reset (MU Auth's own account UI, most likely). Everything else in the 12-action MAS
API is wired end to end.
