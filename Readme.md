# Argio Platform SSO Server

Production-grade Platform SSO companion service for macOS. It exposes the well-known metadata required by Apple’s Platform SSO login window and brokers the handshake between enrolled devices and Authentik.

---

## Architecture

1. **Device registration (`POST /key`)** – the macOS agent uploads its signing/encryption public keys plus metadata. Keys are persisted in the state store.
2. **Nonce negotiation (`POST /nonce`)** – the device requests a one-time nonce (120s TTL). Nonces are stored and marked as used during the token exchange to prevent replay.
3. **Token exchange (`POST /token`)** – the device submits a JOSE assertion (JWS, optionally nested in JWE). The server verifies the signature with the stored device key, checks nonce freshness, and—if password grant is enabled—trades the credentials against Authentik for ID/refresh tokens. The response is signed with the server key and encrypted for the device.
4. **Discovery endpoints** – `.well-known/apple-app-site-association`, `.well-known/jwks.json`, and `/healthz` provide discovery metadata for Apple and infrastructure probes.

---

## Endpoints

| Method | Path                                           | Description |
|--------|------------------------------------------------|-------------|
| GET    | `/.well-known/apple-app-site-association`      | AASA manifest; serves `{ "authsrv": { "apps": [ "TEAM_ID.APP_BUNDLE_ID" ] } }` with JSON content type and caching.
| GET    | `/.well-known/jwks.json`                       | Public JWKS (server signing key, optional encryption key). RS256/ES256 depending on configured key.
| GET    | `/healthz`                                     | JSON health probe (`{"status":"ok"}`).
| POST   | `/nonce`                                       | Issues a 32-byte base64url nonce with 120s TTL. Optional payload binds nonce to a device.
| POST   | `/key`                                         | Registers/updates device metadata and public keys.
| POST   | `/token`                                       | Validates device assertion, performs Authentik password grant (when enabled), returns signed+encrypted Platform SSO response.

---

### Handshake headers & MIME types

| Endpoint | Required request headers | Response content type |
|----------|--------------------------|-----------------------|
| `POST /nonce` | `Content-Type: application/json` when sending a payload.<br>`Accept: application/json` (default is also accepted). | `application/json` |
| `POST /key` | `Content-Type: application/json`.<br>`Accept: application/json`. | `application/json` |
| `POST /token` | `Content-Type: application/x-www-form-urlencoded`.<br>`Accept: application/platformsso-login-response+jwt` (preferred) or `application/platformsso-key-response+jwt`. Any other `Accept` value is rejected with `406 Not Acceptable`. | Matches the negotiated `Accept` header (`application/platformsso-login-response+jwt` by default, `application/platformsso-key-response+jwt` when explicitly requested). |

---

## Security & JOSE

- **Inbound** assertions are JWS signed with the device’s public key (ECDSA/RSA). Optional JWE wrapping is decrypted with the server encryption private key.
- **Outbound** responses are signed with the server signing key (configurable `SERVER_SIGNING_KEY_KID`) and encrypted using RSA-OAEP-256/A256GCM for the device’s RSA public encryption key.
- JWKS exposes public keys only; server-side private keys are loaded from disk (`SERVER_SIGNING_KEY_PRIV_PATH`, optional `SERVER_ENC_KEY_PRIV_PATH`).
- Nonces are one-time-use and expire after 120 seconds. Replay attempts are rejected with `401`.
- Error responses are structured JSON for easier debugging; enable `DEBUG=true` to increase log verbosity.

---

## Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `PSSO_ADDRESS` | `:9100` | Listen address for the HTTP server. |
| `TEAM_ID` | `QUR8QTGXNB` | Apple Team ID for AASA. |
| `APP_BUNDLE_ID` | `ch.argio.psso` | Bundle ID for the Platform SSO extension. |
| `JWKS_PATH` | `./dist/jwks.json` | Location of the public JWKS file. |
| `JWKS_KEY_BITS` | `2048` | Reserved for legacy key generation (public JWKS writing still requires configured server keys). |
| `SERVER_SIGNING_KEY_PRIV_PATH` | `./secrets/server_signing_key.pem` | PEM-encoded private key used to sign responses. Required. |
| `SERVER_SIGNING_KEY_KID` | `argio-ss1` | `kid` published in the JWKS and used in response headers. |
| `SERVER_ENC_KEY_PRIV_PATH` | _empty_ | Optional PEM private key to decrypt nested JWE assertions from devices. |
| `STATE_DIR` | `./dist/state` | Root directory for the lightweight file store. |
| `DEVICE_PATH` | `${STATE_DIR}/devices` | Override device store path if required. |
| `NONCE_PATH` | `${STATE_DIR}/nonces` | Override nonce store path if required. |
| `AUTHENTIK_BASE_URL` | `https://auth.argio.ch` | Base URL for documentation/logging. |
| `AUTHENTIK_TOKEN_ENDPOINT` | `https://auth.argio.ch/application/o/token/` | OAuth2 token endpoint used for password grant. |
| `AK_PASSWORD_GRANT_ENABLED` | `false` | Enable Authentik Resource Owner Password Credentials (ROPC). |
| `AK_CLIENT_ID` / `AK_CLIENT_SECRET` | _empty_ | OAuth2 client credentials; required when password grant is enabled. |
| `DEBUG` | `false` | Increase logging noise for troubleshooting. |

> ⚠️ Startup fails fast with a clear error if the server signing key or mandatory Authentik credentials are missing.

---

## Modes of operation

### Mode: `PASSWORD`
When `AK_PASSWORD_GRANT_ENABLED=true`, the `/token` handler extracts `username` and `password` from the device assertion, executes a password grant against Authentik, and returns the `id_token` and `refresh_token` to the device. This mode supports the current macOS login window experience.

### Mode: `KEY` (future)
The code base is structured to add Secure Enclave / key-assertion flows in the future. Implementations should plug into the same handler via `AuthenticationMethod` and device key material. _TODO: add verification logic and Authentik integration for key-based assertions._

---

## Running locally

```bash
# 1. Provide environment (see above) and ensure server keys exist under ./secrets/
cp examples/server_signing_key.pem ./secrets/ # (placeholder – generate your own!)

# 2. Build & run
chmod +x scripts/*.sh
go mod tidy
go build ./...
PSSO_ADDRESS=:9100 \ 
  SERVER_SIGNING_KEY_PRIV_PATH=./secrets/server_signing_key.pem \ 
  ./psso-server
```

### Smoke tests

```bash
# Endpoint checks (AASA, JWKS, health, nonce)
./scripts/test_endpoints.sh http://localhost:9100

# Handshake flow (register → nonce → token). Expects /token to return 200 or 400.
./scripts/test_handshake.sh http://localhost:9100
```

### Development checks

```bash
go fmt ./...
go vet ./...
go test ./...
```

---

## Reverse proxy examples

**HAProxy**
```haproxy
acl is_aasa path_beg /.well-known/apple-app-site-association
acl is_jwks path_beg /.well-known/jwks.json
acl is_handshake path_beg /nonce /key /token
use_backend bk_psso if is_aasa or is_jwks or is_handshake
backend bk_psso
  http-response set-header Content-Type application/json if is_aasa or is_jwks
  server psso psso:9100 check
```

**Cloudflare Tunnel (`config.yml`)**
```yaml
ingress:
  - hostname: auth.argio.ch
    path: /.well-known/*
    service: http://psso:9100
  - hostname: auth.argio.ch
    path: /nonce
    service: http://psso:9100
  - hostname: auth.argio.ch
    path: /key
    service: http://psso:9100
  - hostname: auth.argio.ch
    path: /token
    service: http://psso:9100
  - hostname: auth.argio.ch
    service: http://authentik:9000
```

> Ensure proxies do not rewrite or cache-bust `.well-known/*`. AASA and JWKS must be served with `Content-Type: application/json` and without redirects.

---

## Troubleshooting

- **404s on handshake endpoints** – verify the reverse proxy forwards `/nonce`, `/key`, and `/token` to the service without rewrites.
- **`server cannot decrypt assertion`** – configure `SERVER_ENC_KEY_PRIV_PATH` if devices encrypt assertions.
- **`password grant is disabled`** – set `AK_PASSWORD_GRANT_ENABLED=true` and provide `AK_CLIENT_ID`/`AK_CLIENT_SECRET`.
- **Missing JWKS** – ensure the service has write access to `JWKS_PATH`; the file is generated on startup from the configured server keys.
- **macOS fails to load login window** – confirm the AASA file contains `QUR8QTGXNB.ch.argio.psso` (or your override) and is served via HTTPS without redirects.

---

## Deployment notes

- TLS terminates at your proxy (Cloudflare/HAProxy). This service only speaks HTTP.
- No private keys are ever written to the JWKS. Keep `./secrets` out of version control.
- For containerised deployments, mount `STATE_DIR`, `JWKS_PATH`, and key files as persistent volumes.

---

## Changelog

See [CHANGELOG.md](CHANGELOG.md) for release notes.

---

## License

MIT – contributions welcome. Please include tests (`go test`, `./scripts/test_handshake.sh`) and update documentation when adding new flows.
