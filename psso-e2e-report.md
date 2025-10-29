# PSSO End-to-End Status Report

## 1. Routing Overview
| Endpoint | Expected | Registered in `NewRouter` | Notes |
| --- | --- | --- | --- |
| `/.well-known/jwks.json` | ✅ | ✅ | Public JWKS served with `Content-Type: application/json`; persisted via `jwks.LoadOrCreate`.
| `/.well-known/apple-app-site-association` | ✅ | ✅ | Response assembled from env-derived `authsrv.apps` array.
| `/healthz` | ✅ | ✅ | Simple liveness responder (`ok`).
| `/nonce` | ✅ | ✅ | Returns JSON nonce payload and stores file under `PSSO_NONCEPATH`.
| `/token` | ✅ | ✅ | POST-only; rejects other verbs with 405.
| `/register` | ✅ | ✅ | POST-only; persists device and key metadata.

> Source: `cmd/local/main.go#NewRouter` registers all six routes, handshake handlers are live again.

## 2. Configuration Matrix
| Key | Source | Default / Current Value |
| --- | --- | --- |
| `TEAM_ID` | env (`TEAM_ID`) | `QUR8QTGXNB`
| `APP_BUNDLE_ID` | env (`APP_BUNDLE_ID`) | `ch.argio.psso`
| `JWKS_PATH` | env (`JWKS_PATH`) | `./dist/jwks.json`
| `PSSO_ISSUER` | env (`PSSO_ISSUER`) | `https://auth.argio.ch`
| `PSSO_AUDIENCE` | env (`PSSO_AUDIENCE`) | `macos`
| `PSSO_NONCEPATH` | env (`PSSO_NONCEPATH`) | `/var/psso/nonce`
| `PSSO_DEVICEFILEPATH` | env (`PSSO_DEVICEFILEPATH`) | `/var/psso/devices`
| `PSSO_KEYPATH` | env (`PSSO_KEYPATH`) | `/var/psso/keys`
| Route overrides | env (`PSSO_ENDPOINT*`) | Default paths listed above

`authsrv.apps` is calculated as `${TEAM_ID}.${APP_BUNDLE_ID}` ensuring the Apple association string matches configuration.

## 3. AASA & JWKS Validation
- **AASA**: Response is JSON-only, with `authsrv.apps` including `${TEAM_ID}.${APP_BUNDLE_ID}` and empty `applinks`/`webcredentials`. Content type locked to `application/json`.
- **JWKS**: `jwks.LoadOrCreate` writes a public-only RSA key set to `JWKS_PATH` on first request. The `kid` remains stable across restarts as long as the file is retained. Only the public key material is exposed.
- **Nonce**: Handler now emits JSON with explicit `Content-Type` and reports errors if persistence fails. Stored TTL remains five minutes.
- **Reverse proxy**: Keep `/.well-known/*` unaltered—no redirects or rewrites, response must be served directly as JSON for AASA/JWKS.

## 4. Build & Test Status
- `go test ./...` – ✅ passes (includes router regression coverage for all endpoints).
- `go vet ./...` – ✅ clean.
- `go build ./...` – ✅ builds without warnings.

Scripts & tooling:
- `scripts/test_endpoints.sh` now exercises the public surface (`/.well-known/*`, `/nonce`) and prints ready-to-run POST samples for `/register` and `/token`.

## 5. Deployment Artifacts
- Dockerfile present (multi-stage Go build).
- `docker-compose.haproxy.yml` & override ready for proxy-integrated deployments.
- Reverse proxy snippets in README updated for HAProxy & Cloudflared, highlighting `Content-Type` enforcement.

## 6. Next Steps
1. Wire external storage (volume or bind mount) for `/var/psso/*` so nonce/register/token state survives container restarts.
2. Provide real payload templates/fixtures for `/register` & `/token` integration tests once device keys are available.
3. Validate reverse proxy configuration in staging—ensure no TLS termination issues and confirm `.well-known/*` content type remains `application/json`.
4. Optional hardening: add structured logging + metrics around handshake endpoints for observability.

### Handy Commands
```bash
# Local run
./scripts/dev_up.sh

# Compose stack (HAProxy + server)
docker compose -f docker-compose.haproxy.yml --env-file .env.psso up -d --build

# Endpoint smoke test
./scripts/test_endpoints.sh http://localhost:9100

# Unit tests & vet
go test ./...
go vet ./...
```
