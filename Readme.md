# Argio PSSO Server

Minimal, production‑ready service for Apple Platform SSO setups with Authentik as IdP — without password grant. Provides only the endpoints macOS/iOS actually need, and plays nicely behind Cloudflare/HAProxy. Reproducible and container‑first.

---

## Features

- AASA endpoint: `/.well-known/apple-app-site-association`
- JWKS (public keys only): `/.well-known/jwks.json`
- Platform SSO handshake: `/nonce`, `/register`, `/token`
- Health check: `/healthz`
- No ROPC or password‑grant flows; PKCE/OAuth handled by the Platform SSO extension ↔ Authentik
- Cloud proxy friendly (HTTP, no in‑process TLS; terminate at CF/HAProxy)
- Reproducible Docker build

---

## Overview

- Purpose: Serve AASA and JWKS for Apple’s Platform SSO so that macOS can discover the extension and validate tokens/keys. The extension itself talks to Authentik using PKCE; this server does not relay user credentials.
- Scope: Well‑knowns (AASA, JWKS), health, and the Platform SSO handshake endpoints used by macOS during device registration.

---

## Endpoints

- `/.well-known/apple-app-site-association` (AASA)
  - Content‑Type: `application/json`
  - Payload (minimal): `{ "authsrv": { "apps": [ "${TEAM_ID}.${APP_BUNDLE_ID}" ] } }`
  - Also includes empty `applinks` and `webcredentials`
- `/.well-known/jwks.json` (JWKS)
  - Returns a public‑only JSON Web Key Set (RSA, RS256)
  - If `JWKS_PATH` doesn’t exist, a new key is generated on first request; `kid = unix timestamp`
- `/nonce` (Nonce)
  - Returns JSON `{ "Nonce": "<base64>" }`
  - Persists the nonce to `PSSO_NONCEPATH` for 5 minutes; ensure this path is writable
- `/register` (Device registration)
  - Expects POST JSON with device UUID + signing/encryption keys
  - Stores metadata under `PSSO_DEVICEFILEPATH` and `PSSO_KEYPATH`
- `/token` (Token exchange)
  - Expects POST form-data (`platform_sso_version`, `assertion`/`request` JWT)
  - Validates device state and returns a PSSO login response JWE
- `/healthz` (Health)
  - Returns `ok` (200)

---

## Quick Start

1) Requirements
- go >= 1.22, docker, jq, curl

2) Configure `.env.psso`
```
PSSO_ADDRESS=:9100
TEAM_ID=QUR8QTGXNB
APP_BUNDLE_ID=ch.argio.psso
JWKS_PATH=./dist/jwks.json
JWKS_KEY_BITS=2048
```

3) Build / run locally
```bash
chmod +x scripts/*.sh
./scripts/dev_up.sh

# (optional) start via compose for shared nets
docker compose -f docker-compose.haproxy.yml --env-file .env.psso up -d --build
```

4) Verify endpoints
```bash
# automatic smoke-test (includes /nonce)
./scripts/test_endpoints.sh http://localhost:9100

# manual handshake calls (sample payloads)
curl -X POST http://localhost:9100/register \
  -H 'Content-Type: application/json' \
  --data '{"DeviceUUID":"<uuid>","DeviceSigningKey":"<pem>","DeviceEncryptionKey":"<pem>","SignKeyID":"<base64>","EncKeyID":"<base64>"}'

curl -X POST http://localhost:9100/token \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data 'platform_sso_version=1.0&assertion=<JWT>'
```

---

## Apple/AASA Notes

- AASA must be served at your auth host without redirects, for example:
  - `https://auth.argio.ch/.well-known/apple-app-site-association`
- Ensure `Content-Type: application/json`
- Test on macOS:
  - `sudo swcutil dl -d auth.argio.ch`
  - `sudo swcutil show | grep -A3 auth.argio.ch`

---

## Reverse Proxy Examples

HAProxy:
```
acl is_aasa path_beg /.well-known/apple-app-site-association
acl is_jwks path_beg /.well-known/jwks.json
acl is_handshake path_beg /nonce /register /token
use_backend bk_psso if is_aasa or is_jwks or is_handshake
backend bk_psso
  http-response set-header Content-Type application/json if is_aasa or is_jwks
  server psso psso:9100 check
```

cloudflared (config.yml excerpt):
```
ingress:
  - hostname: auth.argio.ch
    path: /.well-known/*
    service: http://psso:9100
  - hostname: auth.argio.ch
    path: /nonce
    service: http://psso:9100
  - hostname: auth.argio.ch
    path: /register
    service: http://psso:9100
  - hostname: auth.argio.ch
    path: /token
    service: http://psso:9100
  - hostname: auth.argio.ch
    service: http://authentik:9000
```

**Important:** Do not rewrite or redirect `/.well-known/*` paths. They must be served directly with `Content-Type: application/json`.

---

## Configuration

- `PSSO_ADDRESS`: server listen address (default `:9100`)
- `TEAM_ID`: Apple Team ID (e.g., `QUR8QTGXNB`)
- `APP_BUNDLE_ID`: App Bundle ID (e.g., `ch.argio.psso`)
- `JWKS_PATH`: path for JWKS file (default `./dist/jwks.json`)
- `JWKS_KEY_BITS`: RSA key length (default `2048`)

Notes:
- The service runs HTTP only; terminate TLS at your proxy.
- JWKS file persists between restarts; mount a volume (compose already maps `./dist`).
- Additional env in code (issuer/audience, legacy paths) exist but are not required for the minimal AASA/JWKS/Health setup.

---

## Repository Layout

- `cmd/local/main.go`: HTTP server and routes (no TLS), exposes AASA/JWKS/Health/Handshake
- `pkg/handlers/well-known.go`: AASA + JWKS handlers and init
- `pkg/jwks/jwks.go`: JWKS loader/creator (RSA, RS256)
- `pkg/constants/constants.go`: configuration and env helpers
- `Dockerfile`: multi‑stage Go build
- `docker-compose.haproxy.yml`: service with volume for `dist`, proxy‑friendly
- `scripts/dev_up.sh`: local build helper
- `scripts/test_endpoints.sh`: quick endpoint checks

Legacy helpers:
- `cmd/authentik/*` (Authentik client utilities)

---

## Development

- Install Go 1.22+
- Run `./scripts/dev_up.sh` to tidy, vet, and build
- Use `docker compose -f docker-compose.haproxy.yml --env-file .env.psso up -d --build` to run in Docker

---

## Troubleshooting

- 404 on AASA/JWKS behind proxy: ensure path rules route `/.well-known/*` to psso
- Wrong AASA content type: verify `Content-Type: application/json`
- JWKS not found: first request creates it; check write permissions on `JWKS_PATH`
- macOS doesn’t pick up extension: verify AASA reachable over HTTPS without redirect and TeamID+BundleID string

---

## Security

- JWKS is public‑only; no private keys are served
- No password grant or ROPC endpoints are exposed
- TLS should be terminated by Cloudflare/HAProxy; service itself listens on HTTP only

---

## License & Contributions

- MIT License
- PRs and issues welcome. Keep changes focused and pass `go vet`.
