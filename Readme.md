# Argio PSSO Server

Minimal, production‑ready service for Apple Platform SSO setups with Authentik as IdP — without password grant. Provides only the endpoints macOS/iOS actually need, and plays nicely behind Cloudflare/HAProxy. Reproducible and container‑first.

---

## Features

- AASA endpoint: `/.well-known/apple-app-site-association`
- JWKS (public keys only): `/.well-known/jwks.json`
- Health check: `/healthz`
- No ROPC or password‑grant flows; PKCE/OAuth handled by the Platform SSO extension ↔ Authentik
- Cloud proxy friendly (HTTP, no in‑process TLS; terminate at CF/HAProxy)
- Reproducible Docker build

---

## Overview

- Purpose: Serve AASA and JWKS for Apple’s Platform SSO so that macOS can discover the extension and validate tokens/keys. The extension itself talks to Authentik using PKCE; this server does not relay user credentials.
- Scope: Only well‑knowns + health. Legacy endpoints for device register/token exist in the repo but are not exposed by default.

---

## Endpoints

- `/.well-known/apple-app-site-association` (AASA)
  - Content‑Type: `application/json`
  - Payload (minimal): `{ "authsrv": { "apps": [ "${TEAM_ID}.${APP_BUNDLE_ID}" ] } }`
  - Also includes empty `applinks` and `webcredentials`
- `/.well-known/jwks.json` (JWKS)
  - Returns a public‑only JSON Web Key Set (RSA, RS256)
  - If `JWKS_PATH` doesn’t exist, a new key is generated on first request; `kid = unix timestamp`
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
curl -s http://localhost:9100/healthz
curl -s http://localhost:9100/.well-known/apple-app-site-association | jq .
curl -s http://localhost:9100/.well-known/jwks.json | jq .
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
use_backend bk_psso if is_aasa or is_jwks
backend bk_psso
  server psso psso:9100 check
```

cloudflared (config.yml excerpt):
```
ingress:
  - hostname: auth.argio.ch
    path: /.well-known/*
    service: http://psso:9100
  - hostname: auth.argio.ch
    service: http://authentik:9000
```

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

- `cmd/local/main.go`: HTTP server and routes (no TLS), exposes AASA/JWKS/Health
- `pkg/handlers/well-known.go`: AASA + JWKS handlers and init
- `pkg/jwks/jwks.go`: JWKS loader/creator (RSA, RS256)
- `pkg/constants/constants.go`: configuration and env helpers
- `Dockerfile`: multi‑stage Go build
- `docker-compose.haproxy.yml`: service with volume for `dist`, proxy‑friendly
- `scripts/dev_up.sh`: local build helper
- `scripts/test_endpoints.sh`: quick endpoint checks

Legacy (not registered by default):
- `pkg/handlers/{token.go,register.go,nonce.go}` and `cmd/authentik/*`

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
