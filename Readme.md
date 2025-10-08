# Argio PSSO Server (AASA/JWKS/Health)

Minimal Go service providing:

- AASA at `/.well-known/apple-app-site-association`
- JWKS (public keys only) at `/.well-known/jwks.json`
- Health at `/healthz`

No password flows (ROPC) – OAuth/OIDC (PKCE) is handled directly between the Apple Platform SSO extension and Authentik. Cloudflare/HAProxy friendly.

---

## Usage

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

3) Start locally/build

```bash
chmod +x scripts/*.sh
./scripts/dev_up.sh

# (optional) start via compose for HAProxy/cloudflared nets
docker compose -f docker-compose.haproxy.yml --env-file .env.psso up -d --build
```

4) Test endpoints

```bash
curl -s http://localhost:9100/healthz
curl -s http://localhost:9100/.well-known/apple-app-site-association | jq .
curl -s http://localhost:9100/.well-known/jwks.json | jq .
```

---

## AASA Requirements

- Must be reachable at `https://auth.argio.ch/.well-known/apple-app-site-association` without redirect
- Content-Type `application/json`
- Minimal payload:

```
{ "authsrv": { "apps": [ "${TEAM_ID}.${APP_BUNDLE_ID}" ] } }
```

On macOS test with:

```bash
sudo swcutil dl -d auth.argio.ch
sudo swcutil show | grep -A3 auth.argio.ch
```

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

## Notes

- JWKS is created on first request if missing (RSA, RS256, kid=timestamp)
- File path from `JWKS_PATH`; defaults to `./dist/jwks.json`
- No ROPC endpoints are registered
