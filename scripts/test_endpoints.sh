#!/usr/bin/env bash
set -euo pipefail

BASE="${1:-http://localhost:9100}"

header() {
  echo "==> $1"
}

header "GET $BASE/healthz"
curl -fsS -o /dev/null -w 'status: %{http_code}\n' "$BASE/healthz"

header "GET $BASE/.well-known/apple-app-site-association"
curl -fsS -H 'Accept: application/json' "$BASE/.well-known/apple-app-site-association" | jq .

header "GET $BASE/.well-known/jwks.json"
curl -fsS -H 'Accept: application/json' "$BASE/.well-known/jwks.json" | jq .

header "POST $BASE/nonce"
curl -fsS -X POST -H 'Content-Type: application/json' -d '{}' "$BASE/nonce" | jq .

cat <<'INFO'
# Handshake endpoints (manual invocation)
# 1. Register device keys
curl -X POST "$BASE/key" \
  -H 'Content-Type: application/json' \
  --data '{"device_id":"<uuid>","signing_key_pem":"-----BEGIN PUBLIC KEY-----...","encryption_key_pem":"-----BEGIN PUBLIC KEY-----...","signing_key_id":"device-signing","encryption_key_id":"device-encryption","key_version":"v1"}'

# 2. Request nonce
curl -X POST -H 'Content-Type: application/json' -d '{"device_id":"<uuid>"}' "$BASE/nonce"

# 3. Exchange token (provide JOSE-signed assertion)
curl -X POST "$BASE/token" \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -H 'Accept: application/platformsso-login-response+jwt' \
  --data 'grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer&assertion=<SIGNED_JWT>'
INFO
