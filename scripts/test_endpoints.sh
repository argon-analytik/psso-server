#!/usr/bin/env bash
set -euo pipefail

BASE="${1:-http://localhost:9100}"

echo "==> GET $BASE/healthz"
curl -fsS -o /dev/null -w 'status: %{http_code}\n' "$BASE/healthz"

echo "==> GET $BASE/.well-known/apple-app-site-association"
curl -fsS -H 'Accept: application/json' "$BASE/.well-known/apple-app-site-association" | jq .

echo "==> GET $BASE/.well-known/jwks.json"
curl -fsS -H 'Accept: application/json' "$BASE/.well-known/jwks.json" | jq .

echo "==> GET $BASE/nonce"
if ! curl -fsS -H 'Accept: application/json' "$BASE/nonce" | jq .; then
  echo "[warn] /nonce request failed – ensure PSSO_NONCEPATH is writable" >&2
fi

cat <<EOF

# Handshake POST examples (leave sample values in place until you have real data)
curl -X POST "$BASE/register" \\
  -H 'Content-Type: application/json' \\
  --data '{"DeviceUUID":"<uuid>","DeviceSigningKey":"<pem>","DeviceEncryptionKey":"<pem>","SignKeyID":"<base64>","EncKeyID":"<base64>"}'

curl -X POST "$BASE/token" \\
  -H 'Content-Type: application/x-www-form-urlencoded' \\
  --data 'platform_sso_version=1.0&assertion=<JWT>'
EOF

