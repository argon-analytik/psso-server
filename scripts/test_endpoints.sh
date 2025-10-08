#!/usr/bin/env bash
set -euo pipefail

BASE="${1:-http://localhost:9100}"
curl -si "$BASE/healthz"
curl -s "$BASE/.well-known/apple-app-site-association" | jq .
curl -s "$BASE/.well-known/jwks.json" | jq . || true

