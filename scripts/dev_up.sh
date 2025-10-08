#!/usr/bin/env bash
set -euo pipefail

mkdir -p dist
go mod tidy
go vet ./... || true
go build ./...
echo "Start local psso (compose) if needed:"
echo "  docker compose -f docker-compose.haproxy.yml --env-file .env.psso up -d --build"
echo
echo "Test endpoints (adjust base URL if behind proxy):"
echo "  curl -s http://localhost:9100/healthz"
echo "  curl -s http://localhost:9100/.well-known/apple-app-site-association | jq ."
echo "  curl -s http://localhost:9100/.well-known/jwks.json | jq ."

