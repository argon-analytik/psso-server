#!/usr/bin/env bash
set -euo pipefail

BASE="${1:-http://localhost:9100}"
SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)

echo "==> Performing Platform SSO handshake smoke-test against ${BASE}"
go run "${SCRIPT_DIR}/cmd/handshake" "${BASE}"
