# Platform SSO gap analysis (initial)

## Overview
The current codebase still mirrors the earlier TwoCanoes demo server and only offers a minimal Platform SSO handshake. The following table summarises where it diverges from the new Platform-SSO2 requirements.

## Endpoint coverage
- **AASA/JWKS/healthz**: Implemented via `pkg/handlers/well-known.go` and `pkg/handlers/healthz.go`, but missing proper cache headers and hard-coded defaults; router currently serves `/register` instead of `/key`.
- **Handshake endpoints**: `/nonce` and `/token` exist, yet `/key` is absent. The router registers `/register` (`pkg/handlers/register.go`) using legacy payloads instead of the new key exchange semantics. None of the handlers use the required JOSE flow or replay protection.

## Security & JOSE handling
- Uses `github.com/twocanoes/psso-sdk-go/psso` helpers with custom files, not `go-jose/v3`.
- Nonces are generated but never verified inside `/token`; stored as JSON files without TTL enforcement or one-time semantics.
- `/token` validates JWTs using ECDSA helpers, does not issue signed+encrypted responses via go-jose, and lacks kid management tied to environment variables.
- JWKS generation currently depends on the SDK helper and stores private keys in flat files that can be exposed accidentally.

## Authentik integration
- Legacy code in `cmd/authentik` performs role lookups but no OAuth 2.0 token exchange. There is no password grant (ROPC) implementation or feature flag. Credentials from the device assertion are passed directly to role lookup helpers instead of trading them for `id_token`/`refresh_token`.

## State & storage
- Persistence implemented as ad-hoc JSON files via `pkg/file`. No abstraction for devices/nonces, no `STATE_DIR` defaults, and key data includes both signing and encryption keys in same structure. Device records lack `last_seen` updates and key versioning.

## Configuration
- Environment variables still use legacy prefixes (e.g. `PSSO_*`). Required new settings such as `SERVER_SIGNING_KEY_PRIV_PATH`, `SERVER_SIGNING_KEY_KID`, `STATE_DIR`, `AUTHENTIK_TOKEN_ENDPOINT`, `AK_PASSWORD_GRANT_ENABLED`, etc., are missing.
- No validation that required secrets exist at startup.

## Router & structure
- `cmd/local/main.go` sets up routes for `/register` instead of `/key` and does not centralise middleware/logging. Shutdown logic is partially implemented but mixes tabs/spaces and lacks context timeouts in seconds.
- Package layout misses `pkg/crypto` and `pkg/store` abstractions required for JOSE helpers and persistence.

## AASA/JWKS content
- AASA payload is generated but defaults to legacy IDs and omits required cache headers. Need to ensure the app string always resolves to `QUR8QTGXNB.ch.argio.psso` fallback.
- JWKS uses SDK to generate combined key set, not restricted to public keys. No stable `kid` management.

## Tooling & tests
- Only `scripts/test_endpoints.sh` exists; lacks handshake smoke tests, Go unit coverage, or CI workflows.
- README describes legacy register endpoint and no password flow, missing architecture diagrams, environment table, proxy examples referencing `/key` endpoint, or troubleshooting for missing secrets.

## Documentation & reports
- `psso-psso2-gap.md` (this file) previously absent; needs before/after updates.
- No CHANGELOG entry for upcoming features.

## Summary of required work
1. Replace legacy handlers with go-jose based implementations for nonce/token/key, including store-backed replay protection and device key management.
2. Introduce crypto utilities for loading signing/encryption keys, ensure JWKS exposes public keys only, and enforce kid consistency.
3. Implement Authentik password grant flow guarded by `AK_PASSWORD_GRANT_ENABLED` env flag and return id/refresh tokens to devices.
4. Build configurable store (file or SQLite) under `STATE_DIR` handling devices and nonces with TTL.
5. Refresh configuration constants, validation, README, scripts, tests, CI, and add CHANGELOG notes.

## Current status (post-implementation)
- New handlers live in `pkg/handlers` and rely on go-jose for signing/encryption, while `/key` replaces the legacy `/register` endpoint.
- `pkg/crypto` loads server keys, signs responses, and publishes JWKS with the configured `kid`; optional decrypt support handles nested JWEs.
- `pkg/store` provides a file-backed implementation for devices and nonces with TTL + one-time semantics.
- Authentik integration lives in `pkg/authentik` with password grant gated by `AK_PASSWORD_GRANT_ENABLED` and validated client credentials.
- CLI tools & scripts (`scripts/test_endpoints.sh`, `scripts/test_handshake.sh`) verify endpoints and handshake; docs/README updated along with a CHANGELOG entry.
