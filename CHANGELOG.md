# Changelog

## [Unreleased]
- Added full Platform SSO handshake implementation (`/nonce`, `/token`, `/key`) using go-jose.
- Integrated Authentik password grant with feature flag support.
- Introduced file-backed device & nonce store with replay protection.
- Added JOSE helpers for server key management and JWKS publication.
- Updated documentation, scripts, and smoke tests for the new handshake flow.
- Added GitHub Actions CI pipeline for `go build` and `go vet`.
