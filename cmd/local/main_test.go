package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/argon-analytik/psso-server/pkg/authentik"
	"github.com/argon-analytik/psso-server/pkg/constants"
	"github.com/argon-analytik/psso-server/pkg/crypto"
	"github.com/argon-analytik/psso-server/pkg/jwks"
	"github.com/argon-analytik/psso-server/pkg/store"
	jose "github.com/go-jose/go-jose/v3"
)

func writeRSAKey(t *testing.T, path string) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	block := &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}
	if err := os.WriteFile(path, pem.EncodeToMemory(block), 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}
}

func configureConstants(t *testing.T, root string) func() {
	t.Helper()
	originalJWKS := constants.JWKSPath
	originalState := constants.StateDir
	originalNonce := constants.NoncePath
	originalDevice := constants.DevicePath
	originalSigning := constants.ServerSigningKeyPath
	originalKID := constants.ServerSigningKeyKID

	constants.JWKSPath = filepath.Join(root, "jwks.json")
	constants.StateDir = filepath.Join(root, "state")
	constants.NoncePath = filepath.Join(constants.StateDir, "nonces")
	constants.DevicePath = filepath.Join(constants.StateDir, "devices")
	constants.ServerSigningKeyPath = filepath.Join(root, "signing.pem")
	constants.ServerSigningKeyKID = "test-kid"

	return func() {
		constants.JWKSPath = originalJWKS
		constants.StateDir = originalState
		constants.NoncePath = originalNonce
		constants.DevicePath = originalDevice
		constants.ServerSigningKeyPath = originalSigning
		constants.ServerSigningKeyKID = originalKID
	}
}

func TestNewRouterRegistersExpectedRoutes(t *testing.T) {
	temp := t.TempDir()
	restore := configureConstants(t, temp)
	defer restore()

	writeRSAKey(t, constants.ServerSigningKeyPath)

	cryptoSvc, err := crypto.NewService(constants.ServerSigningKeyPath, constants.ServerSigningKeyKID, "")
	if err != nil {
		t.Fatalf("init crypto: %v", err)
	}

	keys := []jose.JSONWebKey{cryptoSvc.SigningPublicJWK()}
	if _, err := jwks.Write(constants.JWKSPath, keys); err != nil {
		t.Fatalf("write jwks: %v", err)
	}

	st, err := store.NewFSStore(constants.StateDir, constants.DevicePath, constants.NoncePath)
	if err != nil {
		t.Fatalf("init store: %v", err)
	}

	router := newRouter(st, cryptoSvc, &authentik.Client{})

	cases := []struct {
		name       string
		method     string
		path       string
		wantStatus int
	}{
		{name: "jwks", method: http.MethodGet, path: constants.EndpointJWKS, wantStatus: http.StatusOK},
		{name: "aasa", method: http.MethodGet, path: constants.EndpointAppleSiteAssoc, wantStatus: http.StatusOK},
		{name: "nonce-post", method: http.MethodPost, path: constants.EndpointNonce, wantStatus: http.StatusOK},
		{name: "nonce-get", method: http.MethodGet, path: constants.EndpointNonce, wantStatus: http.StatusMethodNotAllowed},
		{name: "key", method: http.MethodPost, path: constants.EndpointKey, wantStatus: http.StatusBadRequest},
		{name: "token", method: http.MethodPost, path: constants.EndpointToken, wantStatus: http.StatusBadRequest},
		{name: "healthz", method: http.MethodGet, path: constants.EndpointHealthz, wantStatus: http.StatusOK},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(tc.method, tc.path, nil)
			if tc.path == constants.EndpointToken && tc.method == http.MethodPost {
				req.Header.Set("Accept", "application/platformsso-login-response+jwt")
			}
			rr := httptest.NewRecorder()

			handler, pattern := router.Handler(req)
			if pattern == "" {
				t.Fatalf("route %s not registered", tc.path)
			}

			handler.ServeHTTP(rr, req)
			if rr.Code != tc.wantStatus {
				t.Fatalf("%s: expected %d, got %d", tc.path, tc.wantStatus, rr.Code)
			}
		})
	}

	// Ensure nonce endpoint returns JSON body
	req := httptest.NewRequest(http.MethodPost, constants.EndpointNonce, nil)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("nonce unexpected status %d", rr.Code)
	}
	if ct := rr.Header().Get("Content-Type"); ct != "application/json" {
		t.Fatalf("nonce content-type = %s", ct)
	}
	if rr.Body.Len() == 0 {
		t.Fatalf("expected nonce body")
	}

	// Give asynchronous store a moment to flush to disk for coverage
	time.Sleep(10 * time.Millisecond)
}
