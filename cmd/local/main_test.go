package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/argon-analytik/psso-server/pkg/constants"
	"github.com/argon-analytik/psso-server/pkg/handlers"
)

type noncePayload struct {
	Nonce string `json:"Nonce"`
}

func configureTestPaths(t *testing.T) func() {
	t.Helper()
	temp := t.TempDir()

	originalJWKS := constants.JWKSPath
	originalNonce := constants.NoncePath
	originalKeys := constants.KeyPath
	originalDevices := constants.DeviceFilePath

	constants.JWKSPath = filepath.Join(temp, "jwks.json")
	constants.NoncePath = filepath.Join(temp, "nonces")
	constants.KeyPath = filepath.Join(temp, "keys")
	constants.DeviceFilePath = filepath.Join(temp, "devices")

	return func() {
		constants.JWKSPath = originalJWKS
		constants.NoncePath = originalNonce
		constants.KeyPath = originalKeys
		constants.DeviceFilePath = originalDevices
	}
}

func TestNewRouterRegistersExpectedRoutes(t *testing.T) {
	cleanup := configureTestPaths(t)
	defer cleanup()

	handlers.CheckWellKnowns()

	router := NewRouter()

	tests := []struct {
		name            string
		method          string
		path            string
		wantStatus      int
		wantContentType string
	}{
		{name: "jwks", method: http.MethodGet, path: constants.EndpointJWKS, wantStatus: http.StatusOK, wantContentType: "application/json"},
		{name: "aasa", method: http.MethodGet, path: constants.EndpointAppleSiteAssoc, wantStatus: http.StatusOK, wantContentType: "application/json"},
		{name: "nonce", method: http.MethodGet, path: constants.EndpointNonce, wantStatus: http.StatusOK, wantContentType: "application/json"},
		{name: "register", method: http.MethodGet, path: constants.EndpointRegister, wantStatus: http.StatusMethodNotAllowed},
		{name: "token", method: http.MethodGet, path: constants.EndpointToken, wantStatus: http.StatusMethodNotAllowed},
		{name: "healthz", method: http.MethodGet, path: constants.EndpointHealthz, wantStatus: http.StatusOK},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, tt.path, nil)
			handler, pattern := router.Handler(req)
			if pattern == "" {
				t.Fatalf("route %s not registered", tt.path)
			}

			rr := httptest.NewRecorder()
			handler.ServeHTTP(rr, req)

			if rr.Code != tt.wantStatus {
				t.Fatalf("%s: expected status %d, got %d", tt.path, tt.wantStatus, rr.Code)
			}

			if tt.wantContentType != "" {
				if got := rr.Header().Get("Content-Type"); got != tt.wantContentType {
					t.Fatalf("%s: expected content-type %q, got %q", tt.path, tt.wantContentType, got)
				}
			}

			if tt.path == constants.EndpointNonce && rr.Code == http.StatusOK {
				var payload noncePayload
				if err := json.Unmarshal(rr.Body.Bytes(), &payload); err != nil {
					t.Fatalf("failed to decode nonce payload: %v", err)
				}
				if payload.Nonce == "" {
					t.Fatalf("nonce response missing nonce field")
				}
			}
		})
	}
}
