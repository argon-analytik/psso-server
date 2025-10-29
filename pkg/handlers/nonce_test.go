package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/argon-analytik/psso-server/pkg/store"
)

func TestNonceHandlerTTL(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	st, err := store.NewFSStore(root, "", "")
	if err != nil {
		t.Fatalf("NewFSStore: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/nonce", nil)
	rr := httptest.NewRecorder()

	Nonce(st).ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected status 200 got %d", rr.Code)
	}

	var resp struct {
		Nonce     string    `json:"nonce"`
		ExpiresAt time.Time `json:"expires_at"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("response json: %v", err)
	}
	if resp.Nonce == "" {
		t.Fatalf("expected nonce value")
	}

	ttl := time.Until(resp.ExpiresAt)
	if ttl < 110*time.Second || ttl > 130*time.Second {
		t.Fatalf("expected ttl ~120s got %s", ttl)
	}
}

func TestNonceHandlerMethodNotAllowed(t *testing.T) {
	t.Parallel()

	st, err := store.NewFSStore(t.TempDir(), "", "")
	if err != nil {
		t.Fatalf("NewFSStore: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/nonce", nil)
	rr := httptest.NewRecorder()

	Nonce(st).ServeHTTP(rr, req)

	if rr.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected status 405 got %d", rr.Code)
	}
}
