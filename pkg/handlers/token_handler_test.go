package handlers

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/argon-analytik/psso-server/pkg/authentik"
	"github.com/argon-analytik/psso-server/pkg/constants"
	"github.com/argon-analytik/psso-server/pkg/crypto"
	"github.com/argon-analytik/psso-server/pkg/store"
	jose "github.com/go-jose/go-jose/v3"
	josejwt "github.com/go-jose/go-jose/v3/jwt"
)

type memoryStore struct {
	device store.Device
	nonces map[string]store.Nonce
}

func (m *memoryStore) UpsertDevice(_ context.Context, device store.Device) (store.Device, error) {
	m.device = device
	return device, nil
}

func (m *memoryStore) GetDevice(_ context.Context, deviceID string) (store.Device, error) {
	if m.device.DeviceID == "" || !strings.EqualFold(m.device.DeviceID, deviceID) {
		return store.Device{}, store.ErrDeviceNotFound
	}
	return m.device, nil
}

func (m *memoryStore) SaveNonce(_ context.Context, nonce store.Nonce) error {
	if m.nonces == nil {
		m.nonces = make(map[string]store.Nonce)
	}
	if _, ok := m.nonces[nonce.Value]; ok {
		return store.ErrNonceUsed
	}
	m.nonces[nonce.Value] = nonce
	return nil
}

func (m *memoryStore) ConsumeNonce(_ context.Context, value, deviceID string) (store.Nonce, error) {
	if m.nonces == nil {
		m.nonces = make(map[string]store.Nonce)
	}
	nonce, ok := m.nonces[value]
	if !ok {
		return store.Nonce{}, store.ErrNonceNotFound
	}
	if nonce.Used {
		return store.Nonce{}, store.ErrNonceUsed
	}
	if nonce.DeviceID != "" && deviceID != "" && !strings.EqualFold(nonce.DeviceID, deviceID) {
		return store.Nonce{}, store.ErrNonceMismatch
	}
	nonce.Used = true
	nonce.UsedAt = time.Now().UTC()
	m.nonces[value] = nonce
	return nonce, nil
}

const (
	testIssuer   = "https://example.test/issuer"
	testAudience = "com.example.bundle"
	testDeviceID = "device-1234"
)

func newTestCryptoService(t *testing.T) *crypto.Service {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate signing key: %v", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("marshal signing key: %v", err)
	}
	pemData := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	dir := t.TempDir()
	path := filepath.Join(dir, "signing.pem")
	if err := os.WriteFile(path, pemData, 0o600); err != nil {
		t.Fatalf("write signing key: %v", err)
	}

	svc, err := crypto.NewService(path, "test-signing", "")
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	return svc
}

func encodePublicKeyPEM(t *testing.T, key interface{}) string {
	t.Helper()

	der, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		t.Fatalf("marshal public key: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
}

func newTokenTestInputs(t *testing.T, modify func(*tokenRequestClaims)) (TokenDependencies, string, *memoryStore) {
	t.Helper()

	authServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{
			"id_token":      "id-token",
			"refresh_token": "refresh-token",
		})
	}))
	t.Cleanup(authServer.Close)

	deviceSigningKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate device signing key: %v", err)
	}
	deviceEncryptionKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate device encryption key: %v", err)
	}

	memStore := &memoryStore{
		device: store.Device{
			DeviceID:         testDeviceID,
			SigningKeyPEM:    encodePublicKeyPEM(t, &deviceSigningKey.PublicKey),
			SigningKeyID:     "device-signing",
			EncryptionKeyPEM: encodePublicKeyPEM(t, &deviceEncryptionKey.PublicKey),
			EncryptionKeyID:  "device-encryption",
			KeyVersion:       "v1",
		},
		nonces: map[string]store.Nonce{},
	}

	now := time.Now().UTC()
	nonceValue := "nonce-123"
	memStore.nonces[nonceValue] = store.Nonce{
		Value:     nonceValue,
		DeviceID:  testDeviceID,
		ExpiresAt: now.Add(5 * time.Minute),
	}

	claims := tokenRequestClaims{
		Claims: josejwt.Claims{
			Issuer:   testIssuer,
			Subject:  "user@example.test",
			Audience: []string{testAudience},
			IssuedAt: josejwt.NewNumericDate(now.Add(-time.Minute)),
			Expiry:   josejwt.NewNumericDate(now.Add(5 * time.Minute)),
			ID:       nonceValue,
		},
		DeviceID:             testDeviceID,
		Nonce:                nonceValue,
		AuthenticationMethod: "password",
		Username:             "user@example.test",
		Password:             "secret",
	}

	if modify != nil {
		modify(&claims)
	}

	assertion := signAssertion(t, deviceSigningKey, claims)

	deps := TokenDependencies{
		Store:  memStore,
		Crypto: newTestCryptoService(t),
		Authentik: &authentik.Client{
			Endpoint: authServer.URL,
		},
		Config: TokenConfig{
			PasswordGrantEnabled: true,
			Issuer:               testIssuer,
			Audience:             []string{testAudience},
		},
	}

	return deps, assertion, memStore
}

func signAssertion(t *testing.T, key *ecdsa.PrivateKey, claims tokenRequestClaims) string {
	t.Helper()

	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: key}, (&jose.SignerOptions{}).WithType("JWT"))
	if err != nil {
		t.Fatalf("new signer: %v", err)
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("marshal claims: %v", err)
	}
	jws, err := signer.Sign(payload)
	if err != nil {
		t.Fatalf("sign jwt: %v", err)
	}
	serialized, err := jws.CompactSerialize()
	if err != nil {
		t.Fatalf("serialize jwt: %v", err)
	}
	return serialized
}

func newTokenRequest(assertion string) *http.Request {
	form := url.Values{}
	form.Set("grant_type", constants.GrantTypeJWTBearer)
	form.Set("assertion", assertion)
	req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", tokenAcceptLoginResponse)
	return req
}

func TestTokenHandlerRejectsUnsupportedAccept(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		accept string
	}{
		{
			name:   "missing",
			accept: "",
		},
		{
			name:   "wrong type",
			accept: "application/json",
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			deps, assertion, _ := newTokenTestInputs(t, nil)
			req := newTokenRequest(assertion)
			if tt.accept == "" {
				req.Header.Del("Accept")
			} else {
				req.Header.Set("Accept", tt.accept)
			}
			rr := httptest.NewRecorder()
			Token(deps).ServeHTTP(rr, req)
			if rr.Code != http.StatusNotAcceptable {
				t.Fatalf("expected status 406 got %d", rr.Code)
			}
			if ct := rr.Header().Get("Content-Type"); ct != "application/json" {
				t.Fatalf("expected json response got %q", ct)
			}
		})
	}
}

func TestTokenHandlerSuccessSetsSecurityHeaders(t *testing.T) {
	t.Parallel()

	deps, assertion, _ := newTokenTestInputs(t, nil)
	req := newTokenRequest(assertion)
	rr := httptest.NewRecorder()

	Token(deps).ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected status 200 got %d", rr.Code)
	}
	if ct := rr.Header().Get("Content-Type"); ct != tokenAcceptLoginResponse {
		t.Fatalf("expected content type %q got %q", tokenAcceptLoginResponse, ct)
	}
	if cc := rr.Header().Get("Cache-Control"); cc != "no-store" {
		t.Fatalf("expected Cache-Control no-store got %q", cc)
	}
	if pragma := rr.Header().Get("Pragma"); pragma != "no-cache" {
		t.Fatalf("expected Pragma no-cache got %q", pragma)
	}
}

func TestTokenHandlerAudienceIssuerMismatch(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		modify func(*tokenRequestClaims)
	}{
		{
			name: "wrong audience",
			modify: func(claims *tokenRequestClaims) {
				claims.Audience = []string{"invalid"}
			},
		},
		{
			name: "wrong issuer",
			modify: func(claims *tokenRequestClaims) {
				claims.Issuer = "https://invalid.example"
			},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			deps, assertion, _ := newTokenTestInputs(t, tt.modify)
			req := newTokenRequest(assertion)
			rr := httptest.NewRecorder()

			Token(deps).ServeHTTP(rr, req)

			if rr.Code != http.StatusUnauthorized {
				t.Fatalf("expected status 401 got %d", rr.Code)
			}
			var resp map[string]string
			if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
				t.Fatalf("decode response: %v", err)
			}
			if resp["error"] != "assertion invalid: audience/issuer mismatch" {
				t.Fatalf("unexpected error message: %q", resp["error"])
			}
		})
	}
}

func TestTokenHandlerNonceReplay(t *testing.T) {
	t.Parallel()

	deps, assertion, memStore := newTokenTestInputs(t, nil)
	req := newTokenRequest(assertion)

	rr := httptest.NewRecorder()
	Token(deps).ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected first request success got %d", rr.Code)
	}

	// Re-run with the same nonce, which should now be marked as used.
	req2 := newTokenRequest(assertion)
	rr2 := httptest.NewRecorder()
	Token(deps).ServeHTTP(rr2, req2)

	if rr2.Code != http.StatusUnauthorized {
		t.Fatalf("expected second request 401 got %d", rr2.Code)
	}
	var resp map[string]string
	if err := json.Unmarshal(rr2.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp["error"] != "nonce invalid or already used" {
		t.Fatalf("unexpected error message: %q", resp["error"])
	}

	if nonce := memStore.nonces["nonce-123"]; !nonce.Used {
		t.Fatalf("expected nonce to be marked used")
	}
}

func TestTokenHandlerJWEMissingPrivateKey(t *testing.T) {
	t.Parallel()

	deps := TokenDependencies{
		Store:  &memoryStore{},
		Crypto: newTestCryptoService(t),
		Config: TokenConfig{},
	}

	form := url.Values{}
	form.Set("grant_type", constants.GrantTypeJWTBearer)
	form.Set("assertion", "a.b.c.d.e")
	req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", tokenAcceptLoginResponse)

	rr := httptest.NewRecorder()
	Token(deps).ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected status 400 got %d", rr.Code)
	}
	var resp map[string]string
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp["error"] != "server cannot decrypt assertion: missing private key" {
		t.Fatalf("unexpected error message: %q", resp["error"])
	}
}
