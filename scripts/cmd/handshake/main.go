package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	crand "crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log"
	mrand "math/rand"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	jose "github.com/go-jose/go-jose/v3"
	josejwt "github.com/go-jose/go-jose/v3/jwt"
)

type nonceResponse struct {
	Nonce string `json:"nonce"`
}

type tokenError struct {
	Error string `json:"error"`
}

type keyRequest struct {
	DeviceID         string `json:"device_id"`
	SigningKeyPEM    string `json:"signing_key_pem"`
	SigningKeyID     string `json:"signing_key_id"`
	EncryptionKeyPEM string `json:"encryption_key_pem"`
	EncryptionKeyID  string `json:"encryption_key_id"`
	KeyVersion       string `json:"key_version"`
}

func main() {
	base := "http://localhost:9100"
	if len(os.Args) > 1 {
		base = os.Args[1]
	}

	httpClient := &http.Client{Timeout: 15 * time.Second}
	ctx := context.Background()

	signingKey, signingPEM := mustGenerateSigningKey()
	_, encPEM := mustGenerateEncryptionKey()

	deviceID := fmt.Sprintf("smoke-%d", mrand.New(mrand.NewSource(time.Now().UnixNano())).Int63())
	keyID := "device-key"

	registerPayload := keyRequest{
		DeviceID:         deviceID,
		SigningKeyPEM:    signingPEM,
		SigningKeyID:     keyID,
		EncryptionKeyPEM: encPEM,
		EncryptionKeyID:  keyID + "-enc",
		KeyVersion:       "v1",
	}
	if err := postJSON(ctx, httpClient, base+"/key", registerPayload); err != nil {
		log.Fatalf("register device: %v", err)
	}
	log.Printf("registered device %s", deviceID)

	nonceResp, err := httpClient.Post(base+"/nonce", "application/json", strings.NewReader(`{"device_id":"`+deviceID+`"}`))
	if err != nil {
		log.Fatalf("request nonce: %v", err)
	}
	defer nonceResp.Body.Close()
	if nonceResp.StatusCode != http.StatusOK {
		log.Fatalf("/nonce returned %s", nonceResp.Status)
	}
	var noncePayload nonceResponse
	if err := json.NewDecoder(nonceResp.Body).Decode(&noncePayload); err != nil {
		log.Fatalf("decode nonce: %v", err)
	}

	assertion, err := buildAssertion(signingKey, keyID, deviceID, noncePayload.Nonce)
	if err != nil {
		log.Fatalf("build assertion: %v", err)
	}

	form := url.Values{}
	form.Set("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer")
	form.Set("assertion", assertion)

	tokenReq, err := http.NewRequestWithContext(ctx, http.MethodPost, base+"/token", strings.NewReader(form.Encode()))
	if err != nil {
		log.Fatalf("token request: %v", err)
	}
	tokenReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	tokenReq.Header.Set("Accept", "application/platformsso-login-response+jwt")

	tokenResp, err := httpClient.Do(tokenReq)
	if err != nil {
		log.Fatalf("token exchange: %v", err)
	}
	defer tokenResp.Body.Close()

	if tokenResp.StatusCode >= 500 {
		log.Fatalf("/token returned %s", tokenResp.Status)
	}

	var errPayload tokenError
	if strings.HasPrefix(tokenResp.Header.Get("Content-Type"), "application/json") {
		_ = json.NewDecoder(tokenResp.Body).Decode(&errPayload)
	}

	log.Printf("/token status: %s", tokenResp.Status)
	if errPayload.Error != "" {
		log.Printf("server message: %s", errPayload.Error)
	}
}

func mustGenerateSigningKey() (*ecdsa.PrivateKey, string) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), crand.Reader)
	if err != nil {
		log.Fatalf("generate signing key: %v", err)
	}
	pub, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		log.Fatalf("marshal signing pubkey: %v", err)
	}
	block := pem.Block{Type: "PUBLIC KEY", Bytes: pub}
	return key, string(pem.EncodeToMemory(&block))
}

func mustGenerateEncryptionKey() (*rsa.PrivateKey, string) {
	key, err := rsa.GenerateKey(crand.Reader, 2048)
	if err != nil {
		log.Fatalf("generate encryption key: %v", err)
	}
	pub, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		log.Fatalf("marshal encryption pubkey: %v", err)
	}
	block := pem.Block{Type: "PUBLIC KEY", Bytes: pub}
	return key, string(pem.EncodeToMemory(&block))
}

func buildAssertion(signingKey *ecdsa.PrivateKey, kid, deviceID, nonce string) (string, error) {
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: signingKey}, (&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", kid))
	if err != nil {
		return "", err
	}

	now := time.Now().UTC()
	claims := struct {
		josejwt.Claims
		DeviceID             string `json:"device_id"`
		Nonce                string `json:"nonce"`
		AuthenticationMethod string `json:"authentication_method"`
		Username             string `json:"username"`
		Password             string `json:"password"`
	}{
		Claims: josejwt.Claims{
			Issuer:   "device",
			Subject:  "smoke-user",
			Audience: josejwt.Audience{"psso"},
			IssuedAt: josejwt.NewNumericDate(now),
			Expiry:   josejwt.NewNumericDate(now.Add(2 * time.Minute)),
			ID:       nonce,
		},
		DeviceID:             deviceID,
		Nonce:                nonce,
		AuthenticationMethod: "password",
		Username:             "demo",
		Password:             "demo",
	}

	return josejwt.Signed(signer).Claims(claims).CompactSerialize()
}

func postJSON(ctx context.Context, client *http.Client, url string, body any) error {
	data, err := json.Marshal(body)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, strings.NewReader(string(data)))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("%s returned %s", url, resp.Status)
	}
	return nil
}
