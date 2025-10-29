package handlers

import (
	"encoding/json"
	"errors"
	"fmt"
	"mime"
	"net/http"
	"strings"
	"time"

	"github.com/argon-analytik/psso-server/pkg/authentik"
	"github.com/argon-analytik/psso-server/pkg/constants"
	"github.com/argon-analytik/psso-server/pkg/crypto"
	"github.com/argon-analytik/psso-server/pkg/store"
	josejwt "github.com/go-jose/go-jose/v3/jwt"
)

type TokenConfig struct {
	PasswordGrantEnabled bool
	Issuer               string
	Audience             []string
}

const (
	tokenAcceptKeyResponse   = "application/platformsso-key-response+jwt"
	tokenAcceptLoginResponse = "application/platformsso-login-response+jwt"
)

func negotiateTokenContentType(header http.Header) (string, bool) {
	accepts := header.Values("Accept")
	if len(accepts) == 0 {
		return tokenAcceptLoginResponse, true
	}

	for _, value := range accepts {
		for _, part := range strings.Split(value, ",") {
			mediaType, _, err := mime.ParseMediaType(strings.TrimSpace(part))
			if err != nil {
				continue
			}
			switch strings.ToLower(mediaType) {
			case tokenAcceptKeyResponse:
				return tokenAcceptKeyResponse, true
			case tokenAcceptLoginResponse:
				return tokenAcceptLoginResponse, true
			case "*/*", "application/*":
				return tokenAcceptLoginResponse, true
			}
		}
	}

	return "", false
}

type tokenRequestClaims struct {
	josejwt.Claims
	DeviceID             string `json:"device_id"`
	Nonce                string `json:"nonce"`
	AuthenticationMethod string `json:"authentication_method"`
	Username             string `json:"username,omitempty"`
	Password             string `json:"password,omitempty"`
	KeyVersion           string `json:"key_version,omitempty"`
}

type tokenResponseClaims struct {
	josejwt.Claims
	DeviceID             string   `json:"device_id"`
	Nonce                string   `json:"nonce"`
	AuthenticationMethod string   `json:"authentication_method"`
	IDToken              string   `json:"id_token"`
	RefreshToken         string   `json:"refresh_token"`
	PreferredUsername    string   `json:"preferred_username,omitempty"`
	Name                 string   `json:"name,omitempty"`
	Groups               []string `json:"groups,omitempty"`
}

type idTokenPreview struct {
	PreferredUsername string   `json:"preferred_username"`
	Name              string   `json:"name"`
	Groups            []string `json:"groups"`
}

type TokenDependencies struct {
	Store     store.Store
	Crypto    *crypto.Service
	Authentik *authentik.Client
	Config    TokenConfig
}

func Token(deps TokenDependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if deps.Store == nil || deps.Crypto == nil {
			writeJSONError(w, http.StatusInternalServerError, "token handler not initialised")
			return
		}
		if r.Method != http.MethodPost {
			writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		contentType, ok := negotiateTokenContentType(r.Header)
		if !ok {
			writeJSONError(w, http.StatusNotAcceptable, "requested response content type not supported")
			return
		}
		if ct := r.Header.Get("Content-Type"); ct != "" && !strings.HasPrefix(ct, "application/x-www-form-urlencoded") {
			writeJSONError(w, http.StatusUnsupportedMediaType, "expected application/x-www-form-urlencoded")
			return
		}
		if err := r.ParseForm(); err != nil {
			writeJSONError(w, http.StatusBadRequest, "invalid form payload")
			return
		}
		if gt := r.PostFormValue("grant_type"); gt != constants.GrantTypeJWTBearer {
			writeJSONError(w, http.StatusBadRequest, "unsupported grant_type")
			return
		}
		assertion := r.PostFormValue("assertion")
		if assertion == "" {
			writeJSONError(w, http.StatusBadRequest, "assertion is required")
			return
		}

		payload := assertion
		if strings.Count(assertion, ".") == 4 {
			decrypted, err := deps.Crypto.Decrypt(assertion)
			if err != nil {
				if errors.Is(err, crypto.ErrNoDecryptionKey) {
					writeJSONError(w, http.StatusBadRequest, "server cannot decrypt assertion: missing private key")
					return
				}
				writeJSONError(w, http.StatusBadRequest, fmt.Sprintf("failed to decrypt assertion: %v", err))
				return
			}
			payload = decrypted
		}

		signed, err := josejwt.ParseSigned(payload)
		if err != nil {
			writeJSONError(w, http.StatusBadRequest, "invalid signed assertion")
			return
		}

		var preview tokenRequestClaims
		if err := signed.UnsafeClaimsWithoutVerification(&preview); err != nil {
			writeJSONError(w, http.StatusBadRequest, "unable to inspect assertion claims")
			return
		}
		if preview.DeviceID == "" {
			writeJSONError(w, http.StatusBadRequest, "device_id missing in assertion")
			return
		}

		device, err := deps.Store.GetDevice(r.Context(), preview.DeviceID)
		if err != nil {
			writeJSONError(w, http.StatusUnauthorized, "device not registered")
			return
		}

		signingKey, err := crypto.ParsePublicKeyPEM(device.SigningKeyPEM)
		if err != nil {
			writeJSONError(w, http.StatusInternalServerError, "failed to parse device signing key")
			return
		}

		if headerKID := signed.Headers[0].KeyID; headerKID != "" && device.KeyVersion != "" && headerKID != device.KeyVersion {
			writeJSONError(w, http.StatusUnauthorized, "device key version mismatch")
			return
		}

		var claims tokenRequestClaims
		if err := signed.Claims(signingKey, &claims); err != nil {
			writeJSONError(w, http.StatusUnauthorized, "invalid assertion signature")
			return
		}

		if err := claims.Validate(josejwt.Expected{Time: time.Now()}); err != nil {
			writeJSONError(w, http.StatusUnauthorized, "assertion expired or not yet valid")
			return
		}
		if claims.Nonce == "" {
			writeJSONError(w, http.StatusBadRequest, "nonce missing in assertion")
			return
		}

		if _, err := deps.Store.ConsumeNonce(r.Context(), claims.Nonce, claims.DeviceID); err != nil {
			status := http.StatusUnauthorized
			switch err {
			case store.ErrNonceExpired:
				status = http.StatusUnauthorized
			case store.ErrNonceNotFound, store.ErrNonceMismatch:
				status = http.StatusUnauthorized
			}
			writeJSONError(w, status, "nonce invalid or already used")
			return
		}

		method := strings.ToLower(claims.AuthenticationMethod)
		if method == "" {
			method = "password"
		}

		var token authentik.TokenResponse
		switch method {
		case "password":
			if !deps.Config.PasswordGrantEnabled {
				writeJSONError(w, http.StatusBadRequest, "password grant is disabled")
				return
			}
			if claims.Username == "" || claims.Password == "" {
				writeJSONError(w, http.StatusBadRequest, "username and password required for password grant")
				return
			}
			if deps.Authentik == nil {
				writeJSONError(w, http.StatusInternalServerError, "authentik client not configured")
				return
			}
			token, err = deps.Authentik.PasswordGrant(r.Context(), claims.Username, claims.Password)
			if err != nil {
				writeJSONError(w, http.StatusUnauthorized, fmt.Sprintf("authentik error: %v", err))
				return
			}
		default:
			writeJSONError(w, http.StatusBadRequest, "authentication_method not supported")
			return
		}

		var previewID idTokenPreview
		if parsedID, err := josejwt.ParseSigned(token.IDToken); err == nil {
			_ = parsedID.UnsafeClaimsWithoutVerification(&previewID)
		}
		if previewID.PreferredUsername == "" {
			previewID.PreferredUsername = claims.Username
		}
		response := tokenResponseClaims{
			Claims: josejwt.Claims{
				Issuer:   deps.Config.Issuer,
				Subject:  claims.Username,
				Audience: deps.Config.Audience,
				IssuedAt: josejwt.NewNumericDate(time.Now().UTC()),
				Expiry:   josejwt.NewNumericDate(time.Now().UTC().Add(5 * time.Minute)),
				ID:       claims.Nonce,
			},
			DeviceID:             claims.DeviceID,
			Nonce:                claims.Nonce,
			AuthenticationMethod: claims.AuthenticationMethod,
			IDToken:              token.IDToken,
			RefreshToken:         token.RefreshToken,
			PreferredUsername:    previewID.PreferredUsername,
			Name:                 previewID.Name,
			Groups:               previewID.Groups,
		}

		signedResponse, err := deps.Crypto.SignJWT(response)
		if err != nil {
			writeJSONError(w, http.StatusInternalServerError, "failed to sign response")
			return
		}

		encryptionKeyRaw, err := crypto.ParsePublicKeyPEM(device.EncryptionKeyPEM)
		if err != nil {
			writeJSONError(w, http.StatusInternalServerError, "invalid device encryption key")
			return
		}
		encKid := device.EncryptionKeyID
		if encKid == "" {
			encKid = device.KeyVersion
		}

		encrypted, err := deps.Crypto.EncryptForDevice(signedResponse, encryptionKeyRaw, encKid)
		if err != nil {
			writeJSONError(w, http.StatusInternalServerError, fmt.Sprintf("failed to encrypt response: %v", err))
			return
		}

		_, _ = deps.Store.UpsertDevice(r.Context(), device)

		w.Header().Set("Content-Type", contentType)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(encrypted))
	}
}

func writeJSONError(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": message})
}
