package constants

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

const (
	GrantTypeJWTBearer = "urn:ietf:params:oauth:grant-type:jwt-bearer"
)

var (
	Address  = getEnv("PSSO_ADDRESS", ":9100")
	TeamID   = getEnv("TEAM_ID", "QUR8QTGXNB")
	BundleID = getEnv("APP_BUNDLE_ID", "ch.argio.psso")

	JWKSPath    = filepath.FromSlash(getEnv("JWKS_PATH", "./dist/jwks.json"))
	JWKSKeyBits = mustInt(getEnv("JWKS_KEY_BITS", "2048"))

	ServerSigningKeyPath    = filepath.FromSlash(getEnv("SERVER_SIGNING_KEY_PRIV_PATH", "./secrets/server_signing_key.pem"))
	ServerSigningKeyKID     = getEnv("SERVER_SIGNING_KEY_KID", "argio-ss1")
	ServerEncryptionKeyPath = filepath.FromSlash(getEnv("SERVER_ENC_KEY_PRIV_PATH", ""))

	StateDir   = filepath.FromSlash(getEnv("STATE_DIR", "./dist/state"))
	NoncePath  = filepath.FromSlash(getEnv("NONCE_PATH", filepath.Join(StateDir, "nonces")))
	DevicePath = filepath.FromSlash(getEnv("DEVICE_PATH", filepath.Join(StateDir, "devices")))

	AuthentikBaseURL       = getEnv("AUTHENTIK_BASE_URL", "https://auth.argio.ch")
	AuthentikTokenEndpoint = getEnv("AUTHENTIK_TOKEN_ENDPOINT", "https://auth.argio.ch/application/o/token/")
	AKPasswordGrantEnabled = getEnvAsBool("AK_PASSWORD_GRANT_ENABLED", false)
	AKClientID             = getEnv("AK_CLIENT_ID", "")
	AKClientSecret         = getEnv("AK_CLIENT_SECRET", "")

	DebugEnabled = getEnvAsBool("DEBUG", false)

	EndpointJWKS           = "/.well-known/jwks.json"
	EndpointAppleSiteAssoc = "/.well-known/apple-app-site-association"
	EndpointHealthz        = "/healthz"
	EndpointNonce          = "/nonce"
	EndpointToken          = "/token"
	EndpointKey            = "/key"
)

func AASAApps() []string {
	team := strings.TrimSpace(TeamID)
	bundle := strings.TrimSpace(BundleID)
	if team == "" || bundle == "" {
		return []string{"QUR8QTGXNB.ch.argio.psso"}
	}
	return []string{fmt.Sprintf("%s.%s", team, bundle)}
}

func getEnv(key, fallback string) string {
	if value, ok := os.LookupEnv(key); ok && value != "" {
		return value
	}
	return fallback
}

func getEnvAsBool(key string, fallback bool) bool {
	if value, ok := os.LookupEnv(key); ok && value != "" {
		switch strings.ToLower(value) {
		case "1", "true", "yes", "on":
			return true
		case "0", "false", "no", "off":
			return false
		}
	}
	return fallback
}

func mustInt(value string) int {
	n, err := strconv.Atoi(value)
	if err != nil {
		return 2048
	}
	return n
}
