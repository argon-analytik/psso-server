package constants

import (
	"os"
	"path/filepath"
)

/* ---------- Apple App‑Site‑Association (nur Beispiel‑IDs) ---------- */
var AASAApps = [...]string{
	"QUR8QTGXNB.ch.argio.sso.container",
	"QUR8QTGXNB.ch.argio.sso.extension",
}

/* ---------- Umgebungs­variablen ---------- */
var (
	/* Basis */
	Issuer   = getEnv("PSSO_ISSUER", "https://auth.argio.ch")
	Audience = getEnv("PSSO_AUDIENCE", "macos")
	Address  = getEnv("PSSO_ADDRESS", ":9100") // Listens inside Docker net

	/* Datei‑/Pfad‑Konfiguration */
	TLSPrivateKeyPath       = getEnv("PSSO_TLSPRIVATEKEYPATH", filepath.FromSlash("/etc/psso/privkey.pem"))
	TLSCertificateChainPath = getEnv("PSSO_TLSCERTIFICATECHAINPATH", filepath.FromSlash("/etc/psso/fullchain.pem"))
	JWKSFilepath            = getEnv("PSSO_JWKSFILEPATH", filepath.FromSlash("/var/psso/jwks.json"))
	DeviceFilePath          = getEnv("PSSO_DEVICEFILEPATH", filepath.FromSlash("/var/psso/devices"))
	NoncePath               = getEnv("PSSO_NONCEPATH", filepath.FromSlash("/var/psso/nonce"))
	KeyPath                 = getEnv("PSSO_KEYPATH", filepath.FromSlash("/var/psso/keys"))

	/* Authentik Anbindung */
	AuthentikBaseURL       = getEnv("AUTHENTIK_BASE_URL", "http://server:9000")
	AuthentikTokenEndpoint = getEnv("AUTHENTIK_TOKEN_ENDPOINT", AuthentikBaseURL+"/application/o/token/")
	AuthentikClientID      = getEnv("AUTHENTIK_CLIENT_ID", "psso-server")
	AuthentikClientSecret  = getEnv("AUTHENTIK_CLIENT_SECRET", "")

	AdminGroups = getEnv("PSSO_ADMIN_GROUPS", "argon_admins")

	/* Öffentliche HTTP‑Routen */
	EndpointJWKS           = getEnv("PSSO_ENDPOINTJWKS", "/.well-known/jwks.json")
	EndpointAppleSiteAssoc = getEnv("PSSO_ENDPOINTAPPLESITEASSOC", "/.well-known/apple-app-site-association")
	EndpointNonce          = getEnv("PSSO_ENDPOINTNONCE", "/nonce")
	EndpointRegister       = getEnv("PSSO_ENDPOINTREGISTER", "/register")
	EndpointToken          = getEnv("PSSO_ENDPOINTTOKEN", "/token")
	EndpointHealthz        = getEnv("PSSO_ENDPOINTHEALTHZ", "/healthz")
)

/* ---------- Helfer ---------- */
func getEnv(key, fallback string) string {
	if value, ok := os.LookupEnv(key); ok && value != "" {
		return value
	}
	return fallback
}