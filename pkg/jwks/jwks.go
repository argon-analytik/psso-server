package jwks

import (
    "crypto/rand"
    "crypto/rsa"
    "encoding/json"
    "fmt"
    "os"
    "path/filepath"
    "strconv"
    "time"

    jose "github.com/go-jose/go-jose/v3"
)

// LoadOrCreate returns the JWKS JSON bytes at path. If the file does not
// exist, it generates a new RSA key (bits) and writes a public-only JWKS.
func LoadOrCreate(path string, bits int) ([]byte, error) {
    if path == "" {
        return nil, fmt.Errorf("jwks path is empty")
    }
    if _, err := os.Stat(path); err == nil {
        return os.ReadFile(path)
    }

    // Ensure parent directory exists
    if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
        return nil, fmt.Errorf("create jwks dir: %w", err)
    }

    // Generate RSA key
    if bits <= 0 {
        bits = 2048
    }
    key, err := rsa.GenerateKey(rand.Reader, bits)
    if err != nil {
        return nil, fmt.Errorf("generate rsa: %w", err)
    }

    // Use only the public key in JWKS
    kid := strconv.FormatInt(time.Now().UTC().Unix(), 10)
    jwk := jose.JSONWebKey{
        Key:       &key.PublicKey,
        KeyID:     kid,
        Algorithm: string(jose.RS256),
        Use:       "sig",
    }
    set := jose.JSONWebKeySet{Keys: []jose.JSONWebKey{jwk}}

    data, err := json.Marshal(set)
    if err != nil {
        return nil, fmt.Errorf("marshal jwks: %w", err)
    }
    if err := os.WriteFile(path, data, 0o644); err != nil {
        return nil, fmt.Errorf("write jwks: %w", err)
    }
    return data, nil
}

