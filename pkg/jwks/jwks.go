package jwks

import (
    "encoding/json"
    "fmt"
    "os"
    "path/filepath"

    jose "github.com/go-jose/go-jose/v3"
)

type Provider interface {
    Bytes() ([]byte, error)
}

func Write(path string, keys []jose.JSONWebKey) ([]byte, error) {
    if len(keys) == 0 {
        return nil, fmt.Errorf("jwks requires at least one key")
    }
    publicKeys := make([]jose.JSONWebKey, len(keys))
    for i, key := range keys {
        jwk := jose.JSONWebKey{Key: key.Key}
        if !jwk.Valid() {
            return nil, fmt.Errorf("invalid jwk at index %d", i)
        }
        pub := jwk.Public()
        publicKeys[i] = key
        publicKeys[i].Key = pub.Key
    }
    data, err := json.Marshal(struct {
        Keys []jose.JSONWebKey `json:"keys"`
    }{Keys: publicKeys})
    if err != nil {
        return nil, fmt.Errorf("marshal jwks: %w", err)
    }
    if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
        return nil, fmt.Errorf("prepare jwks dir: %w", err)
    }
    if err := os.WriteFile(path, data, 0o644); err != nil {
        return nil, fmt.Errorf("write jwks: %w", err)
    }
    return data, nil
}

func Load(path string) ([]byte, error) {
    data, err := os.ReadFile(path)
    if err != nil {
        return nil, err
    }
    return data, nil
}
