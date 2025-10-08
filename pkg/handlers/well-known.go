package handlers

import (
    "encoding/json"
    "fmt"
    "net/http"
    "net/http/httputil"
    "strconv"

    "github.com/argon-analytik/psso-server/pkg/constants"
    "github.com/argon-analytik/psso-server/pkg/jwks"
)

var currentAASA JSONAASA

type JSONAuthServe struct {
    Apps []string `json:"apps"`
}

type JSONAASA struct {
    AuthServ       JSONAuthServe  `json:"authsrv"`
    Applinks       map[string]any `json:"applinks,omitempty"`
    Webcredentials map[string]any `json:"webcredentials,omitempty"`
}

func CheckWellKnowns() {
    fmt.Println("Initializing well-knowns")

    // Ensure JWKS exists on startup
    bits, _ := strconv.Atoi(constants.JWKSKeyBits)
    if _, err := jwks.LoadOrCreate(constants.JWKSPath, bits); err != nil {
        fmt.Println("JWKS init error:", err)
    }

    // Build AASA with env-derived app id
    currentAASA = JSONAASA{
        AuthServ: JSONAuthServe{
            Apps: constants.AASAApps[:],
        },
        Applinks:       map[string]any{},
        Webcredentials: map[string]any{},
    }
}

func WellKnownJWKS() http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        fmt.Println("Request for .well-known/jwks.json")
        bits, _ := strconv.Atoi(constants.JWKSKeyBits)
        data, err := jwks.LoadOrCreate(constants.JWKSPath, bits)
        if err != nil {
            http.Error(w, "failed to load jwks", http.StatusInternalServerError)
            return
        }
        w.Header().Set("Content-Type", "application/json")
        w.WriteHeader(http.StatusOK)
        w.Write(data)
    }
}

func WellKnownAASA() http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        // Log basic request line and headers once for debugging
        requestDump, _ := httputil.DumpRequest(r, false)
        fmt.Println(string(requestDump))

        fmt.Println("Request for .well-known/apple-app-site-association")
        payload, err := json.Marshal(currentAASA)
        if err != nil {
            http.Error(w, "failed to encode response", http.StatusInternalServerError)
            return
        }
        w.Header().Set("Content-Type", "application/json")
        w.WriteHeader(http.StatusOK)
        w.Write(payload)
    }
}
