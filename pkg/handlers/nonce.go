package handlers

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"time"

	"github.com/argon-analytik/psso-server/pkg/store"
)

type nonceRequest struct {
	DeviceID string `json:"device_id,omitempty"`
	UDID     string `json:"udid,omitempty"`
	Serial   string `json:"serial_number,omitempty"`
}

type nonceResponse struct {
	Nonce     string    `json:"nonce"`
	ExpiresAt time.Time `json:"expires_at"`
}

const nonceTTL = 120 * time.Second

func Nonce(state store.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		var req nonceRequest
		if r.Body != nil {
			defer r.Body.Close()
			dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16))
			if err := dec.Decode(&req); err != nil && !errors.Is(err, io.EOF) {
				http.Error(w, "invalid JSON payload", http.StatusBadRequest)
				return
			}
		}

		buf := make([]byte, 32)
		if _, err := rand.Read(buf); err != nil {
			http.Error(w, "failed to generate nonce", http.StatusInternalServerError)
			return
		}
		nonce := base64.RawURLEncoding.EncodeToString(buf)
		expires := time.Now().UTC().Add(nonceTTL)

		if err := state.SaveNonce(r.Context(), store.Nonce{Value: nonce, DeviceID: req.DeviceID, ExpiresAt: expires}); err != nil {
			http.Error(w, "failed to persist nonce", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(nonceResponse{Nonce: nonce, ExpiresAt: expires})
	}
}
