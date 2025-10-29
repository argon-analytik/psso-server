package handlers

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/argon-analytik/psso-server/pkg/crypto"
	"github.com/argon-analytik/psso-server/pkg/store"
)

type keyRequest struct {
	DeviceID         string `json:"device_id"`
	UDID             string `json:"udid,omitempty"`
	Serial           string `json:"serial_number,omitempty"`
	SigningKeyPEM    string `json:"signing_key_pem"`
	SigningKeyID     string `json:"signing_key_id"`
	EncryptionKeyPEM string `json:"encryption_key_pem"`
	EncryptionKeyID  string `json:"encryption_key_id"`
	KeyVersion       string `json:"key_version,omitempty"`
}

type keyResponse struct {
	Status       string    `json:"status"`
	DeviceID     string    `json:"device_id"`
	RegisteredAt time.Time `json:"registered_at"`
	LastSeen     time.Time `json:"last_seen"`
}

func Key(state store.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if ct := r.Header.Get("Content-Type"); ct != "" && !strings.HasPrefix(ct, "application/json") {
			http.Error(w, "expected application/json", http.StatusUnsupportedMediaType)
			return
		}

		defer r.Body.Close()
		reader := http.MaxBytesReader(w, r.Body, 1<<20)
		dec := json.NewDecoder(reader)
		dec.DisallowUnknownFields()

		var req keyRequest
		if err := dec.Decode(&req); err != nil {
			if errors.Is(err, io.EOF) {
				http.Error(w, "request body must not be empty", http.StatusBadRequest)
				return
			}
			http.Error(w, fmt.Sprintf("invalid request: %v", err), http.StatusBadRequest)
			return
		}

		if req.DeviceID == "" {
			http.Error(w, "device_id is required", http.StatusBadRequest)
			return
		}
		if strings.TrimSpace(req.SigningKeyPEM) == "" {
			http.Error(w, "signing_key_pem is required", http.StatusBadRequest)
			return
		}
		if strings.TrimSpace(req.EncryptionKeyPEM) == "" {
			http.Error(w, "encryption_key_pem is required", http.StatusBadRequest)
			return
		}

		if _, err := crypto.ParsePublicKeyPEM(req.SigningKeyPEM); err != nil {
			http.Error(w, "invalid signing key", http.StatusBadRequest)
			return
		}
		if _, err := crypto.ParsePublicKeyPEM(req.EncryptionKeyPEM); err != nil {
			http.Error(w, "invalid encryption key", http.StatusBadRequest)
			return
		}

		keyVersion := req.KeyVersion
		if keyVersion == "" {
			keyVersion = req.SigningKeyID
		}

		device, err := state.UpsertDevice(r.Context(), store.Device{
			DeviceID:         req.DeviceID,
			UDID:             req.UDID,
			SerialNumber:     req.Serial,
			SigningKeyPEM:    strings.TrimSpace(req.SigningKeyPEM),
			SigningKeyID:     strings.TrimSpace(req.SigningKeyID),
			EncryptionKeyPEM: strings.TrimSpace(req.EncryptionKeyPEM),
			EncryptionKeyID:  strings.TrimSpace(req.EncryptionKeyID),
			KeyVersion:       strings.TrimSpace(keyVersion),
		})
		if err != nil {
			http.Error(w, "failed to persist device", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(keyResponse{Status: "ok", DeviceID: device.DeviceID, RegisteredAt: device.RegisteredAt, LastSeen: device.LastSeen})
	}
}
