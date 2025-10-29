package handlers

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"path/filepath"
	"time"

	"github.com/argon-analytik/psso-server/pkg/constants"
	"github.com/argon-analytik/psso-server/pkg/file"
)

type NonceResponse struct {
	Nonce string
}

func Nonce() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		fmt.Println("Request for /nonce")

		nonceBytes := make([]byte, 32)
		if _, err := rand.Read(nonceBytes); err != nil {
			http.Error(w, "bad nonce request", http.StatusBadRequest)
			return
		}

		encoded := base64.StdEncoding.EncodeToString(nonceBytes)
		response := NonceResponse{
			Nonce: encoded,
		}
		nonce := file.Nonce{
			Nonce:    encoded,
			Category: "nonce",
			TTL:      int(time.Now().Unix()) + (5 * 60), // make nonce good for 5 mins
		}

		nonceString := hex.EncodeToString(nonceBytes) + ".json"
		if err := file.Save(nonce, filepath.Join(constants.NoncePath, nonceString)); err != nil {
			fmt.Println(err)
			http.Error(w, "failed to persist nonce", http.StatusInternalServerError)
			return
		}

		payload, err := json.Marshal(response)
		if err != nil {
			http.Error(w, "failed to encode response", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write(payload)
	}
}
