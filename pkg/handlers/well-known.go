package handlers

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/argon-analytik/psso-server/pkg/jwks"
)

type aasaResponse struct {
	AuthSrv struct {
		Apps []string `json:"apps"`
	} `json:"authsrv"`
}

func WellKnownAASA(apps []string) http.HandlerFunc {
	payload := aasaResponse{}
	payload.AuthSrv.Apps = append(payload.AuthSrv.Apps, apps...)

	return func(w http.ResponseWriter, r *http.Request) {
		data, err := json.Marshal(payload)
		if err != nil {
			http.Error(w, "failed to build response", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "max-age=300")
		w.Header().Set("Expires", time.Now().Add(5*time.Minute).UTC().Format(http.TimeFormat))
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(data)
	}
}

func WellKnownJWKS(path string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		data, err := jwks.Load(path)
		if err != nil {
			http.Error(w, "failed to load jwks", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "max-age=300")
		w.Header().Set("Expires", time.Now().Add(5*time.Minute).UTC().Format(http.TimeFormat))
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(data)
	}
}
