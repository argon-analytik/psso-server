package handlers

import (
	"fmt"
	"net/http"
)

func Healthz() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		fmt.Println("Request for /healthz")
		w.Write([]byte("ok"))
	}
}
