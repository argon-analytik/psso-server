package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/argon-analytik/psso-server/pkg/authentik"
	"github.com/argon-analytik/psso-server/pkg/constants"
	"github.com/argon-analytik/psso-server/pkg/crypto"
	"github.com/argon-analytik/psso-server/pkg/handlers"
	"github.com/argon-analytik/psso-server/pkg/jwks"
	"github.com/argon-analytik/psso-server/pkg/store"
	jose "github.com/go-jose/go-jose/v3"
)

func newRouter(state store.Store, cryptoSvc *crypto.Service, authClient *authentik.Client) *http.ServeMux {
	mux := http.NewServeMux()

	mux.HandleFunc(constants.EndpointAppleSiteAssoc, handlers.WellKnownAASA(constants.AASAApps()))
	mux.HandleFunc(constants.EndpointJWKS, handlers.WellKnownJWKS(constants.JWKSPath))
	mux.HandleFunc(constants.EndpointHealthz, handlers.Healthz())
	mux.HandleFunc(constants.EndpointNonce, handlers.Nonce(state))
	mux.HandleFunc(constants.EndpointKey, handlers.Key(state))
	mux.HandleFunc(constants.EndpointToken, handlers.Token(handlers.TokenDependencies{
		Store:     state,
		Crypto:    cryptoSvc,
		Authentik: authClient,
		Config: handlers.TokenConfig{
			PasswordGrantEnabled: constants.AKPasswordGrantEnabled,
			Issuer:               constants.AuthentikBaseURL,
			Audience:             []string{constants.BundleID},
		},
	}))

	return mux
}

func run(ctx context.Context) error {
	cryptoSvc, err := crypto.NewService(constants.ServerSigningKeyPath, constants.ServerSigningKeyKID, constants.ServerEncryptionKeyPath)
	if err != nil {
		return fmt.Errorf("init crypto: %w", err)
	}

	if constants.AKPasswordGrantEnabled {
		if constants.AKClientID == "" || constants.AKClientSecret == "" {
			return fmt.Errorf("AK_PASSWORD_GRANT_ENABLED requires AK_CLIENT_ID and AK_CLIENT_SECRET")
		}
	}

	state, err := store.NewFSStore(constants.StateDir, constants.DevicePath, constants.NoncePath)
	if err != nil {
		return fmt.Errorf("init state store: %w", err)
	}

	keys := []jose.JSONWebKey{cryptoSvc.SigningPublicJWK()}
	if enc := cryptoSvc.EncryptionPublicJWK(); enc != nil {
		keys = append(keys, *enc)
	}
	if _, err := jwks.Write(constants.JWKSPath, keys); err != nil {
		return fmt.Errorf("write jwks: %w", err)
	}

	authClient := &authentik.Client{
		Endpoint:     constants.AuthentikTokenEndpoint,
		ClientID:     constants.AKClientID,
		ClientSecret: constants.AKClientSecret,
	}

	srv := &http.Server{
		Addr:         constants.Address,
		Handler:      newRouter(state, cryptoSvc, authClient),
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
	}()

	log.Printf("PSSO server listening on %s", constants.Address)
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

func main() {
	if strings.TrimSpace(constants.ServerSigningKeyPath) == "" {
		log.Fatal("SERVER_SIGNING_KEY_PRIV_PATH is required")
	}
	info, err := os.Stat(constants.ServerSigningKeyPath)
	if err != nil {
		log.Fatalf("SERVER_SIGNING_KEY_PRIV_PATH=%q not readable: %v", constants.ServerSigningKeyPath, err)
	}
	if info.IsDir() {
		log.Fatalf("SERVER_SIGNING_KEY_PRIV_PATH=%q must point to a PEM file", constants.ServerSigningKeyPath)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if err := run(ctx); err != nil {
		log.Fatalf("startup failed: %v", err)
	}
}
