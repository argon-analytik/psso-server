package main

import (
    "context"
    "log"
    "net/http"
    "os"
    "os/signal"
    "time"

    "github.com/argon-analytik/psso-server/pkg/constants"
    "github.com/argon-analytik/psso-server/pkg/handlers"
)

func NewRouter() *http.ServeMux {
    // Create router and define routes and return that router
    router := http.NewServeMux()

    // well-knowns
    router.HandleFunc(constants.EndpointJWKS, handlers.WellKnownJWKS())
    router.HandleFunc(constants.EndpointAppleSiteAssoc, handlers.WellKnownAASA())

    // handshake endpoints
    router.HandleFunc(constants.EndpointNonce, handlers.Nonce())
    router.HandleFunc(constants.EndpointRegister, handlers.Register())
    router.HandleFunc(constants.EndpointToken, handlers.Token())

    // health
    router.HandleFunc(constants.EndpointHealthz, handlers.Healthz())

    return router
}

func run() {

	if constants.Issuer == "" {
		log.Printf("Issuer is not defined! Set environment variable PSSO_ISSUER that matches your issuer in the PSSO extension")
		os.Exit(-1)
	}
	// Set up a channel to listen to for interrupt signals
	var runChan = make(chan os.Signal, 1)

    // Define server options
    server := &http.Server{
        Addr:         constants.Address,
        Handler:      NewRouter(),
        ReadTimeout:  30 * time.Second,
        WriteTimeout: 30 * time.Second,
        IdleTimeout:  60 * time.Second,
    }

	// Handle ctrl+c/ctrl+x interrupt
	signal.Notify(runChan, os.Interrupt)

	// Alert the user that the server is starting
	log.Printf("Server is starting on %s\n", server.Addr)

	// Run the server on a new goroutine
    go func() {
        if err := server.ListenAndServe(); err != nil {
            if err == http.ErrServerClosed {
                // Normal interrupt operation, ignore
            } else {
                log.Fatalf("Server failed to start due to err: %v", err)
            }
        }
    }()

	// Block on this channel listeninf for those previously defined syscalls assign
	// to variable so we can let the user know why the server is shutting down
	interrupt := <-runChan

	// Set up a context to allow for graceful server shutdowns in the event
	// of an OS interrupt (defers the cancel just in case)
	ctx, cancel := context.WithTimeout(
		context.Background(),
		30,
	)
	defer cancel()

	// If we get one of the pre-prescribed syscalls, gracefully terminate the server
	// while alerting the user
	log.Printf("Server is shutting down due to %+v\n", interrupt)
	if err := server.Shutdown(ctx); err != nil {
		log.Fatalf("Server was unable to gracefully shutdown due to err: %+v", err)
	}
}

func main() {

	// set up handlers

	if env := os.Getenv("PSSO_ADMIN_GROUPS"); env != "" {
		constants.AdminGroups = env
	}
	log.Printf("Admin groups: %v", constants.AdminGroups)

	handlers.CheckWellKnowns()

	run()

}
