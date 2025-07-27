package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/urfave/cli/v3"

	"github.com/praserx/goth/pkg/logger"
	"github.com/praserx/goth/pkg/proxy"
)

// main is the entry point for the goth proxy application.
// It sets up the CLI command and runs the proxy server.
func main() {
	// Define the CLI command and its flags using GetAllFlags().
	cmd := &cli.Command{
		Name:                   "goth",
		Usage:                  "A lightweight, security-focused authorization proxy",
		Flags:                  GetAllFlags(),
		UseShortOptionHandling: true,
		Action:                 runGothProxy,
	}

	// Run the CLI command and handle any startup errors.
	if err := cmd.Run(context.Background(), os.Args); err != nil {
		log.Fatal(err)
	}
}

// runGothProxy is the main action for the CLI command.
// It initializes all core components and starts the HTTP/HTTPS proxy servers.
func runGothProxy(ctx context.Context, cmd *cli.Command) error {
	logger.Info("Starting Goth proxy...")

	// Parse the upstream URL for the proxy target.
	upstreamURL, err := url.Parse(cmd.String("proxy.upstream-url"))
	if err != nil {
		return fmt.Errorf("invalid upstream URL: %w", err)
	}

	// Initialize the session manager (in-memory or Redis).
	sessionManager, err := NewSessionStorage(cmd)
	if err != nil {
		return fmt.Errorf("failed to create session manager: %w", err)
	}

	// Initialize the OIDC provider for authentication.
	oidcProvider, err := NewOIDCProvider(ctx, cmd)
	if err != nil {
		return fmt.Errorf("failed to create oidc provider: %w", err)
	}

	// Build cookie options from CLI flags.
	cookieOptions := NewCookieOptions(cmd)

	// Create the proxy handler with all dependencies.
	proxyHandler, err := proxy.New(
		proxy.WithUpstreamURL(upstreamURL),
		proxy.WithProvider(oidcProvider),
		proxy.WithSessionManager(sessionManager),
		proxy.WithCookieOptions(cookieOptions),
	)
	if err != nil {
		return fmt.Errorf("failed to create goth proxy: %w", err)
	}

	// Read server listen addresses and TLS config from flags.
	listenHTTP := cmd.String("web.listen-http")
	listenHTTPS := cmd.String("web.listen-https")
	tlsCert := cmd.String("web.tls-cert")
	tlsKey := cmd.String("web.tls-key")

	// Create HTTP and HTTPS server instances.
	httpServer, httpsServer := createServers(listenHTTP, listenHTTPS, proxyHandler)
	errChan := make(chan error, 2)

	// Start HTTP server in a goroutine.
	go startHTTPServer(httpServer, listenHTTP, errChan)
	// Start HTTPS server if configured.
	if listenHTTPS != "" && tlsCert != "" && tlsKey != "" {
		go startHTTPSServer(httpsServer, listenHTTPS, tlsCert, tlsKey, errChan)
	}

	// Wait for shutdown signal or server error.
	return handleShutdown(httpServer, httpsServer, listenHTTPS, tlsCert, tlsKey, errChan)
}

// createServers returns HTTP and HTTPS server instances with the given handler and addresses.
func createServers(listenHTTP, listenHTTPS string, handler http.Handler) (*http.Server, *http.Server) {
	httpServer := &http.Server{
		Addr:    listenHTTP,
		Handler: handler,
	}
	httpsServer := &http.Server{
		Addr:    listenHTTPS,
		Handler: handler,
	}
	return httpServer, httpsServer
}

// startHTTPServer starts the HTTP server and sends any errors to errChan.
func startHTTPServer(server *http.Server, addr string, errChan chan<- error) {
	logger.Infof("HTTP server listening on %s", addr)
	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		errChan <- fmt.Errorf("http server error: %w", err)
	}
}

// startHTTPSServer starts the HTTPS server with TLS and sends any errors to errChan.
func startHTTPSServer(server *http.Server, addr, cert, key string, errChan chan<- error) {
	logger.Infof("HTTPS server listening on %s", addr)
	if err := server.ListenAndServeTLS(cert, key); err != nil && err != http.ErrServerClosed {
		errChan <- fmt.Errorf("https server error: %w", err)
	}
}

// handleShutdown waits for a shutdown signal or server error, then gracefully shuts down servers.
func handleShutdown(httpServer, httpsServer *http.Server, listenHTTPS, tlsCert, tlsKey string, errChan <-chan error) error {
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)

	select {
	case err := <-errChan:
		return err
	case <-stop:
		logger.Info("Shutting down gracefully...")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		// Attempt graceful shutdown of HTTP server.
		if err := httpServer.Shutdown(shutdownCtx); err != nil {
			logger.Errorf("HTTP server shutdown error: %v", err)
		}

		// Attempt graceful shutdown of HTTPS server if configured.
		if listenHTTPS != "" && tlsCert != "" && tlsKey != "" {
			if err := httpsServer.Shutdown(shutdownCtx); err != nil {
				logger.Errorf("HTTPS server shutdown error: %v", err)
			}
		}
	}

	return nil
}
