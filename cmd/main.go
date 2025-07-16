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

	"github.com/praserx/aegis/pkg/aegis"
	"github.com/praserx/aegis/pkg/logger"
	oidcprovider "github.com/praserx/aegis/pkg/provider/oidc"
	"github.com/praserx/aegis/pkg/session"
	"github.com/praserx/aegis/pkg/storage"
	"github.com/urfave/cli/v3"
)

func main() {
	cmd := &cli.Command{
		Name:  "aegis",
		Usage: "A lightweight, security-focused authorization proxy",
		Flags: []cli.Flag{
			flagVerbose,
			flagWebListenHTTP,
			flagWebListenHTTPS,
			flagWebTLSCert,
			flagWebTLSKey,
			flagWebCookieName,
			flagWebCookieMaxAge,
			flagWebCookieHTTPOnly,
			flagWebCookieSecure,
			flagWebCookieSameSite,
			flagOIDCTLSSkipVerify,
			flagOIDCProviderURL,
			flagOIDCClientID,
			flagOIDCClientSecret,
			flagProxyUpstreamURL,
			flagStorageRedisEnabled,
			flagStorageRedisURL,
			flagAuthPolicyMode,
		},
		UseShortOptionHandling: true,
		Action: func(ctx context.Context, cmd *cli.Command) error {
			logger.Info("Starting Aegis proxy...")

			upstreamURL, err := url.Parse(cmd.String("proxy.upstream-url"))
			if err != nil {
				return fmt.Errorf("invalid upstream URL: %w", err)
			}

			// Initialize storage based on configuration
			var store storage.Storage
			if cmd.Bool("storage.redis.enabled") {
				store, err = storage.NewRedisStore(ctx, cmd.String("storage.redis.url"))
				if err != nil {
					return fmt.Errorf("failed to create redis store: %w", err)
				}
				logger.Info("Using Redis for session storage")
			} else {
				store, err = storage.NewInMemoryStore()
				if err != nil {
					return fmt.Errorf("failed to create in-memory store: %w", err)
				}
				logger.Info("Using in-memory for session storage")
			}
			defer store.Close()

			sessionManager, err := session.NewManager(session.WithStorage(store))
			if err != nil {
				return fmt.Errorf("failed to create session manager: %w", err)
			}

			// Initialize OIDC provider
			oidcProvider, err := oidcprovider.NewProvider(ctx,
				oidcprovider.WithIssuer(cmd.String("oidc.provider-url")),
				oidcprovider.WithClientID(cmd.String("oidc.client-id")),
				oidcprovider.WithClientSecret(cmd.String("oidc.client-secret")),
				oidcprovider.WithRedirectURL(buildRedirectURL(cmd)), // Helper function to build redirect URL
			)
			if err != nil {
				return fmt.Errorf("failed to create oidc provider: %w", err)
			}

			cookieOptions := session.CookieOptions{
				Name:     cmd.String("web.cookie-name"),
				MaxAge:   cmd.Int("web.cookie-max-age"),      // Max age in seconds
				Secure:   cmd.Bool("web.cookie-secure"),      // Secure if specified
				HttpOnly: cmd.Bool("web.cookie-http-only"),   // HttpOnly if specified
				SameSite: cmd.String("web.cookie-same-site"), // SameSite attribute
			}

			proxy, err := aegis.New(
				aegis.WithUpstreamURL(upstreamURL),
				aegis.WithProvider(oidcProvider),
				aegis.WithSessionManager(sessionManager),
				aegis.WithCookieOptions(cookieOptions),
			)
			if err != nil {
				return fmt.Errorf("failed to create aegis proxy: %w", err)
			}

			listenHTTP := cmd.String("web.listen-http")
			listenHTTPS := cmd.String("web.listen-https")
			tlsCert := cmd.String("web.tls-cert")
			tlsKey := cmd.String("web.tls-key")

			errChan := make(chan error, 2)
			httpServer := &http.Server{
				Addr:    listenHTTP,
				Handler: proxy,
			}

			httpsServer := &http.Server{
				Addr:    listenHTTPS,
				Handler: proxy,
			}

			go func() {
				logger.Infof("HTTP server listening on %s", listenHTTP)
				if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
					errChan <- fmt.Errorf("http server error: %w", err)
				}
			}()

			if listenHTTPS != "" && tlsCert != "" && tlsKey != "" {
				go func() {
					logger.Infof("HTTPS server listening on %s", listenHTTPS)
					if err := httpsServer.ListenAndServeTLS(tlsCert, tlsKey); err != nil && err != http.ErrServerClosed {
						errChan <- fmt.Errorf("https server error: %w", err)
					}
				}()
			}

			stop := make(chan os.Signal, 1)
			signal.Notify(stop, os.Interrupt, syscall.SIGTERM)

			select {
			case err := <-errChan:
				return err
			case <-stop:
				logger.Info("Shutting down gracefully...")
				shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()

				if err := httpServer.Shutdown(shutdownCtx); err != nil {
					logger.Errorf("HTTP server shutdown error: %v", err)
				}

				if listenHTTPS != "" && tlsCert != "" && tlsKey != "" {
					if err := httpsServer.Shutdown(shutdownCtx); err != nil {
						logger.Errorf("HTTPS server shutdown error: %v", err)
					}
				}
			}

			return nil
		},
	}

	if err := cmd.Run(context.Background(), os.Args); err != nil {
		log.Fatal(err)
	}
}

// buildRedirectURL constructs the redirect URL from the command flags.
// This helper function centralizes the logic for determining the correct
// redirect URL based on the server's configuration (HTTP/HTTPS).
func buildRedirectURL(cmd *cli.Command) string {
	// This is a placeholder. Implement the logic to build the redirect URL
	// based on your application's routing and configuration.
	// For example, it might be something like:
	// scheme := "http"
	// if cmd.String("web.tls-cert") != "" {
	// 	scheme = "https"
	// }
	// host := cmd.String("web.listen-http") // or some other host configuration
	// return fmt.Sprintf("%s://%s/callback", scheme, host)
	return "http://localhost:8080/callback" // Example
}
