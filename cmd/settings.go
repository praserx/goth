package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"time"

	"github.com/urfave/cli/v3"

	"github.com/praserx/goth/pkg/logger"
	"github.com/praserx/goth/pkg/provider"
	"github.com/praserx/goth/pkg/session"
	"github.com/praserx/goth/pkg/storage"
)

// NewSessionStorage initializes a session manager based on command line flags.
func NewSessionStorage(cmd *cli.Command) (storage.Storage, error) {
	var err error

	// Initialize storage based on configuration
	var store storage.Storage
	if cmd.Bool("storage.redis.enabled") {
		store, err = storage.NewRedisStore(cmd.String("storage.redis.url"))
		if err != nil {
			return nil, fmt.Errorf("failed to create redis store: %w", err)
		}
		logger.Info("Using Redis for session storage")
	} else {
		store, err = storage.NewInMemoryStore()
		if err != nil {
			return nil, fmt.Errorf("failed to create in-memory store: %w", err)
		}
		logger.Info("Using in-memory for session storage")
	}

	return store, nil
}

// NewCookieOptions creates session cookie options based on command line flags.
func NewCookieOptions(cmd *cli.Command) session.CookieOptions {
	return session.CookieOptions{
		SessionCookieName:  cmd.String("web.session-cookie-name"),
		TrackingCookieName: cmd.String("web.tracking-cookie-name"),
		AuthCookieName:     cmd.String("web.auth-cookie-name"),
		MaxAge:             cmd.Int("web.cookie-max-age"),
		Secure:             cmd.Bool("web.cookie-secure"),
		SameSite:           cmd.String("web.cookie-same-site"),
	}
}

// NewOIDCProvider initializes an OIDC provider based on command line flags.
func NewOIDCProvider(ctx context.Context, cmd *cli.Command) (provider.Provider, error) {
	// Get ODIC provider config from discovery URL
	if cmd.String("oidc.discovery-url") == "" {
		return nil, fmt.Errorf("OIDC discovery URL is required")
	}
	if cmd.String("oidc.client-id") == "" {
		return nil, fmt.Errorf("OIDC client ID is required")
	}
	if cmd.String("oidc.client-secret") == "" {
		return nil, fmt.Errorf("OIDC client secret is required")
	}

	// Get params from discovery URL via request
	discoveryURL := cmd.String("oidc.discovery-url")
	httpClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: cmd.Bool("oidc.tls-skip-verify"),
				MinVersion:         tls.VersionTLS13,
			},
		},
	}
	httpClient.Timeout = 10 * time.Second // Set a reasonable timeout

	config, err := provider.FetchOAuthMetadata(discoveryURL, httpClient)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch OIDC configuration: %w", err)
	}

	opts := []func(*provider.Options){
		provider.WithIssuer(config.Issuer),
		provider.WithClientID(cmd.String("oidc.client-id")),
		provider.WithClientSecret(cmd.String("oidc.client-secret")),
	}

	if cmd.String("oidc.callback-path") != "" {
		opts = append(opts, provider.WithRedirectURL(cmd.String("oidc.callback-path")))
	} else {
		opts = append(opts, provider.WithRedirectURL(buildRedirectURL(cmd))) // Helper function to build redirect URL
	}

	// Initialize OIDC provider
	oidcProvider, err := provider.NewKeycloakProvider(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize OIDC provider: %w", err)
	}

	return oidcProvider, nil
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
