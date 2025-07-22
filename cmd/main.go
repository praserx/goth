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
			flagOIDCDiscoveryURL,
			flagOIDCClientID,
			flagOIDCClientSecret,
			flagOIDCLoginPath,
			flagOIDCLogoutPath,
			flagOIDCCallbackPath,
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

			sessionManager, err := NewSessionStorage(ctx, cmd)
			if err != nil {
				return fmt.Errorf("failed to create session manager: %w", err)
			}

			oidcProvider, err := NewOIDCProvider(ctx, cmd)
			if err != nil {
				return fmt.Errorf("failed to create oidc provider: %w", err)
			}

			cookieOptions := NewCookieOptions(cmd)

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
