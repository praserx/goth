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

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/praserx/aegis/pkg/aegis"
	"github.com/praserx/aegis/pkg/logger"
	"github.com/urfave/cli/v3"
	"golang.org/x/oauth2"
)

func main() {
	cmd := &cli.Command{
		Name:  "aegis",
		Usage: "A lightweight, security-focused authorization proxy",
		Flags: []cli.Flag{
			flagVerbose,
			flagListenHTTP,
			flagListenHTTPS,
			flagTLSCert,
			flagTLSKey,
			flagTLSSkipVerify,
			flagDiscoveryURL,
			flagClientID,
			flagClientSecret,
			flagUpstreamURL,
			flagPolicyMode,
		},
		UseShortOptionHandling: true,
		Action: func(ctx context.Context, cmd *cli.Command) error {
			logger.Info("Starting Aegis proxy...")

			upstreamURL, err := url.Parse(cmd.String("upstream-url"))
			if err != nil {
				return fmt.Errorf("invalid upstream URL: %w", err)
			}

			// provider, err := oidc.NewProvider(ctx, cmd.String("discovery-url"))
			// if err != nil {
			// 	return fmt.Errorf("failed to create OIDC provider: %w", err)
			// }

			oauth2Config := &oauth2.Config{
				ClientID:     cmd.String("client-id"),
				ClientSecret: cmd.String("client-secret"),
				// Endpoint:     provider.Endpoint(),
				Scopes: []string{oidc.ScopeOpenID, "profile", "email"},
			}

			proxy := aegis.New(
				aegis.WithVerbosity(verbosityLevel),
				aegis.WithUpstreamURL(upstreamURL),
				aegis.WithOauth2Config(oauth2Config),
			)

			listenHTTP := cmd.String("listen-http")
			listenHTTPS := cmd.String("listen-https")
			tlsCert := cmd.String("tls-cert")
			tlsKey := cmd.String("tls-key")

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
