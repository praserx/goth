package middleware

import (
	"fmt"
	"net/http"
	"net/http/httputil"
	"net/url"

	"github.com/praserx/goth/pkg/logger"
)

// Proxy returns a middleware that forwards requests to the given target URL.
// This middleware terminates the chain and does not call the next handler.
func Proxy(target *url.URL) Middleware {
	proxy := httputil.NewSingleHostReverseProxy(target)

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			logger.Info(fmt.Sprintf("executing proxy middleware: method: %s, url: %s", r.Method, r.URL.Path))

			// TODO: Add logic to modify request headers if needed.
			// For example, setting the X-Forwarded-Host header.
			r.Host = target.Host
			proxy.ServeHTTP(w, r)

		})
	}
}
