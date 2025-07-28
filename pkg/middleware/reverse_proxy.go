package middleware

import (
	"fmt"
	"net/http"
	"net/http/httputil"
	"net/url"

	"github.com/praserx/goth/pkg/logger"
)

// ReverseProxyMiddleware returns a middleware that forwards requests to the given target URL.
// This middleware terminates the chain and does not call the next handler.
func ReverseProxyMiddleware(target *url.URL) Middleware {
	proxy := httputil.NewSingleHostReverseProxy(target)

	// Custom error handler for better logging
	proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		logger.Errorf("proxy error: %v", err)
		http.Error(w, "Proxy error", http.StatusBadGateway)
	}

	// Modify the Director to set X-Forwarded-* headers
	originalDirector := proxy.Director
	proxy.Director = func(req *http.Request) {
		originalDirector(req)
		// Set X-Forwarded-For
		clientIP := req.RemoteAddr
		if prior, ok := req.Header["X-Forwarded-For"]; ok {
			clientIP = prior[0] + ", " + clientIP
		}
		req.Header.Set("X-Forwarded-For", clientIP)
		// Set X-Forwarded-Host
		req.Header.Set("X-Forwarded-Host", req.Host)
		// Set X-Forwarded-Proto
		if req.TLS != nil {
			req.Header.Set("X-Forwarded-Proto", "https")
		} else {
			req.Header.Set("X-Forwarded-Proto", "http")
		}
		// Optionally, set Host header to target host
		req.Host = target.Host
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			logger.Info(fmt.Sprintf("executing proxy middleware: method: %s, url: %s", r.Method, r.URL.Path))
			proxy.ServeHTTP(w, r)
		})
	}
}
