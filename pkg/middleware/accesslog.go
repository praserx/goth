package middleware

import (
	"bufio"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/praserx/goth/pkg/logger"
	"github.com/praserx/goth/pkg/session"
	"github.com/praserx/goth/pkg/storage"
)

// responseWriter is a wrapper for http.ResponseWriter to capture the status code
// and support optional interfaces like http.Hijacker, http.Flusher, and http.Pusher.
// This ensures that the middleware is transparent and doesn't interfere with
// advanced HTTP features.
type responseWriter struct {
	http.ResponseWriter
	statusCode int
}

// newResponseWriter creates a new responseWriter that wraps the original
// http.ResponseWriter.
func newResponseWriter(w http.ResponseWriter) *responseWriter {
	return &responseWriter{w, http.StatusOK} // Default to 200
}

// Header returns the header map of the original http.ResponseWriter.
// This is crucial for ensuring that any middleware that modifies the headers
// is modifying the *real* header map, not a copy.
func (rw *responseWriter) Header() http.Header {
	return rw.ResponseWriter.Header()
}

// Write captures the response body and allows the status code to be set.
func (rw *responseWriter) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}

// Hijack implements the http.Hijacker interface, allowing the underlying connection to be taken over.
// This is necessary for features like WebSockets.
func (rw *responseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	if hijacker, ok := rw.ResponseWriter.(http.Hijacker); ok {
		return hijacker.Hijack()
	}
	return nil, nil, fmt.Errorf("http.Hijacker is not supported")
}

// Flush implements the http.Flusher interface, allowing buffered data to be sent to the client.
// This is useful for streaming responses.
func (rw *responseWriter) Flush() {
	if flusher, ok := rw.ResponseWriter.(http.Flusher); ok {
		flusher.Flush()
	}
}

// Push implements the http.Pusher interface, allowing server-sent pushes for HTTP/2.
// This improves performance by sending resources proactively.
func (rw *responseWriter) Push(target string, opts *http.PushOptions) error {
	if pusher, ok := rw.ResponseWriter.(http.Pusher); ok {
		return pusher.Push(target, opts)
	}
	return fmt.Errorf("http.Pusher is not supported")
}

// AccessLogMiddleware logs all access requests in ECS/JSON format.
// It captures the response status code and latency.
func AccessLogMiddleware(c storage.Storage, opts session.CookieOptions) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()

			// Wrap the original ResponseWriter to capture the status code.
			rw := newResponseWriter(w)

			// Call the next handler in the chain.
			next.ServeHTTP(rw, r)

			// After the handler has finished, log the request details.
			logger.GetLogger().LogAccess(
				r,
				rw.statusCode,
				time.Since(start),
			)
		})
	}
}
