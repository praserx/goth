package middleware

import (
	"context"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/praserx/goth/pkg/session"
)

const (
	RequestIDHeader = "X-Request-ID"
)

// contextKey is a type for context keys to avoid collisions.
type contextKey string

const (
	RequestStartTimeContextKey contextKey = "request-start-time"
	RequestIDContextKey        contextKey = "request-id"
)

const TrackingCookieMaxAge = 24 * time.Hour // 1 day

// ContextMiddleware adds request-scoped context to the request.
func ContextMiddleware(opts session.CookieOptions) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Log the start time of the request.
			setStartTime(r)

			// Set a unique request ID for tracing.
			setRequestID(r)

			// Set a tracking cookie if needed.
			setTrackingCookie(w, r, opts)

			// Call the next handler in the chain.
			next.ServeHTTP(w, r)
		})
	}
}

// setStartTime sets the start time of the request in the context.
func setStartTime(r *http.Request) *http.Request {
	if r == nil {
		return nil
	}

	// Store the start time in the request context.
	r = r.WithContext(context.WithValue(r.Context(), RequestStartTimeContextKey, time.Now()))

	return r
}

// setRequestID sets a unique request ID in the context.
func setRequestID(r *http.Request) *http.Request {
	if r == nil {
		return nil
	}

	// Generate a unique request ID (could be a UUID or any unique identifier).
	requestID := uuid.New().String()

	// Store the generated request ID in the request context for downstream handlers.
	r = r.WithContext(context.WithValue(r.Context(), RequestIDContextKey, requestID))

	// Optionally, you can also set it as a header for visibility.
	r.Header.Set(RequestIDHeader, requestID)

	return r
}

// setTrackingCookie sets a tracking cookie in the response writer.
func setTrackingCookie(w http.ResponseWriter, r *http.Request, opts session.CookieOptions) {
	const renewBefore = 6 * time.Hour

	cookie, err := r.Cookie(opts.TrackingCookieName)
	needNew := false

	if err != nil || cookie == nil {
		// No cookie present, need to set a new one
		needNew = true
	} else if cookie.Expires.Before(time.Now().Add(renewBefore)) {
		// Cookie is expiring soon, renew it
		needNew = true
	}

	if needNew {
		cookie = session.NewTrackingCookie(uuid.New().String(), int(TrackingCookieMaxAge.Seconds()), opts)
		http.SetCookie(w, cookie)
	}
}
