package middleware

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	"github.com/praserx/aegis/pkg/logger"
	"github.com/praserx/aegis/pkg/session"
	"github.com/praserx/aegis/pkg/storage"
	"github.com/praserx/aegis/pkg/writer"
)

// SessionContextKey is the key used to store session data in the request context.
type sessionContextKey string

// sessionContextKey creates a new context key for session data.
const SessionContextKey = sessionContextKey("session")

// NewContextWithSessionData returns a new context with the provided session data.
func NewContextWithSessionData(ctx context.Context, data session.Session) context.Context {
	return context.WithValue(ctx, SessionContextKey, data)
}

// SessionFromContext retrieves the session data from the context, if it exists.
func SessionFromContext(ctx context.Context) (session.Session, bool) {
	sessionData, ok := ctx.Value(SessionContextKey).(session.Session)
	return sessionData, ok
}

// SessionMiddleware is a middleware that manages user sessions. It checks for a
// session cookie on incoming requests. If a valid session exists, it's attached
// to the request context. If no session exists, a new one is created.
func SessionMiddleware(sessionStorage storage.Storage, opts session.CookieOptions) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			logger.Info(fmt.Sprintf("executing session middleware: method: %s, url: %s", r.Method, r.URL.Path))

			var err error
			sessionObj, err := session.NewSession(r.Context(), sessionStorage)
			if err != nil {
				logger.Error(fmt.Sprintf("failed to create session: %v", err))
				writer.WriteErrorResponse(w, r, http.StatusInternalServerError, "Failed to create session")
				return
			}
			defer sessionObj.Save(r.Context())

			cookie, err := r.Cookie(opts.Name)
			if err != nil && !errors.Is(err, http.ErrNoCookie) {
				logger.Error(fmt.Sprintf("failed to retrieve session cookie: %v", err))
				writer.WriteErrorResponse(w, r, http.StatusInternalServerError, "Failed to retrieve session cookie")
				return
			} else if err != nil && errors.Is(err, http.ErrNoCookie) {
				http.SetCookie(w, NewCookie(sessionObj.GetID(), opts))
			} else {
				err = sessionObj.Load(r.Context(), cookie.Value)
				if err != nil {
					logger.Error(fmt.Sprintf("failed to load session: %v", err))
					writer.WriteErrorResponse(w, r, http.StatusInternalServerError, "Failed to load session")
					return
				}
			}

			ctx := NewContextWithSessionData(r.Context(), sessionObj)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// NewCookie creates a new HTTP cookie with the specified value and options.
func NewCookie(value string, opts session.CookieOptions) *http.Cookie {
	return &http.Cookie{
		Name:     opts.Name,
		Value:    value,
		Path:     "/",
		MaxAge:   opts.MaxAge,
		HttpOnly: opts.HttpOnly,
		Secure:   opts.Secure,
		SameSite: getSameSiteAttribute(opts.SameSite),
	}
}

// getSameSiteAttribute converts a string representation of SameSite to http.SameSite type.
func getSameSiteAttribute(sameSite string) http.SameSite {
	switch sameSite {
	case "Strict":
		return http.SameSiteStrictMode
	case "Lax":
		return http.SameSiteLaxMode
	case "None":
		return http.SameSiteNoneMode
	default:
		return http.SameSiteDefaultMode
	}
}
