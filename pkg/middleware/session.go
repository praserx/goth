package middleware

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	"github.com/google/uuid"
	"github.com/praserx/aegis/pkg/logger"
	"github.com/praserx/aegis/pkg/session"
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
func SessionMiddleware(manager *session.Manager, opts session.CookieOptions) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			logger.Info(fmt.Sprintf("executing session middleware: method: %s, url: %s", r.Method, r.URL.Path))

			var sessionData session.Session
			var err error

			cookie, err := r.Cookie(opts.Name)
			if err != nil {
				if errors.Is(err, http.ErrNoCookie) {
					// Handle case where no cookie is found
					sessionData, err = handleNewSession(w, r, manager, opts)
				} else {
					// Handle other errors retrieving the cookie
					logger.Error(fmt.Sprintf("failed to retrieve session cookie: %v", err))
					http.Error(w, "Failed to retrieve session cookie", http.StatusInternalServerError)
					return
				}
			} else {
				// Handle case where cookie is found
				sessionData, err = handleExistingSession(r, manager, cookie)
			}

			if err != nil {
				logger.Error(fmt.Sprintf("session handling failed: %v", err))
				http.Error(w, "Session handling failed", http.StatusInternalServerError)
				return
			}

			ctx := NewContextWithSessionData(r.Context(), sessionData)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// handleNewSession creates a new session when no cookie is found. It generates a
// new session ID, saves it to the store, and sets the corresponding cookie on
// the response.
func handleNewSession(w http.ResponseWriter, r *http.Request, manager *session.Manager, opts session.CookieOptions) (session.Session, error) {
	logger.Info("session cookie not found, creating a new session")

	sessionID, sessionData, err := CreateNewSession(r.Context(), manager)
	if err != nil {
		return session.Session{}, fmt.Errorf("failed to create new session: %w", err)
	}

	http.SetCookie(w, &http.Cookie{
		Name:     opts.Name,
		Value:    sessionID,
		Path:     "/",
		MaxAge:   opts.MaxAge,
		HttpOnly: opts.HttpOnly,
		Secure:   opts.Secure,
		SameSite: getSameSiteAttribute(opts.SameSite),
	})

	return sessionData, nil
}

// handleExistingSession validates a session from an existing cookie. If the
// session is valid, it's returned. If the session ID is not found in the store,
// a new empty session is created with the same ID to renew it.
func handleExistingSession(r *http.Request, manager *session.Manager, cookie *http.Cookie) (session.Session, error) {
	sessionID := cookie.Value
	sessionData, ok, err := manager.Get(r.Context(), sessionID)
	if err != nil {
		return session.Session{}, fmt.Errorf("failed to get session data: %w", err)
	}

	// If the session ID from the cookie is not in our store, it's invalid.
	// We renew the session by creating a new empty one with the same ID.
	if !ok {
		logger.Info(fmt.Sprintf("session with ID %s does not exist, renewing session data", sessionID))
		sessionData = session.Empty()
		if err := manager.SetWithTTL(r.Context(), sessionID, sessionData, session.DefaultSessionTTL); err != nil {
			return session.Session{}, fmt.Errorf("failed to set renewed session data: %w", err)
		}
	}

	return sessionData, nil
}

// CreateNewSession creates a new session and sets the session cookie.
func CreateNewSession(ctx context.Context, mgr *session.Manager) (string, session.Session, error) {
	for i := 0; i < 10; i++ {
		newSessionID := GenerateSessionID()
		if ok, err := mgr.Exists(ctx, newSessionID); err != nil {
			logger.Error(fmt.Sprintf("failed to check session existence: %v", err))
			return "", session.Session{}, fmt.Errorf("failed to check session existence: %w", err)
		} else if !ok {
			sessionData := session.Empty()
			mgr.SetWithTTL(ctx, newSessionID, sessionData, session.DefaultSessionTTL)
			return newSessionID, sessionData, nil
		}

		if i > 6 {
			return "", session.Session{}, fmt.Errorf("failing to generate a unique session ID after multiple attempts")
		}
	}

	return "", session.Session{}, fmt.Errorf("failed to create a new session after multiple attempts")
}

// GenerateSessionID creates a new unique session ID using UUID.
func GenerateSessionID() string {
	return uuid.New().String()
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
