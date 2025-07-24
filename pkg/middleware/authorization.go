package middleware

import (
	"errors"
	"fmt"
	"net/http"

	"github.com/google/uuid"

	"github.com/praserx/goth/pkg/logger"
	"github.com/praserx/goth/pkg/provider"
	"github.com/praserx/goth/pkg/session"
	"github.com/praserx/goth/pkg/storage"
	"github.com/praserx/goth/pkg/writer"
)

const (
	errIntProviderNotConfigured = "authorization resolver is not configured"
	errIntCannotGetUserCookie   = "cannot retrieve user cookie"
	errIntCannotGetUserSession  = "cannot retrieve user session"
	errIntAccessVerification    = "cannot verify access for the request"
	errAccessUnauthorized       = "user session not found"
	errAccessDenied             = "access denied"
)

// AuthorizationMiddleware checks if a user is authorized to access a resource.
// It uses the AuthorizationResolver to make a decision.
func AuthorizationMiddleware(p provider.Provider, c storage.Storage, opts session.CookieOptions) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			logger.Info(fmt.Sprintf("executing authorization middleware: method: %s, url: %s", r.Method, r.URL.Path))

			// If the authorization server provider is not configured,
			// we deny access by default for safety.
			if p == nil {
				logger.Error("authorization resolver is not configured")
				writer.ErrorResponse(w, r, http.StatusInternalServerError, errIntProviderNotConfigured)
				return
			}

			// Determine if the request is anonymous or not.
			userSessionID, err := r.Cookie(opts.SessionCookieName)
			if err != nil && !errors.Is(err, http.ErrNoCookie) {
				logger.Error(fmt.Sprintf("error getting session cookie: %v", err))
				writer.ErrorResponse(w, r, http.StatusInternalServerError, errIntCannotGetUserSession)
				return
			}

			if userSessionID == nil || userSessionID.Value == "" {
				logger.Info("anonymous request detected")

				allowed, err := p.AuthorizeAnonymousRequest(r.Context(), r)
				if err != nil {
					logger.Error(fmt.Sprintf("error checking access: %v", err))
					writer.ErrorResponse(w, r, http.StatusInternalServerError, errIntAccessVerification)
					return
				}

				if !allowed {
					authSessionID, err := session.NewAuthSessionID(r.Context(), c)
					if err != nil {
						logger.Errorf("failed to create auth session ID: %v", err)
						writer.ErrorResponse(w, r, http.StatusInternalServerError, fmt.Sprintf("Failed to create auth session ID: %v", err))
						return
					}

					authSession := session.AuthSession{
						State:   uuid.New().String(),
						OrigURL: r.URL,
					}

					cookie := session.NewAuthCookie(authSessionID, opts)
					session.SetAuthSession(r.Context(), c, authSessionID, authSession)

					redirectURL := p.GetAuthURL(authSession.State)
					http.SetCookie(w, cookie)
					http.Redirect(w, r, redirectURL, http.StatusFound)

					// writer.ErrorResponse(w, r, http.StatusForbidden, errAccessDenied)
					return
				}
			} else {
				logger.Info("authenticated request detected")

				// Load the user session from storage.
				userSession, err := session.GetUserSession(r.Context(), c, userSessionID.Value)
				if err != nil {
					logger.Error(fmt.Sprintf("error getting user session: %v", err))
					writer.ErrorResponse(w, r, http.StatusInternalServerError, errIntCannotGetUserSession)
					return
				}

				if userSession == nil {
					logger.Error("user session not found")
					writer.ErrorResponse(w, r, http.StatusUnauthorized, errAccessUnauthorized)
					return
				}

				// Check if the user is authorized to access the resource.
			}

			next.ServeHTTP(w, r)
		})
	}
}
