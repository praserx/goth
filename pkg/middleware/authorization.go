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
			userSessionID, handled := getSessionCookieOrHandleError(w, r, opts.SessionCookieName)
			if handled {
				return
			}

			if userSessionID == nil || userSessionID.Value == "" {
				if handleAnonymousRequest(w, r, p, c, opts) {
					return
				}
			} else {
				if handleAuthenticatedRequest(w, r, c, userSessionID.Value) {
					return
				}
			}

			next.ServeHTTP(w, r)
		})
	}
}

// getSessionCookieOrHandleError tries to retrieve the session cookie. If an error occurs (other than no cookie),
// it writes an error response and returns (nil, true). Otherwise, returns the cookie and false.
func getSessionCookieOrHandleError(w http.ResponseWriter, r *http.Request, cookieName string) (*http.Cookie, bool) {
	cookie, err := r.Cookie(cookieName)
	if err != nil && !errors.Is(err, http.ErrNoCookie) {
		logger.Error(fmt.Sprintf("error getting session cookie: %v", err))
		writer.ErrorResponse(w, r, http.StatusInternalServerError, errIntCannotGetUserSession)
		return nil, true
	}
	return cookie, false
}

// handleAnonymousRequest processes requests without a valid session cookie.
// Returns true if the request was handled (response written), false otherwise.
func handleAnonymousRequest(w http.ResponseWriter, r *http.Request, p provider.Provider, c storage.Storage, opts session.CookieOptions) bool {
	logger.Info("anonymous request detected")

	allowed, err := p.AuthorizeAnonymousRequest(r.Context(), r)
	if err != nil {
		logger.Error(fmt.Sprintf("error checking access: %v", err))
		writer.ErrorResponse(w, r, http.StatusInternalServerError, errIntAccessVerification)
		return true
	}

	if !allowed {
		authSessionID, err := session.NewAuthSessionID(r.Context(), c)
		if err != nil {
			logger.Errorf("failed to create auth session ID: %v", err)
			writer.ErrorResponse(w, r, http.StatusInternalServerError, fmt.Sprintf("Failed to create auth session ID: %v", err))
			return true
		}

		authSession := session.AuthSession{
			State:   uuid.New().String(),
			OrigURL: r.URL,
		}

		cookie := session.NewAuthCookie(authSessionID, opts)
		err = session.SetAuthSession(r.Context(), c, authSessionID, authSession)
		if err != nil {
			logger.Errorf("failed to set auth session: %v", err)
			writer.ErrorResponse(w, r, http.StatusInternalServerError, fmt.Sprintf("Failed to set auth session: %v", err))
			return true
		}

		redirectURL := p.GetAuthURL(authSession.State)
		http.SetCookie(w, cookie)
		http.Redirect(w, r, redirectURL, http.StatusFound)
		return true
	}
	return false
}

// handleAuthenticatedRequest processes requests with a valid session cookie.
// Returns true if the request was handled (response written), false otherwise.
func handleAuthenticatedRequest(w http.ResponseWriter, r *http.Request, c storage.Storage, sessionID string) bool {
	logger.Info("authenticated request detected")

	userSession, err := session.GetUserSession(r.Context(), c, sessionID)
	if err != nil {
		logger.Error(fmt.Sprintf("error getting user session: %v", err))
		writer.ErrorResponse(w, r, http.StatusInternalServerError, errIntCannotGetUserSession)
		return true
	}

	if userSession == nil {
		logger.Error("user session not found")
		writer.ErrorResponse(w, r, http.StatusUnauthorized, errAccessUnauthorized)
		return true
	}

	// Additional user authorization logic can be added here.
	return false
}
