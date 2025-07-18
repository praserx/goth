package middleware

import (
	"fmt"
	"net/http"

	"github.com/praserx/aegis/pkg/logger"
	"github.com/praserx/aegis/pkg/resolver"
)

// AuthorizationMiddleware checks if a user is authorized to access a resource.
// It uses the AuthorizationResolver to make a decision.
func AuthorizationMiddleware(resolver resolver.AuthorizationResolver) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			logger.Info(fmt.Sprintf("executing authorization middleware: method: %s, url: %s", r.Method, r.URL.Path))

			sessionData, ok := SessionFromContext(r.Context())
			if !ok {
				http.Error(w, "could not get session from context", http.StatusInternalServerError)
				return
			}

			// If the resolver is not configured, we deny access by default for safety.
			if resolver == nil {
				logger.Error("authorization resolver is not configured")
				http.Error(w, "Authorization service not configured", http.StatusInternalServerError)
				return
			}

			allowed, err := resolver.CheckAccess(r.Context(), sessionData, r)
			if err != nil {
				logger.Error(fmt.Sprintf("error checking access: %v", err))
				http.Error(w, "Error checking access", http.StatusInternalServerError)
				return
			}

			if !allowed {
				http.Error(w, "Forbidden", http.StatusForbidden)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}
