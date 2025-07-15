package middleware

import (
	"fmt"
	"net/http"

	"github.com/praserx/aegis/pkg/logger"
	"github.com/praserx/aegis/pkg/session"
)

// sessionMiddleware checks the current session or JWT claims.
func SessionMiddleware(sessionManager *session.Manager) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			logger.Info(fmt.Sprintf("executing session middleware: method: %s, url: %s", r.Method, r.URL.Path))
			// TODO: Check session or JWT claims for authorization

			// 1. check if session exists
			// 2. if not, return redirect to oidc provider and return session cookie (create new session)
			//    - save previous URL/request in session
			// 3. after authentication process callback and store tokens
			// 4. redirect to previous URL or default page

			next.ServeHTTP(w, r)
		})
	}
}
