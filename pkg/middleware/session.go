package middleware

import (
	"fmt"
	"net/http"

	"github.com/praserx/aegis/pkg/logger"
)

// sessionMiddleware checks the current session or JWT claims.
func SessionMiddleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			logger.Info(fmt.Sprintf("executing session middleware: method: %s, url: %s", r.Method, r.URL.Path))
			// TODO: Check session or JWT claims for authorization
			next.ServeHTTP(w, r)
		})
	}
}
