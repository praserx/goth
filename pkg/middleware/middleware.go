package middleware

import "net/http"

// Middleware type for chaining.
type Middleware func(http.Handler) http.Handler

// Example: Add more middlewares here as needed.
// func customMiddleware() Middleware {
// 	return func(next http.Handler) http.Handler {
// 		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
// 			// Custom logic
// 			next.ServeHTTP(w, r)
// 		})
// 	}
// }
