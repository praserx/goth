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

// 1. check if session exists
// 2. if not, return redirect to oidc provider and return session cookie (create new session)
//    - save previous URL/request in session
// 3. after authentication process callback and store tokens
// 4. redirect to previous URL or default page
