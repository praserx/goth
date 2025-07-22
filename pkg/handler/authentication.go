package handler

// import (
// 	"github.com/praserx/aegis/pkg/provider"
// 	"github.com/praserx/aegis/pkg/session"
// )

// // AuthHandler provides handlers for authentication routes.
// type AuthHandler struct {
// 	provider   provider.Provider
// 	sessionMgr *session.Manager
// 	opts       session.CookieOptions
// }

// // NewAuthHandler creates a new AuthHandler.
// func NewAuthHandler(p provider.Provider, sm *session.Manager, opts session.CookieOptions) *AuthHandler {
// 	return &AuthHandler{
// 		provider:   p,
// 		sessionMgr: sm,
// 		opts:       opts,
// 	}
// }

// // NewLoginHandler creates a new HTTP handler for login.
// func NewLoginHandler(redirectURL string) http.Handler {
// 	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
// 		http.Redirect(w, r, redirectURL, http.StatusFound)
// 	})
// }

// func NewLogoutHandler(redirectURL string) http.Handler {

// // // Login initiates the OIDC login flow.
// // func (h *AuthHandler) Login() http.Handler {
// // 	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
// // 		cookie, err := r.Cookie(h.opts.Name)
// // 		if err != nil || cookie.Value == "" {
// // 			http.Error(w, "missing session cookie", http.StatusBadRequest)
// // 			return
// // 		}
// // 		sessionID := cookie.Value

// // 		sessionData, ok, err := h.sessionMgr.Get(r.Context(), sessionID)
// // 		if err != nil {
// // 			http.Error(w, "failed to get session", http.StatusInternalServerError)
// // 			return
// // 		}
// // 		if !ok {
// // 			sessionData = session.Empty()
// // 		}

// // 		state, err := generateRandomState()
// // 		if err != nil {
// // 			http.Error(w, "failed to generate state", http.StatusInternalServerError)
// // 			return
// // 		}

// // 		sessionData.State = state
// // 		if err := h.sessionMgr.Set(r.Context(), sessionID, sessionData); err != nil {
// // 			http.Error(w, "failed to save session", http.StatusInternalServerError)
// // 			return
// // 		}

// // 		http.Redirect(w, r, h.provider.GetAuthURL(state), http.StatusFound)
// // 	})
// // }

// // // Callback handles the redirect from the OIDC provider.
// // func (h *AuthHandler) Callback() http.Handler {
// // 	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
// // 		cookie, err := r.Cookie(h.opts.Name)
// // 		if err != nil {
// // 			http.Error(w, "missing session cookie", http.StatusBadRequest)
// // 			return
// // 		}
// // 		sessionID := cookie.Value

// // 		sessionData, ok, err := h.sessionMgr.Get(r.Context(), sessionID)
// // 		if err != nil || !ok {
// // 			http.Error(w, "failed to retrieve session", http.StatusInternalServerError)
// // 			return
// // 		}

// // 		if r.URL.Query().Get("state") != sessionData.State {
// // 			http.Error(w, "invalid state parameter", http.StatusBadRequest)
// // 			return
// // 		}

// // 		token, err := h.provider.Exchange(r.Context(), r.URL.Query().Get("code"))
// // 		if err != nil {
// // 			http.Error(w, "failed to exchange code for token", http.StatusInternalServerError)
// // 			return
// // 		}

// // 		userInfo, err := h.provider.GetUserInfo(r.Context(), token)
// // 		if err != nil {
// // 			http.Error(w, "failed to get user info", http.StatusInternalServerError)
// // 			return
// // 		}

// // 		var claims map[string]interface{}
// // 		if err := userInfo.GetClaims(&claims); err != nil {
// // 			http.Error(w, "failed to get claims from user info", http.StatusInternalServerError)
// // 			return
// // 		}

// // 		sessionData.AccessToken = token.AccessToken
// // 		sessionData.RefreshToken = token.RefreshToken
// // 		sessionData.IDToken = token.Extra("id_token").(string)
// // 		sessionData.ExpiresIn = token.Expiry
// // 		sessionData.Email = userInfo.GetEmail()
// // 		sessionData.Username = userInfo.GetName()
// // 		sessionData.Claims = claims
// // 		sessionData.State = "" // Clear state after use

// // 		if err := h.sessionMgr.Set(r.Context(), sessionID, sessionData); err != nil {
// // 			http.Error(w, "failed to save session", http.StatusInternalServerError)
// // 			return
// // 		}

// // 		http.Redirect(w, r, "/", http.StatusFound)
// // 	})
// // }

// // // Logout clears the user's session.
// // func (h *AuthHandler) Logout() http.Handler {
// // 	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
// // 		cookie, err := r.Cookie(h.opts.Name)
// // 		if err != nil {
// // 			http.Redirect(w, r, "/", http.StatusFound)
// // 			return
// // 		}

// // 		if err := h.sessionMgr.Delete(r.Context(), cookie.Value); err != nil {
// // 			http.Error(w, "failed to delete session", http.StatusInternalServerError)
// // 			return
// // 		}

// // 		http.SetCookie(w, &http.Cookie{
// // 			Name:   h.opts.Name,
// // 			Value:  "",
// // 			Path:   "/",
// // 			MaxAge: -1,
// // 		})

// // 		http.Redirect(w, r, "/", http.StatusFound)
// // 	})
// // }

// // // Auth is a middleware that checks if a user is authenticated.
// // func Auth() func(http.Handler) http.Handler {
// // 	return func(next http.Handler) http.Handler {
// // 		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
// // 			sessionData, ok := middleware.SessionFromContext(r.Context())
// // 			if !ok {
// // 				http.Error(w, "could not get session from context", http.StatusInternalServerError)
// // 				return
// // 			}

// // 			if !sessionData.IsAuthenticated() {
// // 				http.Redirect(w, r, "/auth/login", http.StatusFound)
// // 				return
// // 			}

// // 			next.ServeHTTP(w, r)
// // 		})
// // 	}
// // }

// // func generateRandomState() (string, error) {
// // 	b := make([]byte, 32)
// // 	_, err := rand.Read(b)
// // 	if err != nil {
// // 		return "", fmt.Errorf("failed to generate random bytes for state: %w", err)
// // 	}
// // 	return base64.RawURLEncoding.EncodeToString(b), nil
// // }
