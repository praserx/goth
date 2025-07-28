package proxy

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/praserx/goth/pkg/logger"
	"github.com/praserx/goth/pkg/middleware"
	"github.com/praserx/goth/pkg/provider"
	"github.com/praserx/goth/pkg/session"
	"github.com/praserx/goth/pkg/storage"
	"github.com/praserx/goth/pkg/writer"
)

// Proxy is the main struct for the HTTP authorization proxy server.
type Proxy struct {
	Mux      *http.ServeMux // HTTP multiplexer for routing
	Upstream *url.URL
	shutdown chan struct{} // Used for graceful shutdown
}

// New creates a new Proxy instance with all required middlewares and handlers.
// It returns an error if initialization fails.
func New(options ...func(*Options)) (*Proxy, error) {
	opts := &Options{
		Provider:       nil,
		UpstreamURL:    nil,
		SessionStorage: nil,
		CookieOptions: session.CookieOptions{
			MaxAge: int(session.DefaultSessionTTL.Seconds()), // Session cookie expiration time in seconds
			Secure: true,                                     // Set to true if using HTTPS
		},
		EndpointPaths: EndpointPaths{
			Login:               "/auth/login",              // Default login endpoint
			Logout:              "/auth/logout",             // Default logout endpoint
			Callback:            "/auth/callback",           // Default callback endpoint for OIDC
			BackchannelLogout:   "/auth/backchannel-logout", // Default backchannel logout endpoint
			AfterLogoutRedirect: "/",                        // Default redirect after logout
		},
	}

	for _, opt := range options {
		opt(opts)
	}

	if opts.Provider == nil {
		return nil, fmt.Errorf("provider is required")
	}
	if opts.UpstreamURL == nil {
		return nil, fmt.Errorf("upstream URL is required")
	}
	// Stricter URL validation
	if opts.UpstreamURL.Scheme != "http" && opts.UpstreamURL.Scheme != "https" {
		return nil, fmt.Errorf("upstream URL must have http or https scheme")
	}
	if opts.UpstreamURL.Host == "" {
		return nil, fmt.Errorf("upstream URL must have a host")
	}
	// Stricter cookie name validation (RFC 6265)
	for _, name := range []string{
		opts.CookieOptions.SessionCookieName,
		opts.CookieOptions.TrackingCookieName,
		opts.CookieOptions.AuthCookieName,
	} {
		if name == "" {
			return nil, fmt.Errorf("cookie names must not be empty")
		}
		if !isValidCookieName(name) {
			return nil, fmt.Errorf("invalid cookie name: %q", name)
		}
	}

	// If no session manager is provided, create a default in-memory one.
	if opts.SessionStorage == nil {
		store, err := storage.NewInMemoryStore()
		if err != nil {
			return nil, fmt.Errorf("failed to create default in-memory store: %w", err)
		}
		opts.SessionStorage = store
	}

	mux := http.NewServeMux()

	// Setup authentication routes
	setupAuthenticationRoutes(mux, opts)

	// Register the main handler with middleware chain
	mux.Handle("/", chainMiddlewares(
		middleware.ContextMiddleware(opts.CookieOptions),
		middleware.AccessLogMiddleware(opts.SessionStorage, opts.CookieOptions),
		middleware.AuthorizationMiddleware(opts.Provider, opts.SessionStorage, opts.CookieOptions),
		middleware.Proxy(opts.UpstreamURL),
	)(http.NotFoundHandler()))

	return &Proxy{
		Mux:      mux,
		Upstream: opts.UpstreamURL,
		shutdown: make(chan struct{}),
	}, nil
}

// setupAuthenticationRoutes sets up the authentication routes with the provided options.
func setupAuthenticationRoutes(mux *http.ServeMux, opts *Options) {
	mux.Handle(
		opts.EndpointPaths.Login,
		handlerWithMiddlewares(opts, newLoginHandler(opts.Provider, opts.SessionStorage, opts.CookieOptions)),
	)
	mux.Handle(
		opts.EndpointPaths.Logout,
		handlerWithMiddlewares(opts, newLogoutHandler(opts.EndpointPaths.AfterLogoutRedirect, opts.CookieOptions)),
	)
	mux.Handle(
		opts.EndpointPaths.Callback,
		handlerWithMiddlewares(opts, newCallbackHandler(opts.Provider, opts.SessionStorage, opts.CookieOptions)),
	)
}

// isValidCookieName checks if a cookie name is valid according to RFC 6265 (simplified).
func isValidCookieName(name string) bool {
	// Disallow control chars, space, tab, and separators: ()<>@,;:\"/[]?={}
	for _, c := range name {
		if c <= 0x20 || c >= 0x7f || strings.ContainsRune("()<>@,;:\\\"/[]?={} ", c) {
			return false
		}
	}
	return true
}

// Shutdown signals the proxy to gracefully shutdown. For now, it just closes the shutdown channel.
func (p *Proxy) Shutdown() {
	close(p.shutdown)
}

// ServeHTTP implements http.Handler for Proxy.
func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	p.Mux.ServeHTTP(w, r)
}

// chainMiddlewares applies a series of middlewares to an http.Handler.
// Middlewares are applied in the order they are provided.
func chainMiddlewares(middlewares ...func(http.Handler) http.Handler) func(http.Handler) http.Handler {
	return func(final http.Handler) http.Handler {
		for i := len(middlewares) - 1; i >= 0; i-- {
			final = middlewares[i](final)
		}
		return final
	}
}

// handlerWithMiddlewares wraps the handler with access log and session middlewares.
func handlerWithMiddlewares(opts *Options, handler http.Handler) http.Handler {
	return middleware.ContextMiddleware(opts.CookieOptions)(
		middleware.AccessLogMiddleware(opts.SessionStorage, opts.CookieOptions)(
			handler,
		),
	)
}

// NewLoginHandler creates a new HTTP handler for login.
func newLoginHandler(p provider.Provider, c storage.Storage, opts session.CookieOptions) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authSessionID, err := session.NewAuthSessionID(r.Context(), c)
		if err != nil {
			logger.Errorf("failed to create auth session ID: %v", err)
			writer.ErrorResponse(w, r, http.StatusInternalServerError, fmt.Sprintf("Failed to create auth session ID: %v", err))
			return
		}

		authSession := session.AuthSession{
			State:   uuid.New().String(),
			OrigURL: &url.URL{Path: "/"},
		}

		cookie := session.NewAuthCookie(authSessionID, opts)
		err = session.SetAuthSession(r.Context(), c, authSessionID, authSession)
		if err != nil {
			logger.Errorf("failed to set auth session: %v", err)
			writer.ErrorResponse(w, r, http.StatusInternalServerError, fmt.Sprintf("Failed to set auth session: %v", err))
			return
		}

		redirectURL := p.GetAuthURL(authSession.State)
		http.SetCookie(w, cookie)
		http.Redirect(w, r, redirectURL, http.StatusFound)
	})
}

// newLogoutHandler creates a new HTTP handler for logout.
func newLogoutHandler(redirectURL string, opts session.CookieOptions) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.SetCookie(w, session.NewSessionCookie("", -1, opts))
		http.Redirect(w, r, redirectURL, http.StatusFound)
	})
}

// newCallbackHandler creates a new HTTP handler for the OIDC callback.
func newCallbackHandler(p provider.Provider, c storage.Storage, opts session.CookieOptions) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Get the auth session ID from the cookie.
		authSessionID, err := r.Cookie(opts.AuthCookieName)
		if err != nil {
			logger.Errorf("failed to get auth session cookie: %v", err)
			writer.ErrorResponse(w, r, http.StatusUnauthorized, "Unauthorized")
			return
		}

		// Load the auth session from storage.
		authSession, err := session.GetAuthSession(r.Context(), c, authSessionID.Value)
		if err != nil {
			logger.Errorf("failed to get auth session: %v", err)
			writer.ErrorResponse(w, r, http.StatusUnauthorized, "Unauthorized")
			return
		}

		// Validate the state parameter to prevent CSRF attacks.
		state := r.URL.Query().Get("state")
		if state != authSession.State {
			logger.Errorf("state mismatch: expected %s, got %s", authSession.State, state)
			http.Error(w, "Invalid state", http.StatusBadRequest)
			return
		}

		// Exchange the authorization code for tokens.
		token, err := p.Exchange(r.Context(), r.URL.Query().Get("code"))
		if err != nil {
			http.Error(w, fmt.Sprintf("failed to exchange token: %v", err), http.StatusInternalServerError)
			return
		}

		userSessionID, err := session.NewUserSessionID(r.Context(), c)
		if err != nil {
			logger.Errorf("failed to create user session ID: %v", err)
			writer.ErrorResponse(w, r, http.StatusInternalServerError, fmt.Sprintf("Failed to create user session ID: %v", err))
			return
		}

		userSession := session.UserSession{
			AccessToken:  token.AccessToken,
			RefreshToken: token.RefreshToken,
			ExpiresIn:    time.Now().Add(time.Duration(token.ExpiresIn) * time.Second),
		}

		userInfo, err := p.GetUserInfo(r.Context(), token)
		if err != nil {
			http.Error(w, fmt.Sprintf("Failed to get user info: %v", err), http.StatusInternalServerError)
			return
		}

		userSession.Username = userInfo.GetName()
		userSession.Email = userInfo.GetEmail()
		// sessionObj.Claims = userInfo.GetClaims()

		cookie := session.NewSessionCookie(userSessionID, int(token.ExpiresIn), opts)
		err = session.SetUserSession(r.Context(), c, userSessionID, userSession)
		if err != nil {
			logger.Errorf("failed to set user session: %v", err)
			writer.ErrorResponse(w, r, http.StatusInternalServerError, fmt.Sprintf("Failed to set user session: %v", err))
			return
		}

		http.SetCookie(w, cookie)
		http.Redirect(w, r, authSession.OrigURL.String(), http.StatusFound)
	})
}
