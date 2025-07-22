package aegis

import (
	"fmt"
	"net/http"
	"net/url"

	"github.com/google/uuid"
	"github.com/praserx/aegis/pkg/middleware"
	"github.com/praserx/aegis/pkg/provider"
	"github.com/praserx/aegis/pkg/session"
	"github.com/praserx/aegis/pkg/storage"
)

// Proxy is the main struct for the HTTP authorization proxy server.
type Proxy struct {
	Mux      *http.ServeMux // HTTP multiplexer for routing
	Upstream *url.URL
}

// New creates a new Proxy instance with all required middlewares and handlers.
// It returns an error if initialization fails.
func New(options ...func(*Options)) (*Proxy, error) {
	opts := &Options{
		Provider:       nil,
		UpstreamURL:    nil,
		SessionStorage: nil,
		CookieOptions: session.CookieOptions{
			Name:     "proxy-session",                          // Default session name
			MaxAge:   int(session.DefaultSessionTTL.Seconds()), // Session cookie expiration time in seconds
			Secure:   true,                                     // Set to true if using HTTPS
			HttpOnly: true,                                     // Prevents JavaScript access to the cookie
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
		middleware.AccessLogMiddleware(),
		middleware.SessionMiddleware(opts.SessionStorage, opts.CookieOptions),
		middleware.AuthorizationMiddleware(opts.Provider),
		middleware.Proxy(opts.UpstreamURL),
	)(http.NotFoundHandler()))

	return &Proxy{
		Mux:      mux,
		Upstream: opts.UpstreamURL,
	}, nil
}

// ServeHTTP implements http.Handler for Proxy.
func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	p.Mux.ServeHTTP(w, r)
}

// setupAuthenticationRoutes sets up the authentication routes with the provided options.
func setupAuthenticationRoutes(mux *http.ServeMux, opts *Options) {
	mux.Handle(
		opts.EndpointPaths.Login,
		handlerWithMiddlewares(opts, newLoginHandler(opts.Provider)),
	)
	mux.Handle(
		opts.EndpointPaths.Logout,
		handlerWithMiddlewares(opts, newLogoutHandler(opts.EndpointPaths.AfterLogoutRedirect, opts.CookieOptions.Name)),
	)
	mux.Handle(
		opts.EndpointPaths.Callback,
		handlerWithMiddlewares(opts, newCallbackHandler(opts.Provider)),
	)
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
	return middleware.AccessLogMiddleware()( // log first
		middleware.SessionMiddleware(opts.SessionStorage, opts.CookieOptions)(
			handler,
		),
	)
}

// NewLoginHandler creates a new HTTP handler for login.
func newLoginHandler(provider provider.Provider) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sessionData, ok := middleware.SessionFromContext(r.Context())
		if !ok {
			http.Error(w, "Failed to retrieve session", http.StatusInternalServerError)
			return
		}

		state := uuid.New().String()
		redirectURL := provider.GetAuthURL(state)
		sessionData.State = state
		middleware.NewContextWithSessionData(r.Context(), sessionData)

		http.Redirect(w, r, redirectURL, http.StatusFound)
	})
}

// newLogoutHandler creates a new HTTP handler for logout.
func newLogoutHandler(redirectURL string, cookieName string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Clear session cookie
		http.SetCookie(w, &http.Cookie{
			Name:   cookieName,
			Value:  "",
			MaxAge: -1, // Expire immediately
		})
		http.Redirect(w, r, redirectURL, http.StatusFound)
	})
}

func newCallbackHandler(provider provider.Provider) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// // Handle the callback logic here, e.g., exchanging code for tokens
		// // and saving session data.
		// sessionData, err := provider.HandleCallback(r.Context(), r)
		// if err != nil {
		// 	http.Error(w, "Failed to handle callback", http.StatusInternalServerError)
		// 	return
		// }

		// // Save session data
		// sessionID, err := sessionManager.Save(r.Context(), sessionData)
		// if err != nil {
		// 	http.Error(w, "Failed to save session", http.StatusInternalServerError)
		// 	return
		// }
	})
}
