package aegis

import (
	"fmt"
	"net/http"
	"net/url"

	"github.com/praserx/aegis/pkg/middleware"
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
		SessionManager: nil,
		CookieOptions: session.CookieOptions{
			Name:     "proxy-session",                          // Default session name
			MaxAge:   int(session.DefaultSessionTTL.Seconds()), // Session cookie expiration time in seconds
			Secure:   true,                                     // Set to true if using HTTPS
			HttpOnly: true,                                     // Prevents JavaScript access to the cookie
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
	if opts.SessionManager == nil {
		store, err := storage.NewInMemoryStore()
		if err != nil {
			return nil, fmt.Errorf("failed to create default in-memory store: %w", err)
		}
		sessionManager, err := session.NewManager(session.WithStorage(store))
		if err != nil {
			return nil, fmt.Errorf("failed to create default session manager: %w", err)
		}
		opts.SessionManager = sessionManager
	}

	mux := http.NewServeMux()

	// Authentication routes
	// authHandler := handler.NewAuthHandler(opts.Provider, opts.SessionManager, opts.CookieOptions.Name)
	// mux.Handle("/auth/callback", authHandler.Callback())
	// mux.Handle("/auth/logout", authHandler.Logout())

	// Register the main handler with middleware chain
	mux.Handle("/", chainMiddlewares(
		middleware.AccessLogMiddleware(),
		middleware.SessionMiddleware(opts.SessionManager, opts.CookieOptions),
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
