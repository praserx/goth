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
		Verbosity:      0, // Default verbosity level
		Oauth2Config:   nil,
		UpstreamURL:    nil,
		SessionManager: nil, // Default session manager
	}

	for _, opt := range options {
		opt(opts)
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

	// Register the main handler with middleware chain
	mux.Handle("/", chainMiddlewares(
		middleware.Proxy(opts.UpstreamURL)(http.NotFoundHandler()), // Main proxy handler
		middleware.AuthorizationMiddleware(),
		middleware.SessionMiddleware(opts.SessionManager),
		middleware.AccessLogMiddleware(),
	))

	proxy := &Proxy{Mux: mux, Upstream: opts.UpstreamURL}
	return proxy, nil
}

// ServeHTTP implements http.Handler for Proxy.
func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	p.Mux.ServeHTTP(w, r)
}

// chainMiddlewares chains multiple middlewares around a handler.
func chainMiddlewares(h http.Handler, mws ...middleware.Middleware) http.Handler {
	for i := len(mws) - 1; i >= 0; i-- {
		h = mws[i](h)
	}
	return h
}
