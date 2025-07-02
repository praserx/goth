package aegis

import (
	"net/http"
	"net/url"

	"github.com/praserx/aegis/pkg/middleware"
)

// Proxy is the main struct for the HTTP authorization proxy server.
type Proxy struct {
	Mux      *http.ServeMux // HTTP multiplexer for routing
	Upstream *url.URL
}

// New creates a new Proxy instance with all required middlewares and handlers.
func New(options ...func(*Options)) *Proxy {
	opts := &Options{
		Verbosity:    0, // Default verbosity level
		Oauth2Config: nil,
		UpstreamURL:  nil,
	}

	for _, opt := range options {
		opt(opts)
	}

	mux := http.NewServeMux()

	// Register the main handler with middleware chain
	mux.Handle("/", chainMiddlewares(
		middleware.Proxy(opts.UpstreamURL)(http.NotFoundHandler()), // Main proxy handler
		middleware.AuthorizationMiddleware(),
		middleware.SessionMiddleware(),
		middleware.AccessLogMiddleware(),
	))

	return &Proxy{Mux: mux, Upstream: opts.UpstreamURL}
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
