package aegis

import (
	"net/url"

	"github.com/praserx/aegis/pkg/provider"
	"github.com/praserx/aegis/pkg/session"
)

type Options struct {
	Provider       provider.Provider     // Authentication provider
	UpstreamURL    *url.URL              // URL for the upstream service
	SessionManager *session.Manager      // Session management instance
	CookieOptions  session.CookieOptions // Cookie options
}

func WithProvider(p provider.Provider) func(*Options) {
	return func(o *Options) {
		o.Provider = p
	}
}

func WithUpstreamURL(url *url.URL) func(*Options) {
	return func(o *Options) {
		o.UpstreamURL = url
	}
}

func WithSessionManager(manager *session.Manager) func(*Options) {
	return func(o *Options) {
		o.SessionManager = manager
	}
}

func WithCookieOptions(opts session.CookieOptions) func(*Options) {
	return func(o *Options) {
		o.CookieOptions = opts
	}
}
