package proxy

import (
	"net/url"

	"github.com/praserx/goth/pkg/provider"
	"github.com/praserx/goth/pkg/session"
	"github.com/praserx/goth/pkg/storage"
)

type Options struct {
	Provider       provider.Provider     // Authentication provider
	UpstreamURL    *url.URL              // URL for the upstream service
	SessionStorage storage.Storage       // Session management instance
	CookieOptions  session.CookieOptions // Cookie options
	EndpointPaths  EndpointPaths         // Custom endpoint paths for authentication
}

type EndpointPaths struct {
	Login               string // Path for login endpoint
	Logout              string // Path for logout endpoint
	Callback            string // Path for callback endpoint
	BackchannelLogout   string // Path for backchannel logout endpoint
	AfterLogoutRedirect string // URL to redirect to after logout
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

func WithSessionManager(sessionStorage storage.Storage) func(*Options) {
	return func(o *Options) {
		o.SessionStorage = sessionStorage
	}
}

func WithCookieOptions(opts session.CookieOptions) func(*Options) {
	return func(o *Options) {
		o.CookieOptions = opts
	}
}

func WithCustomEndpointPaths(paths EndpointPaths) func(*Options) {
	return func(o *Options) {
		o.EndpointPaths = paths
	}
}
