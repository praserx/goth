package aegis

import (
	"net/url"

	"github.com/praserx/aegis/pkg/session"
	"golang.org/x/oauth2"
)

type Options struct {
	Verbosity      int              // Enable verbose logging
	Oauth2Config   *oauth2.Config   // OAuth2 configuration
	UpstreamURL    *url.URL         // URL for the upstream service
	SessionManager *session.Manager // Session management instance
	SessionKey     string           // Key for session encryption
}

func WithOauth2Config(conf *oauth2.Config) func(*Options) {
	return func(s *Options) {
		s.Oauth2Config = conf
	}
}

func WithUpstreamURL(url *url.URL) func(*Options) {
	return func(s *Options) {
		s.UpstreamURL = url
	}
}

func WithVerbosity(level int) func(*Options) {
	return func(s *Options) {
		s.Verbosity = level
	}
}

func WithSessionManager(manager *session.Manager) func(*Options) {
	return func(s *Options) {
		s.SessionManager = manager
	}
}

func WithSessionKey(key string) func(*Options) {
	return func(s *Options) {
		s.SessionKey = key
	}
}
