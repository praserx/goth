package aegis

import (
	"net/url"

	"golang.org/x/oauth2"
)

type Options struct {
	Verbosity    int            // Enable verbose logging
	Oauth2Config *oauth2.Config // OAuth2 configuration
	UpstreamURL  *url.URL       // URL for the upstream service
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
