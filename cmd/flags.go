package main

import (
	"github.com/urfave/cli/v3"
)

// verbosityLevel is a variable to track the verbosity level for logging.
var verbosityLevel = 0

// flagVerbose is a CLI flag for enabling verbose logging.
var flagVerbose = &cli.BoolFlag{
	Name:    "log.verbose",
	Usage:   "Enable verbose logging",
	Aliases: []string{"v"},
	Config: cli.BoolConfig{
		Count: &verbosityLevel,
	},
	Sources: cli.EnvVars("LOG_VERBOSE"),
}

// flagWebListenHTTP is a CLI flag for specifying the HTTP address to listen on.
var flagWebListenHTTP = &cli.StringFlag{
	Name:     "web.listen-http",
	Usage:    "HTTP listen address (e.g., :8080 or 0.0.0.0:8080)",
	Value:    ":8080",
	Required: false,
	Sources:  cli.EnvVars("WEB_LISTEN_HTTP"),
}

// flagWebListenHTTPS is a CLI flag for specifying the HTTPS address to listen on.
var flagWebListenHTTPS = &cli.StringFlag{
	Name:     "web.listen-https",
	Usage:    "HTTPS listen address (e.g., :8443 or 0.0.0.0:8443)",
	Value:    ":8443",
	Required: false,
	Sources:  cli.EnvVars("WEB_LISTEN_HTTPS"),
}

// flagWebTLSCert is a CLI flag for specifying the path to the TLS certificate file.
// This is used for enabling HTTPS on the server and needs to be provided
// if HTTPS is enabled.
var flagWebTLSCert = &cli.StringFlag{
	Name:     "web.tls-cert",
	Usage:    "Path to the TLS certificate file",
	Required: false,
	Sources:  cli.EnvVars("WEB_TLS_CERT"),
}

// flagWebTLSKey is a CLI flag for specifying the path to the TLS private key file.
// This is used for enabling HTTPS on the server and needs to be provided
// if HTTPS is enabled. It should be used in conjunction with --tls-cert.
var flagWebTLSKey = &cli.StringFlag{
	Name:     "web.tls-key",
	Usage:    "Path to the TLS private key file",
	Required: false,
	Sources:  cli.EnvVars("WEB_TLS_KEY"),
}

// flagWebSessionName is a CLI flag for specifying the name used for session management.
var flagWebSessionName = &cli.StringFlag{
	Name:    "web.session-name",
	Usage:   "Name for session management (e.g., a long, random string)",
	Value:   "default-session-name",
	Sources: cli.EnvVars("WEB_SESSION_KEY"),
}

// flagOIDCDiscoveryURL is a CLI flag for specifying the OpenID Connect discovery URL.
var flagOIDCDiscoveryURL = &cli.StringFlag{
	Name:     "oidc.discovery-url",
	Usage:    "URL for OpenID Connect discovery (e.g., https://example.com/.well-known/openid-configuration)",
	Required: true,
	Sources:  cli.EnvVars("OIDC_DISCOVERY_URL"),
}

// flagOIDCClientID is a CLI flag for specifying the client ID for OpenID Connect.
var flagOIDCClientID = &cli.StringFlag{
	Name:     "oidc.client-id",
	Usage:    "Client ID for OpenID Connect",
	Required: true,
	Sources:  cli.EnvVars("OIDC_CLIENT_ID"),
}

// flagOIDCClientSecret is a CLI flag for specifying the client secret for OpenID
// Connect.
var flagOIDCClientSecret = &cli.StringFlag{
	Name:     "oidc.client-secret",
	Usage:    "Client secret for OpenID Connect",
	Required: true,
	Sources:  cli.EnvVars("OIDC_CLIENT_SECRET"),
}

// flagOIDCTLSSkipVerify is a CLI flag for skipping TLS verification.
var flagOIDCTLSSkipVerify = &cli.BoolFlag{
	Name:     "oidc.tls-skip-verify",
	Usage:    "Skip TLS verification (useful for self-signed certificates)",
	Value:    false,
	Required: false,
	Sources:  cli.EnvVars("OIDC_TLS_SKIP_VERIFY"),
}

// flagProxyUpstreamURL is a CLI flag for specifying the URL of the upstream service.
var flagProxyUpstreamURL = &cli.StringFlag{
	Name:     "proxy.upstream-url",
	Usage:    "URL for the upstream service (e.g., https://api.example.com)",
	Required: true,
	Sources:  cli.EnvVars("PROXY_UPSTREAM_URL"),
}

// flagStorageRedisEnabled is a CLI flag for enabling Redis storage for session management.
var flagStorageRedisEnabled = &cli.BoolFlag{
	Name:    "storage.redis-enabled",
	Usage:   "Enable Redis storage for session management",
	Value:   false,
	Sources: cli.EnvVars("STORAGE_REDIS_ENABLED"),
}

// flagStorageRedisURL is a CLI flag for specifying the Redis server URL.
var flagStorageRedisURL = &cli.StringFlag{
	Name:    "storage.redis-url",
	Usage:   "URL for the Redis server (e.g., localhost:6379)",
	Value:   "localhost:6379",
	Sources: cli.EnvVars("STORAGE_REDIS_URL"),
}

// flagAuthPolicyMode is a CLI flag for specifying the policy mode.
// There are two modes: "local" for local policy management and "delegated"
// for using an external policy service (e.g., Keycloak).
var flagAuthPolicyMode = &cli.StringFlag{
	Name:    "auth.mode",
	Usage:   "Policy mode: 'local' for local policy, 'delegated' for delegated (e.g., Keycloak) policies",
	Value:   "local",
	Sources: cli.EnvVars("AUTH_MODE"),
}
