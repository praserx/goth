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
var flagWebCookieName = &cli.StringFlag{
	Name:    "web.cookie-name",
	Usage:   "Name for session cookie",
	Value:   "AEGIS_SESSION", // Default session cookie name
	Sources: cli.EnvVars("WEB_COOKIE_NAME"),
}

// flagWebCookieMaxAge is a CLI flag for specifying the maximum age of session cookies.
var flagWebCookieMaxAge = &cli.IntFlag{
	Name:     "web.cookie-max-age",
	Usage:    "Maximum age for session cookies in seconds (default is 86400 seconds, or 24 hours)",
	Value:    86400, // Default to 24 hours
	Required: false,
	Sources:  cli.EnvVars("WEB_COOKIE_MAX_AGE"),
}

// flagWebCookieSecure is a CLI flag for specifying whether session cookies should be secure.
var flagWebCookieSecure = &cli.BoolFlag{
	Name:     "web.cookie-secure",
	Usage:    "Set session cookies to be secure (only sent over HTTPS)",
	Value:    true, // Default to true for security
	Required: false,
	Sources:  cli.EnvVars("WEB_COOKIE_SECURE"),
}

// flagWebCookieHTTPOnly is a CLI flag for specifying whether session cookies should be HTTP-only.
var flagWebCookieHTTPOnly = &cli.BoolFlag{
	Name:     "web.cookie-http-only",
	Usage:    "Set session cookies to be HTTP-only (not accessible via JavaScript)",
	Value:    true, // Default to true for security
	Required: false,
	Sources:  cli.EnvVars("WEB_COOKIE_HTTP_ONLY"),
}

// flagWebCookieSameSite is a CLI flag for specifying the SameSite attribute for session cookies.
var flagWebCookieSameSite = &cli.StringFlag{
	Name:     "web.cookie-same-site",
	Usage:    "SameSite attribute for session cookies (e.g., 'Strict', 'Lax', 'None')",
	Value:    "Strict", // Default to Lax for compatibility
	Required: false,
	Sources:  cli.EnvVars("WEB_COOKIE_SAME_SITE"),
}

// flagOIDCDiscoveryURL is a CLI flag for specifying the OpenID Connect provider URL.
var flagOIDCDiscoveryURL = &cli.StringFlag{
	Name:     "oidc.discovery-url",
	Usage:    "Discovery URL for OpenID Connect provider (see your OIDC provider documentation)",
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

// flagOIDCLoginPath is a CLI flag for specifying the path for the OIDC login endpoint.
var flagOIDCLoginPath = &cli.StringFlag{
	Name:     "oidc.login-path",
	Usage:    "Path for OIDC login endpoint (default is /auth/login)",
	Value:    "/auth/login",
	Required: false,
	Sources:  cli.EnvVars("OIDC_LOGIN_PATH"),
}

// flagOIDCLogoutPath is a CLI flag for specifying the path for the OIDC logout endpoint.
var flagOIDCLogoutPath = &cli.StringFlag{
	Name:     "oidc.logout-path",
	Usage:    "Path for OIDC logout endpoint (default is /auth/logout)",
	Value:    "/auth/logout",
	Required: false,
	Sources:  cli.EnvVars("OIDC_LOGOUT_PATH"),
}

// flagOIDCCallbackPath is a CLI flag for specifying the path for the OIDC callback endpoint.
var flagOIDCCallbackPath = &cli.StringFlag{
	Name:     "oidc.callback-path",
	Usage:    "Path for OIDC callback endpoint (default is /auth/callback)",
	Value:    "/auth/callback",
	Required: false,
	Sources:  cli.EnvVars("OIDC_CALLBACK_PATH"),
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
