package main

import (
	"github.com/urfave/cli/v3"
)

// verbosityLevel is a variable to track the verbosity level for logging.
var verbosityLevel = 0

// flagVerbose is a CLI flag for enabling verbose logging.
var flagVerbose = &cli.BoolFlag{
	Name:    "verbose",
	Usage:   "Enable verbose logging",
	Aliases: []string{"v"},
	Config: cli.BoolConfig{
		Count: &verbosityLevel,
	},
	Sources: cli.EnvVars("VERBOSE"),
}

// flagListenHTTP is a CLI flag for specifying the HTTP address to listen on.
var flagListenHTTP = &cli.StringFlag{
	Name:     "listen-http",
	Usage:    "HTTP listen address (e.g., :8080 or 0.0.0.0:8080)",
	Value:    ":8080",
	Required: false,
	Sources:  cli.EnvVars("LISTEN_HTTP"),
}

// flagListenHTTPS is a CLI flag for specifying the HTTPS address to listen on.
var flagListenHTTPS = &cli.StringFlag{
	Name:     "listen-https",
	Usage:    "HTTPS listen address (e.g., :8443 or 0.0.0.0:8443)",
	Value:    ":8443",
	Required: false,
	Sources:  cli.EnvVars("LISTEN_HTTPS"),
}

// flagTLSCert is a CLI flag for specifying the path to the TLS certificate file.
// This is used for enabling HTTPS on the server and needs to be provided
// if HTTPS is enabled.
var flagTLSCert = &cli.StringFlag{
	Name:     "tls-cert",
	Usage:    "Path to the TLS certificate file",
	Required: false,
	Sources:  cli.EnvVars("TLS_CERT"),
}

// flagTLSKey is a CLI flag for specifying the path to the TLS private key file.
// This is used for enabling HTTPS on the server and needs to be provided
// if HTTPS is enabled. It should be used in conjunction with --tls-cert.
var flagTLSKey = &cli.StringFlag{
	Name:     "tls-key",
	Usage:    "Path to the TLS private key file",
	Required: false,
	Sources:  cli.EnvVars("TLS_KEY"),
}

// flagTLSSkipVerify is a CLI flag for skipping TLS verification.
var flagTLSSkipVerify = &cli.BoolFlag{
	Name:     "tls-skip-verify",
	Usage:    "Skip TLS verification (useful for self-signed certificates)",
	Value:    false,
	Required: false,
	Sources:  cli.EnvVars("TLS_SKIP_VERIFY"),
}

// flagDiscoveryURL is a CLI flag for specifying the OpenID Connect discovery URL.
var flagDiscoveryURL = &cli.StringFlag{
	Name:     "discovery-url",
	Usage:    "URL for OpenID Connect discovery (e.g., https://example.com/.well-known/openid-configuration)",
	Required: true,
	Sources:  cli.EnvVars("DISCOVERY_URL"),
}

// flagClientID is a CLI flag for specifying the client ID for OpenID Connect.
var flagClientID = &cli.StringFlag{
	Name:     "client-id",
	Usage:    "Client ID for OpenID Connect",
	Required: true,
	Sources:  cli.EnvVars("CLIENT_ID"),
}

// flagClientSecret is a CLI flag for specifying the client secret for OpenID
// Connect.
var flagClientSecret = &cli.StringFlag{
	Name:     "client-secret",
	Usage:    "Client secret for OpenID Connect",
	Required: true,
	Sources:  cli.EnvVars("CLIENT_SECRET"),
}

// flagUpstreamURL is a CLI flag for specifying the URL of the upstream service.
var flagUpstreamURL = &cli.StringFlag{
	Name:     "upstream-url",
	Usage:    "URL for the upstream service (e.g., https://api.example.com)",
	Required: true,
	Sources:  cli.EnvVars("UPSTREAM_URL"),
}

// flagPolicyMode is a CLI flag for specifying the policy mode.
// There are two modes: "local" for local policy management and "delegated"
// for using an external policy service (e.g., Keycloak).
var flagPolicyMode = &cli.StringFlag{
	Name:    "policy-mode",
	Usage:   "Policy mode: 'local' for local policy, 'delegated' for delegated (e.g., Keycloak) policies",
	Value:   "local",
	Sources: cli.EnvVars("POLICY_MODE"),
}
