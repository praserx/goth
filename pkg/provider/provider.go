package provider

import (
	"context"
	"net/http"

	"github.com/praserx/aegis/pkg/session"
	"golang.org/x/oauth2"
)

// ClaimsMap specifies which claims to use for common user attributes.
// This allows for flexible mapping of claims from different providers.
type ClaimsMap struct {
	ID    string `json:"id"`    // e.g., "sub", "uid"
	Email string `json:"email"` // e.g., "email"
	Name  string `json:"name"`  // e.g., "name", "given_name"
}

// UserInfo represents user information obtained from a provider.
// It provides a common way to access basic user details like ID, email, and name.
type UserInfo interface {
	GetID() string
	GetEmail() string
	GetName() string
	GetClaims(v interface{}) error
}

// Provider defines a generic interface for an authentication provider.
// This allows for multiple implementations (e.g., OIDC, OAuth2, SAML) to be used
// interchangeably within the application.
type Provider interface {
	// GetAuthURL returns the URL for the authentication endpoint, which the user
	// will be redirected to for login. The state parameter is used to prevent
	// CSRF attacks.
	GetAuthURL(state string) string

	// Exchange exchanges an authorization code for an OAuth2 token.
	Exchange(ctx context.Context, code string) (*oauth2.Token, error)

	// GetUserInfo retrieves user information from the provider using a valid token.
	GetUserInfo(ctx context.Context, token *oauth2.Token) (UserInfo, error)

	// AuthorizeAnonymousRequest checks if the unauthenticated user has permission
	// to access the requested resource. This is useful for public resources that
	// do not require a logged-in user but still need authorization checks.
	AuthorizeAnonymousRequest(ctx context.Context, s session.Session, req *http.Request) (bool, error)
}

// Options holds the configuration options for creating a new Identity
// provider.
type Options struct {
	// Issuer is the OIDC issuer URL, which is used to discover the provider's
	// endpoints and configuration.
	Issuer string
	// ClientID is the OIDC client ID used for authentication.
	ClientID string
	// ClientSecret is the OIDC client secret used for authentication.
	ClientSecret string
	// RedirectURL is the URL to which the provider will redirect after authentication.
	RedirectURL string
	// Scopes are the OIDC scopes requested during authentication.
	Scopes []string
	// ClaimsMap defines how to map claims from the provider to common user attributes.
	ClaimsMap ClaimsMap
	// HttpClient is the HTTP client used for making requests to the provider.
	HttpClient *http.Client
}

// WithIssuer sets the OIDC issuer URL in the provider options.
func WithIssuer(issuer string) func(*Options) {
	return func(o *Options) {
		o.Issuer = issuer
	}
}

// WithClientID sets the OIDC client ID in the provider options.
func WithClientID(clientID string) func(*Options) {
	return func(o *Options) {
		o.ClientID = clientID
	}
}

// WithClientSecret sets the OIDC client secret in the provider options.
func WithClientSecret(clientSecret string) func(*Options) {
	return func(o *Options) {
		o.ClientSecret = clientSecret
	}
}

// WithRedirectURL sets the OIDC redirect URL in the provider options.
func WithRedirectURL(redirectURL string) func(*Options) {
	return func(o *Options) {
		o.RedirectURL = redirectURL
	}
}

// WithScopes sets the OIDC scopes in the provider options.
func WithScopes(scopes []string) func(*Options) {
	return func(o *Options) {
		o.Scopes = scopes
	}
}

// WithClaimsMap sets the claims map in the provider options.
func WithClaimsMap(claimsMap ClaimsMap) func(*Options) {
	return func(o *Options) {
		o.ClaimsMap = claimsMap
	}
}

// WithHttpClient sets the HTTP client used for making requests to the provider.
func WithHttpClient(client *http.Client) func(*Options) {
	return func(o *Options) {
		o.HttpClient = client
	}
}
