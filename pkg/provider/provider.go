package provider

import (
	"context"

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
}
