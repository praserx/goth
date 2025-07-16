package oidc

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/praserx/aegis/pkg/provider"
	"golang.org/x/oauth2"
)

var (
	ErrMissingIssuer       = errors.New("oidc provider issuer is required")
	ErrMissingClientID     = errors.New("oidc client id is required")
	ErrMissingClientSecret = errors.New("oidc client secret is required")
	ErrMissingRedirectURL  = errors.New("oidc redirect url is required")
)

// Provider represents an OIDC provider with its configuration.
type Provider struct {
	provider    *oidc.Provider
	oauthConfig oauth2.Config
	claimsMap   provider.ClaimsMap
}

// ProviderOptions holds the configuration options for creating an OIDC provider.
type ProviderOptions struct {
	Issuer       string
	ClientID     string
	ClientSecret string
	RedirectURL  string
	Scopes       []string
	ClaimsMap    provider.ClaimsMap
}

// NewProvider creates a new OIDC provider instance with the given options.
func NewProvider(ctx context.Context, options ...func(*ProviderOptions)) (provider.Provider, error) {
	opts := &ProviderOptions{
		Scopes: []string{oidc.ScopeOpenID, "profile", "email"}, // Default scopes
		ClaimsMap: provider.ClaimsMap{ // Default claims map
			ID:    "sub",
			Email: "email",
			Name:  "name",
		},
	}

	for _, opt := range options {
		opt(opts)
	}

	if opts.Issuer == "" {
		return nil, ErrMissingIssuer
	}
	if opts.ClientID == "" {
		return nil, ErrMissingClientID
	}
	if opts.ClientSecret == "" {
		return nil, ErrMissingClientSecret
	}
	if opts.RedirectURL == "" {
		return nil, ErrMissingRedirectURL
	}

	oidcProvider, err := oidc.NewProvider(ctx, opts.Issuer)
	if err != nil {
		return nil, err
	}

	p := &Provider{
		provider: oidcProvider,
		oauthConfig: oauth2.Config{
			ClientID:     opts.ClientID,
			ClientSecret: opts.ClientSecret,
			RedirectURL:  opts.RedirectURL,
			Endpoint:     oidcProvider.Endpoint(),
			Scopes:       opts.Scopes,
		},
		claimsMap: opts.ClaimsMap,
	}

	return p, nil
}

// WithIssuer sets the OIDC issuer URL in the provider options.
func WithIssuer(issuer string) func(*ProviderOptions) {
	return func(o *ProviderOptions) {
		o.Issuer = issuer
	}
}

// WithClientID sets the OIDC client ID in the provider options.
func WithClientID(clientID string) func(*ProviderOptions) {
	return func(o *ProviderOptions) {
		o.ClientID = clientID
	}
}

// WithClientSecret sets the OIDC client secret in the provider options.
func WithClientSecret(clientSecret string) func(*ProviderOptions) {
	return func(o *ProviderOptions) {
		o.ClientSecret = clientSecret
	}
}

// WithRedirectURL sets the OIDC redirect URL in the provider options.
func WithRedirectURL(redirectURL string) func(*ProviderOptions) {
	return func(o *ProviderOptions) {
		o.RedirectURL = redirectURL
	}
}

// WithScopes sets the OIDC scopes in the provider options.
func WithScopes(scopes []string) func(*ProviderOptions) {
	return func(o *ProviderOptions) {
		o.Scopes = scopes
	}
}

// WithClaimsMap sets the claims map in the provider options.
func WithClaimsMap(claimsMap provider.ClaimsMap) func(*ProviderOptions) {
	return func(o *ProviderOptions) {
		o.ClaimsMap = claimsMap
	}
}

// GetAuthURL returns the authentication URL with the given state.
// The state parameter is used to maintain state between the request and the callback.
func (p *Provider) GetAuthURL(state string) string {
	return p.oauthConfig.AuthCodeURL(state)
}

// Exchange exchanges an authorization code for an OAuth2 token.
// Returns a token source that can be used to obtain the token.
func (p *Provider) Exchange(ctx context.Context, code string) (*oauth2.Token, error) {
	return p.oauthConfig.Exchange(ctx, code)
}

// GetUserInfo retrieves user information from the provider using a valid token.
// The user information is stored in the claims parameter.
func (p *Provider) GetUserInfo(ctx context.Context, token *oauth2.Token) (provider.UserInfo, error) {
	oidcUserInfo, err := p.provider.UserInfo(ctx, oauth2.StaticTokenSource(token))
	if err != nil {
		return nil, err
	}

	// Create a struct to hold the claims.
	var claims struct {
		Email    string   `json:"email"`
		Verified bool     `json:"email_verified"`
		Groups   []string `json:"groups"`
		// Add other claims you need to extract here.
	}
	if err := oidcUserInfo.Claims(&claims); err != nil {
		return nil, err
	}

	rawClaims, err := json.Marshal(claims)
	if err != nil {
		return nil, err
	}

	userInfo := &UserInfo{
		rawClaims: rawClaims,
		claimsMap: p.claimsMap,
	}

	return userInfo, nil
}
