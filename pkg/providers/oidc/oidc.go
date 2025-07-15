package oidc

import (
	"context"
	"errors"

	"github.com/coreos/go-oidc/v3/oidc"
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
}

// ProviderOptions holds the configuration options for creating an OIDC provider.
type ProviderOptions struct {
	Issuer       string
	ClientID     string
	ClientSecret string
	RedirectURL  string
	Scopes       []string
}

// NewProvider creates a new OIDC provider instance with the given options.
func NewProvider(ctx context.Context, options ...func(*ProviderOptions)) (*Provider, error) {
	opts := &ProviderOptions{
		Scopes: []string{oidc.ScopeOpenID, "profile", "email"}, // Default scopes
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

	provider, err := oidc.NewProvider(ctx, opts.Issuer)
	if err != nil {
		return nil, err
	}

	p := &Provider{
		provider: provider,
		oauthConfig: oauth2.Config{
			ClientID:     opts.ClientID,
			ClientSecret: opts.ClientSecret,
			RedirectURL:  opts.RedirectURL,
			Endpoint:     provider.Endpoint(),
			Scopes:       opts.Scopes,
		},
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

// GetProvider returns the OIDC provider.
// This provider can be used to interact with the OpenID Connect server.
func (p *Provider) GetProvider() *oidc.Provider {
	return p.provider
}

// GetConfig returns the OAuth2 configuration.
// This configuration contains the client ID, client secret, redirect URL, and other OAuth2 settings.
func (p *Provider) GetConfig() oauth2.Config {
	return p.oauthConfig
}

// GetAuthURL returns the authentication URL with the given state.
// The state parameter is used to maintain state between the request and the callback.
func (p *Provider) GetAuthURL(state string) string {
	return p.oauthConfig.AuthCodeURL(state)
}

// GetTokenByCode exchanges the authorization code for an OAuth2 token.
// Returns a token source that can be used to obtain the token.
func (p *Provider) GetTokenByCode(ctx context.Context, code string) (*oauth2.TokenSource, error) {
	var err error
	var token *oauth2.Token

	if token, err = p.oauthConfig.Exchange(ctx, code); err != nil {
		return nil, err
	}

	tokenSource := p.oauthConfig.TokenSource(ctx, token)

	return &tokenSource, nil
}

// GetUserInfo retrieves the user information using the OAuth2 token.
// The user information is stored in the claims parameter.
func (p *Provider) GetUserInfo(ctx context.Context, token *oauth2.TokenSource, claims interface{}) error {
	var err error

	var userInfo *oidc.UserInfo
	if userInfo, err = p.provider.UserInfo(ctx, *token); err != nil {
		return err
	}

	if err = userInfo.Claims(&claims); err != nil {
		return err
	}

	return nil
}
