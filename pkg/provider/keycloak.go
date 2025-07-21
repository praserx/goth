package provider

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/praserx/aegis/pkg/session"
	"golang.org/x/oauth2"
)

var (
	ErrMissingIssuer       = errors.New("oidc provider issuer is required")
	ErrMissingClientID     = errors.New("oidc client id is required")
	ErrMissingClientSecret = errors.New("oidc client secret is required")
	ErrMissingRedirectURL  = errors.New("oidc redirect url is required")
)

// UserInfo implements the provider.UserInfo interface for OIDC.
type KeycloakUserInfo struct {
	rawClaims []byte
	claimsMap ClaimsMap
}

// NewKeycloakUserInfo creates a new KeycloakUserInfo instance with the
// provided claims.
func NewKeycloakUserInfo(id, email, name string, claims []byte) UserInfo {
	return &KeycloakUserInfo{
		rawClaims: claims,
		claimsMap: ClaimsMap{
			ID:    id,
			Email: email,
			Name:  name,
		},
	}
}

// GetID returns the user's ID from the claims.
func (u *KeycloakUserInfo) GetID() string {
	var claims map[string]interface{}
	if err := json.Unmarshal(u.rawClaims, &claims); err != nil {
		return ""
	}
	id, _ := claims[u.claimsMap.ID].(string)
	return id
}

// GetEmail returns the user's email from the claims.
func (u *KeycloakUserInfo) GetEmail() string {
	var claims map[string]interface{}
	if err := json.Unmarshal(u.rawClaims, &claims); err != nil {
		return ""
	}
	email, _ := claims[u.claimsMap.Email].(string)
	return email
}

// GetName returns the user's name from the claims.
func (u *KeycloakUserInfo) GetName() string {
	var claims map[string]interface{}
	if err := json.Unmarshal(u.rawClaims, &claims); err != nil {
		return ""
	}
	name, _ := claims[u.claimsMap.Name].(string)
	return name
}

// GetClaims unmarshals the raw claims into the provided interface.
func (u *KeycloakUserInfo) GetClaims(v interface{}) error {
	return json.Unmarshal(u.rawClaims, v)
}

// KeycloakProvider represents an OIDC provider with its configuration.
type KeycloakProvider struct {
	// The underlying OIDC provider instance.
	provider *oidc.Provider
	// OAuth2 configuration for the provider.
	oauthConfig oauth2.Config
	// ClaimsMap defines how to map claims from the provider to common user attributes.
	claimsMap ClaimsMap
	// HttpClient is the HTTP client used for making requests to the provider.
	httpClient *http.Client
}

// NewKeycloakProvider creates a new OIDC provider instance with the given options.
func NewKeycloakProvider(ctx context.Context, options ...func(*Options)) (Provider, error) {
	opts := &Options{
		Scopes: []string{oidc.ScopeOpenID, "profile", "email"}, // Default scopes
		ClaimsMap: ClaimsMap{ // Default claims map
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
	if opts.HttpClient == nil {
		opts.HttpClient = &http.Client{
			Transport: &http.Transport{
				// Skip TLS verification if configured
				TLSClientConfig: &tls.Config{InsecureSkipVerify: false},
			},
			Timeout: 10 * time.Second, // Set a reasonable timeout
		}
	}

	oidcProvider, err := oidc.NewProvider(ctx, opts.Issuer)
	if err != nil {
		return nil, err
	}

	p := &KeycloakProvider{
		provider: oidcProvider,
		oauthConfig: oauth2.Config{
			ClientID:     opts.ClientID,
			ClientSecret: opts.ClientSecret,
			RedirectURL:  opts.RedirectURL,
			Endpoint:     oidcProvider.Endpoint(),
			Scopes:       opts.Scopes,
		},
		claimsMap:  opts.ClaimsMap,
		httpClient: opts.HttpClient,
	}

	return p, nil
}

// GetAuthURL returns the authentication URL with the given state.
// The state parameter is used to maintain state between the request and the callback.
func (p *KeycloakProvider) GetAuthURL(state string) string {
	return p.oauthConfig.AuthCodeURL(state)
}

// Exchange exchanges an authorization code for an OAuth2 token.
// Returns a token source that can be used to obtain the token.
func (p *KeycloakProvider) Exchange(ctx context.Context, code string) (*oauth2.Token, error) {
	return p.oauthConfig.Exchange(ctx, code)
}

// GetUserInfo retrieves user information from the provider using a valid token.
// The user information is stored in the claims parameter.
func (p *KeycloakProvider) GetUserInfo(ctx context.Context, token *oauth2.Token) (UserInfo, error) {
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

	userInfo := &KeycloakUserInfo{
		rawClaims: rawClaims,
		claimsMap: p.claimsMap,
	}

	return userInfo, nil
}

// AuthorizeAnonymousRequest checks if the unauthenticated user has permission
// to access the requested resource.
func (p *KeycloakProvider) AuthorizeAnonymousRequest(ctx context.Context, s session.Session, req *http.Request) (bool, error) {
	// The resource being requested is the URI path.
	permission := req.URL.Path

	formData := url.Values{}
	formData.Set("grant_type", "urn:ietf:params:oauth:grant-type:uma-ticket")
	formData.Set("audience", p.oauthConfig.ClientID)
	formData.Set("response_mode", "decision")
	formData.Set("permission", permission)
	formData.Set("permission_resource_format", "uri")
	formData.Set("permission_resource_matching_uri", "true")

	tokenReq, err := http.NewRequestWithContext(ctx, http.MethodPost, p.oauthConfig.Endpoint.TokenURL, strings.NewReader(formData.Encode()))
	if err != nil {
		return false, fmt.Errorf("failed to create token request: %w", err)
	}

	if s.IsAuthenticated() {
		tokenReq.Header.Set("Authorization", "Bearer "+s.AccessToken)
	} else {
		tokenReq.SetBasicAuth(p.oauthConfig.ClientID, p.oauthConfig.ClientSecret)
		tokenReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}

	resp, err := p.httpClient.Do(tokenReq)
	if err != nil {
		return false, fmt.Errorf("failed to send token request to keycloak: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return false, fmt.Errorf("failed to read keycloak response body: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		if resp.StatusCode == http.StatusForbidden {
			return false, nil
		}
		return false, fmt.Errorf("keycloak returned status %d: %s", resp.StatusCode, string(body))
	}

	var decisionResponse struct {
		Result bool `json:"result"`
	}
	if err := json.Unmarshal(body, &decisionResponse); err != nil {
		return false, fmt.Errorf("failed to unmarshal keycloak decision response: %w", err)
	}

	return decisionResponse.Result, nil
}
