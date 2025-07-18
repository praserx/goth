package uma

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/praserx/aegis/pkg/session"
)

// KeycloakUMAConfig holds the configuration for Keycloak UMA requests.
type KeycloakUMAConfig struct {
	UMA2Config          // The token endpoint URL of the Keycloak realm.
	ClientID     string // The client ID of the resource server in Keycloak that is being protected.
	ClientSecret string // The client secret of the resource server in Keycloak.
	Audience     string // The audience of the resource server in Keycloak.
}

// AuthorizationResolver checks access rights using Keycloak's fine-grained policies.
type AuthorizationResolver struct {
	Config     KeycloakUMAConfig
	HttpClient *http.Client
}

// NewAuthorizationResolver creates a new resolver for Keycloak fine-grained policies.
func NewAuthorizationResolver(config KeycloakUMAConfig) *AuthorizationResolver {
	return &AuthorizationResolver{
		Config:     config,
		HttpClient: &http.Client{},
	}
}

// CheckAccess evaluates if the session's access token grants permission for the requested URI.
// It sends a request to Keycloak's token endpoint using the UMA grant type to get a decision.
func (r *AuthorizationResolver) CheckAccess(ctx context.Context, s session.Session, req *http.Request) (bool, error) {
	// The resource being requested is the URI path.
	permission := req.URL.Path

	formData := url.Values{}
	formData.Set("grant_type", "urn:ietf:params:oauth:grant-type:uma-ticket")
	formData.Set("audience", r.Config.Audience)
	formData.Set("response_mode", "decision")
	formData.Set("permission", permission)
	formData.Set("permission_resource_format", "uri")
	formData.Set("permission_resource_matching_uri", "true")

	tokenReq, err := http.NewRequestWithContext(ctx, http.MethodPost, r.Config.TokenEndpoint, strings.NewReader(formData.Encode()))
	if err != nil {
		return false, fmt.Errorf("failed to create token request: %w", err)
	}

	if s.IsAuthenticated() {
		tokenReq.Header.Set("Authorization", "Bearer "+s.AccessToken)
	} else {
		tokenReq.SetBasicAuth(r.Config.Audience, r.Config.ClientSecret)
		tokenReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}

	resp, err := r.HttpClient.Do(tokenReq)
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
