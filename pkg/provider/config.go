package provider

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

// KeycloakConfig represents the OpenID Connect configuration for Keycloak.
// Source: https://openid.net/specs/openid-connect-discovery-1_0-final.html#ProviderMetadata
type OAuthMeta struct {
	Issuer                                                    string   `json:"issuer"`
	AuthorizationEndpoint                                     string   `json:"authorization_endpoint"`
	TokenEndpoint                                             string   `json:"token_endpoint"`
	IntrospectionEndpoint                                     string   `json:"introspection_endpoint"`
	UserinfoEndpoint                                          string   `json:"userinfo_endpoint"`
	EndSessionEndpoint                                        string   `json:"end_session_endpoint"`
	FrontchannelLogoutSessionSupported                        bool     `json:"frontchannel_logout_session_supported"`
	FrontchannelLogoutSupported                               bool     `json:"frontchannel_logout_supported"`
	JWKSURI                                                   string   `json:"jwks_uri"`
	CheckSessionIframe                                        string   `json:"check_session_iframe"`
	GrantTypesSupported                                       []string `json:"grant_types_supported"`
	ACRValuesSupported                                        []string `json:"acr_values_supported"`
	ResponseTypesSupported                                    []string `json:"response_types_supported"`
	SubjectTypesSupported                                     []string `json:"subject_types_supported"`
	PromptValuesSupported                                     []string `json:"prompt_values_supported"`
	IDTokenSigningAlgValuesSupported                          []string `json:"id_token_signing_alg_values_supported"`
	IDTokenEncryptionAlgValuesSupported                       []string `json:"id_token_encryption_alg_values_supported"`
	IDTokenEncryptionEncValuesSupported                       []string `json:"id_token_encryption_enc_values_supported"`
	UserinfoSigningAlgValuesSupported                         []string `json:"userinfo_signing_alg_values_supported"`
	UserinfoEncryptionAlgValuesSupported                      []string `json:"userinfo_encryption_alg_values_supported"`
	UserinfoEncryptionEncValuesSupported                      []string `json:"userinfo_encryption_enc_values_supported"`
	RequestObjectSigningAlgValuesSupported                    []string `json:"request_object_signing_alg_values_supported"`
	RequestObjectEncryptionAlgValuesSupported                 []string `json:"request_object_encryption_alg_values_supported"`
	RequestObjectEncryptionEncValuesSupported                 []string `json:"request_object_encryption_enc_values_supported"`
	ResponseModesSupported                                    []string `json:"response_modes_supported"`
	RegistrationEndpoint                                      string   `json:"registration_endpoint"`
	TokenEndpointAuthMethodsSupported                         []string `json:"token_endpoint_auth_methods_supported"`
	TokenEndpointAuthSigningAlgValuesSupported                []string `json:"token_endpoint_auth_signing_alg_values_supported"`
	IntrospectionEndpointAuthMethodsSupported                 []string `json:"introspection_endpoint_auth_methods_supported"`
	IntrospectionEndpointAuthSigningAlgValuesSupported        []string `json:"introspection_endpoint_auth_signing_alg_values_supported"`
	AuthorizationSigningAlgValuesSupported                    []string `json:"authorization_signing_alg_values_supported"`
	AuthorizationEncryptionAlgValuesSupported                 []string `json:"authorization_encryption_alg_values_supported"`
	AuthorizationEncryptionEncValuesSupported                 []string `json:"authorization_encryption_enc_values_supported"`
	ClaimsSupported                                           []string `json:"claims_supported"`
	ClaimTypesSupported                                       []string `json:"claim_types_supported"`
	ClaimsParameterSupported                                  bool     `json:"claims_parameter_supported"`
	ScopesSupported                                           []string `json:"scopes_supported"`
	RequestParameterSupported                                 bool     `json:"request_parameter_supported"`
	RequestURIParameterSupported                              bool     `json:"request_uri_parameter_supported"`
	RequireRequestURIRegistration                             bool     `json:"require_request_uri_registration"`
	CodeChallengeMethodsSupported                             []string `json:"code_challenge_methods_supported"`
	TLSClientCertificateBoundAccessTokens                     bool     `json:"tls_client_certificate_bound_access_tokens"`
	RevocationEndpoint                                        string   `json:"revocation_endpoint"`
	RevocationEndpointAuthMethodsSupported                    []string `json:"revocation_endpoint_auth_methods_supported"`
	RevocationEndpointAuthSigningAlgValuesSupported           []string `json:"revocation_endpoint_auth_signing_alg_values_supported"`
	BackchannelLogoutSupported                                bool     `json:"backchannel_logout_supported"`
	BackchannelLogoutSessionSupported                         bool     `json:"backchannel_logout_session_supported"`
	DeviceAuthorizationEndpoint                               string   `json:"device_authorization_endpoint"`
	BackchannelTokenDeliveryModesSupported                    []string `json:"backchannel_token_delivery_modes_supported"`
	BackchannelAuthenticationEndpoint                         string   `json:"backchannel_authentication_endpoint"`
	BackchannelAuthenticationRequestSigningAlgValuesSupported []string `json:"backchannel_authentication_request_signing_alg_values_supported"`
	RequirePushedAuthorizationRequests                        bool     `json:"require_pushed_authorization_requests"`
	PushedAuthorizationRequestEndpoint                        string   `json:"pushed_authorization_request_endpoint"`
	MTLSEndpointAliases                                       struct {
		TokenEndpoint                      string `json:"token_endpoint"`
		RevocationEndpoint                 string `json:"revocation_endpoint"`
		IntrospectionEndpoint              string `json:"introspection_endpoint"`
		DeviceAuthorizationEndpoint        string `json:"device_authorization_endpoint"`
		RegistrationEndpoint               string `json:"registration_endpoint"`
		UserinfoEndpoint                   string `json:"userinfo_endpoint"`
		PushedAuthorizationRequestEndpoint string `json:"pushed_authorization_request_endpoint"`
		BackchannelAuthenticationEndpoint  string `json:"backchannel_authentication_endpoint"`
	} `json:"mtls_endpoint_aliases"`
	AuthorizationResponseIssParameterSupported bool `json:"authorization_response_iss_parameter_supported"`
}

// KeycloakUMA2Config represents the UMA server configuration endpoints
// and supported features.
type UMAMeta struct {
	OAuthMeta
	ResourceRegistrationEndpoint string `json:"resource_registration_endpoint"`
	PermissionEndpoint           string `json:"permission_endpoint"`
	PolicyEndpoint               string `json:"policy_endpoint"`
}

// FetchOAuthMetadata retrieves the OAuth metadata from the discovery URL.
func FetchOAuthMetadata(url string, httpClient *http.Client) (*OAuthMeta, error) {
	data, err := fetchMetadata(url, httpClient)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch metadata: %w", err)
	}

	var meta OAuthMeta
	if err := json.Unmarshal(data, &meta); err != nil {
		return nil, fmt.Errorf("failed to decode oauth config: %w", err)
	}

	return &meta, nil
}

// FetchUMAMetadata retrieves the UMA metadata from the discovery URL.
func FetchUMAMetadata(url string, httpClient *http.Client) (*UMAMeta, error) {
	data, err := fetchMetadata(url, httpClient)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch metadata: %w", err)
	}

	var meta UMAMeta
	if err := json.Unmarshal(data, &meta); err != nil {
		return nil, fmt.Errorf("failed to decode uma2 config: %w", err)
	}

	return &meta, nil
}

// FetchProviderMetadata retrieves the OIDC configuration from the discovery URL.
func fetchMetadata(url string, httpClient *http.Client) ([]byte, error) {
	resp, err := httpClient.Get(url)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch metadata: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to fetch metadata: %s", resp.Status)
	}

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read metadata response body: %w", err)
	}

	return data, nil
}
