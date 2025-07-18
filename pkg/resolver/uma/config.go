package uma

// UMA2Config represents the UMA server configuration endpoints and supported features.
type UMA2Config struct {
	Issuer                                     string   `json:"issuer"`
	AuthorizationEndpoint                      string   `json:"authorization_endpoint"`
	TokenEndpoint                              string   `json:"token_endpoint"`
	IntrospectionEndpoint                      string   `json:"introspection_endpoint"`
	EndSessionEndpoint                         string   `json:"end_session_endpoint"`
	FrontchannelLogoutSessionSupported         bool     `json:"frontchannel_logout_session_supported"`
	FrontchannelLogoutSupported                bool     `json:"frontchannel_logout_supported"`
	JWKSURI                                    string   `json:"jwks_uri"`
	GrantTypesSupported                        []string `json:"grant_types_supported"`
	ResponseTypesSupported                     []string `json:"response_types_supported"`
	ResponseModesSupported                     []string `json:"response_modes_supported"`
	RegistrationEndpoint                       string   `json:"registration_endpoint"`
	TokenEndpointAuthMethodsSupported          []string `json:"token_endpoint_auth_methods_supported"`
	TokenEndpointAuthSigningAlgValuesSupported []string `json:"token_endpoint_auth_signing_alg_values_supported"`
	ScopesSupported                            []string `json:"scopes_supported"`
	ResourceRegistrationEndpoint               string   `json:"resource_registration_endpoint"`
	PermissionEndpoint                         string   `json:"permission_endpoint"`
	PolicyEndpoint                             string   `json:"policy_endpoint"`
}
