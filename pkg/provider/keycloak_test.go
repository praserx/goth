package provider

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewKeycloakProvider(t *testing.T) {
	ctx := context.Background()

	t.Run("missing issuer", func(t *testing.T) {
		_, err := NewKeycloakProvider(ctx)
		assert.Error(t, err)
		assert.Equal(t, ErrMissingIssuer, err)
	})

	t.Run("missing client id", func(t *testing.T) {
		_, err := NewKeycloakProvider(ctx, WithIssuer("http://issuer"))
		assert.Error(t, err)
		assert.Equal(t, ErrMissingClientID, err)
	})

	t.Run("missing client secret", func(t *testing.T) {
		_, err := NewKeycloakProvider(ctx, WithIssuer("http://issuer"), WithClientID("client-id"))
		assert.Error(t, err)
		assert.Equal(t, ErrMissingClientSecret, err)
	})

	t.Run("missing redirect url", func(t *testing.T) {
		_, err := NewKeycloakProvider(ctx, WithIssuer("http://issuer"), WithClientID("client-id"), WithClientSecret("secret"))
		assert.Error(t, err)
		assert.Equal(t, ErrMissingRedirectURL, err)
	})

	// This test requires a running OIDC provider, so it's commented out.
	// In a real-world scenario, you would use a mock OIDC provider.
	// t.Run("success", func(t *testing.T) {
	// 	provider, err := NewKeycloakProvider(ctx,
	// 		WithIssuer("http://localhost:8080/auth/realms/test"),
	// 		WithClientID("test-client"),
	// 		WithClientSecret("secret"),
	// 		WithRedirectURL("http://localhost:8081/callback"),
	// 	)
	// 	assert.NoError(t, err)
	// 	assert.NotNil(t, provider)
	// })
}

func TestOptions(t *testing.T) {
	opts := &Options{}

	WithIssuer("issuer")(opts)
	assert.Equal(t, "issuer", opts.Issuer)

	WithClientID("client-id")(opts)
	assert.Equal(t, "client-id", opts.ClientID)

	WithClientSecret("secret")(opts)
	assert.Equal(t, "secret", opts.ClientSecret)

	WithRedirectURL("redirect")(opts)
	assert.Equal(t, "redirect", opts.RedirectURL)

	WithScopes([]string{"openid", "email"})(opts)
	assert.Equal(t, []string{"openid", "email"}, opts.Scopes)
}
