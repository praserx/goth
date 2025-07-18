package resolver

import (
	"context"
	"net/http"

	"github.com/praserx/aegis/pkg/resolver/uma"
	"github.com/praserx/aegis/pkg/session"
)

// AuthorizationResolver defines the interface for checking access rights.
type AuthorizationResolver interface {
	CheckAccess(ctx context.Context, s session.Session, req *http.Request) (bool, error)
}

// NewUMAAuthorizationResolver creates a new resolver for Keycloak fine-grained policies.
func NewUMAAuthorizationResolver(config uma.KeycloakUMAConfig) *uma.AuthorizationResolver {
	return &uma.AuthorizationResolver{
		Config:     config,
		HttpClient: &http.Client{},
	}
}
