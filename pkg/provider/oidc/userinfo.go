package oidc

import (
	"encoding/json"

	"github.com/praserx/aegis/pkg/provider"
)

// UserInfo implements the provider.UserInfo interface for OIDC.
type UserInfo struct {
	rawClaims []byte
	claimsMap provider.ClaimsMap
}

func NewUserInfo(id, email, name string, claims []byte) *UserInfo {
	return &UserInfo{
		rawClaims: claims,
		claimsMap: provider.ClaimsMap{
			ID:    id,
			Email: email,
			Name:  name,
		},
	}
}

// GetID returns the user's ID from the claims.
func (u *UserInfo) GetID() string {
	var claims map[string]interface{}
	if err := json.Unmarshal(u.rawClaims, &claims); err != nil {
		return ""
	}
	id, _ := claims[u.claimsMap.ID].(string)
	return id
}

// GetEmail returns the user's email from the claims.
func (u *UserInfo) GetEmail() string {
	var claims map[string]interface{}
	if err := json.Unmarshal(u.rawClaims, &claims); err != nil {
		return ""
	}
	email, _ := claims[u.claimsMap.Email].(string)
	return email
}

// GetName returns the user's name from the claims.
func (u *UserInfo) GetName() string {
	var claims map[string]interface{}
	if err := json.Unmarshal(u.rawClaims, &claims); err != nil {
		return ""
	}
	name, _ := claims[u.claimsMap.Name].(string)
	return name
}

// GetClaims unmarshals the raw claims into the provided interface.
func (u *UserInfo) GetClaims(v interface{}) error {
	return json.Unmarshal(u.rawClaims, v)
}
