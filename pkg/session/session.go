package session

import (
	"encoding/json"
	"time"
)

const DefaultSessionTTL = 24 * time.Hour // Default session expiration time

// CookieOptions stores configuration for a session cookie.
type CookieOptions struct {
	Name     string
	Path     string
	Domain   string
	MaxAge   int
	Secure   bool
	HttpOnly bool
	SameSite string // Can be "Strict", "Lax", or "None"
}

// Session represents the structure of a session object.
type Session struct {
	AccessToken  string                 `json:"access_token,omitempty"`
	RefreshToken string                 `json:"refresh_token,omitempty"`
	ExpiresIn    time.Time              `json:"expires_in,omitempty"`
	IDToken      string                 `json:"id_token,omitempty"`
	Username     string                 `json:"username,omitempty"`
	Email        string                 `json:"email,omitempty"`
	Claims       map[string]interface{} `json:"claims,omitempty"`
	State        string                 `json:"state,omitempty"`
}

// Empty returns a new, empty session object with default values.
func Empty() Session {
	return Session{
		AccessToken:  "",
		RefreshToken: "",
		ExpiresIn:    time.Now().Add(DefaultSessionTTL), // Default expiration time
		IDToken:      "",
		Username:     "",
		Email:        "",
		Claims:       make(map[string]interface{}),
		State:        "",
	}
}

// String returns the JSON string representation of the session.
func (s *Session) String() string {
	data, _ := json.Marshal(s)
	return string(data)
}

// IsAuthenticated checks if the session is authenticated.
// A session is considered authenticated if the access token is not empty and
// the session has not expired.
func (s *Session) IsAuthenticated() bool {
	return s.AccessToken != "" && s.ExpiresIn.After(time.Now())
}
