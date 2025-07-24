package session

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"time"

	"github.com/google/uuid"
	"github.com/praserx/goth/pkg/storage"
)

// SessionContextKey is the key used to store session data in the request context.
type sessionContextKey string

const UserSessionContextKey = sessionContextKey("user_session")
const AuthSessionContextKey = sessionContextKey("auth_session")

const DefaultSessionTTL = 24 * time.Hour // Default session expiration time
const AuthSessionTTL = 5 * time.Minute   // Short term authentication session expiration time

// UserSession represents the structure of a user session object.
type UserSession struct {
	AccessToken  string                 `json:"access_token,omitempty"`
	RefreshToken string                 `json:"refresh_token,omitempty"`
	ExpiresIn    time.Time              `json:"expires_in,omitempty"`
	IDToken      string                 `json:"id_token,omitempty"`
	Sub          string                 `json:"sub,omitempty"`
	Email        string                 `json:"email,omitempty"`
	Username     string                 `json:"username,omitempty"`
	Claims       map[string]interface{} `json:"claims,omitempty"`
}

// String returns the JSON string representation of the UserSession.
func (s *UserSession) String() string {
	data, _ := json.Marshal(s)
	return string(data)
}

// IsAuthenticated checks if the session is authenticated.
// A session is considered authenticated if the access token is not empty and
// the session has not expired.
func (s *UserSession) IsAuthenticated() bool {
	return s.AccessToken != "" && s.ExpiresIn.After(time.Now())
}

// GetUserSession retrieves a user session from the storage backend using the session ID.
func GetUserSession(ctx context.Context, client storage.Storage, sid string) (*UserSession, error) {
	var userSession UserSession
	if err := getSessionFromStorage(ctx, client, usid(sid), &userSession); err != nil {
		return nil, err
	}
	return &userSession, nil
}

// SetUserSession saves a user session to the storage backend using the session ID.
func SetUserSession(ctx context.Context, client storage.Storage, sid string, us UserSession) error {
	if client == nil {
		return fmt.Errorf("storage client is not set")
	}

	data, err := json.Marshal(us)
	if err != nil {
		return fmt.Errorf("failed to marshal session data: %w", err)
	}

	var ttl time.Duration
	if us.ExpiresIn.Equal(time.Time{}) {
		us.ExpiresIn = time.Now().Add(DefaultSessionTTL) // Set default expiration if not set
		ttl = DefaultSessionTTL
	} else {
		ttl = time.Until(us.ExpiresIn)
	}

	if err := client.SetWithTTL(ctx, usid(sid), string(data), ttl); err != nil {
		return fmt.Errorf("failed to set session in storage: %w", err)
	}

	return nil
}

// UpdateUserSession updates an existing user session in the storage backend.
func UpdateUserSession(ctx context.Context, client storage.Storage, sid string, us UserSession) error {
	if client == nil {
		return fmt.Errorf("storage client is not set")
	}

	data, err := json.Marshal(us)
	if err != nil {
		return fmt.Errorf("failed to marshal session data: %w", err)
	}

	if err := client.Update(ctx, usid(sid), string(data)); err != nil {
		return fmt.Errorf("failed to update session in storage: %w", err)
	}

	return nil
}

// AuthSession represents a short term authentication session flash entry.
type AuthSession struct {
	State   string   `json:"state,omitempty"`
	OrigURL *url.URL `json:"orig_url,omitempty"`
}

// String returns the JSON string representation of the AuthSession.
func (s *AuthSession) String() string {
	data, _ := json.Marshal(s)
	return string(data)
}

// GetAuthSession retrieves an authentication session from the storage backend using the session ID.
func GetAuthSession(ctx context.Context, client storage.Storage, sid string) (*AuthSession, error) {
	var authSession AuthSession
	if err := getSessionFromStorage(ctx, client, asid(sid), &authSession); err != nil {
		return nil, err
	}
	return &authSession, nil
}

// SetAuthSession saves an authentication session to the storage backend using the session ID.
func SetAuthSession(ctx context.Context, client storage.Storage, sid string, as AuthSession) error {
	if client == nil {
		return fmt.Errorf("storage client is not set")
	}

	data, err := json.Marshal(as)
	if err != nil {
		return fmt.Errorf("failed to marshal session data: %w", err)
	}

	if err := client.SetWithTTL(ctx, asid(sid), string(data), AuthSessionTTL); err != nil {
		return fmt.Errorf("failed to set session in storage: %w", err)
	}

	return nil
}

// NewAuthSessionID generates a new unique session ID for authentication sessions.
func NewAuthSessionID(ctx context.Context, client storage.Storage) (string, error) {
	newSessionID, err := getSessionID(ctx, client)
	if err != nil {
		return "", fmt.Errorf("failed to create new auth session id: %w", err)
	}
	return newSessionID, nil
}

// NewUserSessionID generates a new unique session ID for user sessions.
func NewUserSessionID(ctx context.Context, client storage.Storage) (string, error) {
	newSessionID, err := getSessionID(ctx, client)
	if err != nil {
		return "", fmt.Errorf("failed to create new user session id: %w", err)
	}
	return newSessionID, nil
}

// getSessionID generates a new unique session ID.
func getSessionID(ctx context.Context, client storage.Storage) (string, error) {
	for i := 0; i < 10; i++ {
		newSessionID := uuid.New().String()
		if ok, err := client.Exists(ctx, newSessionID); err != nil {
			return "", fmt.Errorf("failed to check session existence: %w", err)
		} else if !ok {
			return newSessionID, nil // Return the new session ID if it does not exist
		}
	}

	return "", fmt.Errorf("failed to create a new unique session id after multiple attempts")
}

// getSessionFromStorage is a helper to load and unmarshal a session from storage.
func getSessionFromStorage(ctx context.Context, client storage.Storage, sid string, target interface{}) error {
	if client == nil {
		return fmt.Errorf("storage client is not set")
	}

	data, err := client.Get(ctx, sid)
	if err != nil {
		return fmt.Errorf("failed to retrieve session from storage: %w", err)
	}

	if err := json.Unmarshal([]byte(data), target); err != nil {
		return fmt.Errorf("failed to unmarshal session data: %w", err)
	}

	return nil
}

// Utility functions to format session IDs for user sessions.
func usid(sid string) string {
	return fmt.Sprintf("US-%s", sid)
}

// Utility function to format session IDs for auth sessions.
func asid(sid string) string {
	return fmt.Sprintf("AS-%s", sid)
}
