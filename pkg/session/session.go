package session

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/praserx/aegis/pkg/storage"
)

const DefaultSessionTTL = 24 * time.Hour // Default session expiration time

// CookieOptions stores configuration for a session cookie.
type CookieOptions struct {
	Name     string // Name of the cookie
	Path     string // Path for the cookie, defaults to "/"
	Domain   string // Domain for the cookie, if applicable
	MaxAge   int    // MaxAge in seconds
	Secure   bool   // Indicates if the cookie should only be sent over HTTPS
	HttpOnly bool   // Prevents JavaScript access to the cookie
	SameSite string // Can be "Strict", "Lax", or "None"
}

// Session represents the structure of a session object.
type Session struct {
	sessionID     string                 `json:"-"`
	storageClient storage.Storage        `json:"-"`
	AccessToken   string                 `json:"access_token,omitempty"`
	RefreshToken  string                 `json:"refresh_token,omitempty"`
	ExpiresIn     time.Time              `json:"expires_in,omitempty"`
	IDToken       string                 `json:"id_token,omitempty"`
	Sub           string                 `json:"sub,omitempty"`
	Email         string                 `json:"email,omitempty"`
	Username      string                 `json:"username,omitempty"`
	Claims        map[string]interface{} `json:"claims,omitempty"`
	State         string                 `json:"state,omitempty"`
}

// NewSession returns a new, empty session object with default values.
func NewSession(ctx context.Context, client storage.Storage) (Session, error) {
	id, err := newUniqueSessionID(ctx, client)
	if err != nil {
		return Session{}, err
	}

	return Session{
		sessionID:     id,
		storageClient: client,
		AccessToken:   "",
		RefreshToken:  "",
		ExpiresIn:     time.Now().Add(DefaultSessionTTL), // Default expiration time
		IDToken:       "",
		Username:      "",
		Email:         "",
		Claims:        make(map[string]interface{}),
		State:         "",
	}, nil
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

// SetID sets the unique identifier for the session.
func (s *Session) SetID(id string) {
	s.sessionID = id
}

// GetID returns the unique identifier for the session.
func (s *Session) GetID() string {
	return s.sessionID
}

// Save saves the session to the storage backend.
func (s *Session) Save(ctx context.Context) error {
	if s.storageClient == nil {
		return fmt.Errorf("storage client is not set")
	}

	data, err := json.Marshal(s)
	if err != nil {
		return fmt.Errorf("failed to marshal session data: %w", err)
	}

	ok, err := s.storageClient.Exists(ctx, s.sessionID)
	if err != nil {
		return fmt.Errorf("failed to check session existence: %w", err)
	} else if ok {
		if err := s.storageClient.Update(ctx, s.sessionID, string(data)); err != nil {
			return fmt.Errorf("failed to update session data: %w", err)
		}
	} else {
		ttl := DefaultSessionTTL
		if s.ExpiresIn != (time.Time{}) {
			ttl = time.Until(s.ExpiresIn)
		}

		// If the session does not exist, create a new one.
		if err := s.storageClient.SetWithTTL(ctx, s.sessionID, string(data), ttl); err != nil {
			return fmt.Errorf("failed to create new session data: %w", err)
		}
	}

	return nil
}

// Load retrieves the session data from the storage backend using the session ID.
func (s *Session) Load(ctx context.Context, sessionID string) error {
	if s.storageClient == nil {
		return fmt.Errorf("storage client is not set")
	}

	data, err := s.storageClient.Get(ctx, sessionID)
	if err != nil {
		return fmt.Errorf("failed to retrive session from stroage: %w", err)
	}

	var sessionData Session
	err = json.Unmarshal([]byte(data), &sessionData)
	if err != nil {
		return fmt.Errorf("failed to unmarshal session data: %w", err)
	}

	s.sessionID = sessionID // Set the session ID after loading data

	s.AccessToken = sessionData.AccessToken
	s.RefreshToken = sessionData.RefreshToken
	s.ExpiresIn = sessionData.ExpiresIn
	s.IDToken = sessionData.IDToken
	s.Username = sessionData.Username
	s.Email = sessionData.Email
	s.Claims = sessionData.Claims
	s.State = sessionData.State

	return nil
}

// newUniqueSessionID generates a new unique session ID.
func newUniqueSessionID(ctx context.Context, client storage.Storage) (string, error) {
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
