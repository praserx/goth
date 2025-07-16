package session

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/praserx/aegis/pkg/storage"
)

// Manager manages session storage and serialization.
type Manager struct {
	store storage.Storage
}

// ManagerOptions holds options for creating a new session manager.
type ManagerOptions struct {
	Storage storage.Storage
}

// NewManager creates a new session manager with the provided options.
func NewManager(options ...func(*ManagerOptions)) (*Manager, error) {
	opts := &ManagerOptions{}

	for _, opt := range options {
		opt(opts)
	}

	// If no storage is provided, use an in-memory store by default.
	if opts.Storage == nil {
		store, err := storage.NewInMemoryStore()
		if err != nil {
			return nil, fmt.Errorf("failed to create default in-memory session store: %w", err)
		}
		opts.Storage = store
	}

	manager := &Manager{
		store: opts.Storage,
	}

	return manager, nil
}

// WithStorage provides a storage backend for the session manager.
func WithStorage(storage storage.Storage) func(*ManagerOptions) {
	return func(o *ManagerOptions) {
		o.Storage = storage
	}
}

// GetStorage returns the storage backend used by the session manager.
func (m *Manager) GetStorage() storage.Storage {
	return m.store
}

// Exists checks if a session with the given ID exists in the storage.
func (m *Manager) Exists(ctx context.Context, id string) (bool, error) {
	exists, err := m.store.Exists(ctx, id)
	if err != nil {
		return false, fmt.Errorf("storage exists check error: %w", err)
	}
	return exists, nil
}

// Set stores a session by its ID, handling serialization.
func (m *Manager) Set(ctx context.Context, id string, session Session) error {
	data, err := json.Marshal(session)
	if err != nil {
		return fmt.Errorf("session marshal error: %w", err)
	}

	if err := m.store.Set(ctx, id, string(data)); err != nil {
		return fmt.Errorf("storage set error: %w", err)
	}

	return nil
}

// SetWithTTL stores a session by its ID with a time-to-live (TTL), handling serialization.
func (m *Manager) SetWithTTL(ctx context.Context, id string, session Session, ttl time.Duration) error {
	data, err := json.Marshal(session)
	if err != nil {
		return fmt.Errorf("session marshal error: %w", err)
	}

	if err := m.store.SetWithTTL(ctx, id, string(data), ttl); err != nil {
		return fmt.Errorf("storage set with TTL error: %w", err)
	}

	return nil
}

// Get retrieves a session by its ID, handling deserialization.
func (m *Manager) Get(ctx context.Context, id string) (Session, bool, error) {
	if id == "" {
		return Session{}, false, nil
	}

	exists, err := m.store.Exists(ctx, id)
	if err != nil {
		return Session{}, false, fmt.Errorf("storage exists check error: %w", err)
	}
	if !exists {
		return Session{}, false, nil
	}

	var session Session
	value, err := m.store.Get(ctx, id)
	if err != nil {
		return Session{}, false, fmt.Errorf("storage get error: %w", err)
	}

	if err := json.Unmarshal([]byte(value), &session); err != nil {
		return Session{}, false, fmt.Errorf("session unmarshal error: %w", err)
	}

	return session, true, nil
}
