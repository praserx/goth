package storage

import (
	"context"
	"errors"
	"time"
)

var ErrNotFound = errors.New("key not found")

// Storage defines the interface for a key-value store.
// This can be implemented by various backends like Redis or in-memory maps.
type Storage interface {
	// Get retrieves a value by key. It should return an error if the key is not found.
	Get(ctx context.Context, key string) (string, error)
	// Set stores a key-value pair.
	Set(ctx context.Context, key string, value string) error
	// SetWithTTL stores a key-value pair with a time-to-live (TTL).
	SetWithTTL(ctx context.Context, key string, value string, ttl time.Duration) error
	// Delete removes a value by key.
	Delete(ctx context.Context, key string) error
	// Exists checks if a key exists.
	Exists(ctx context.Context, key string) (bool, error)
	// Close closes the storage connection.
	Close() error
}
