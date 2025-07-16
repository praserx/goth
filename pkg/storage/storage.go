package storage

import (
	"context"
	"errors"
	"time"

	"github.com/praserx/aegis/pkg/storage/inmemory"
	"github.com/praserx/aegis/pkg/storage/redis"
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

// NewRedisStore creates a new Redis storage instance.
func NewRedisStore(ctx context.Context, url string) (Storage, error) {
	var _ Storage = &redis.RedisStore{} // Ensure RedisStore implements Storage interface
	return redis.New(url)
}

// NewInMemoryStore creates a new in-memory storage instance.
func NewInMemoryStore() (Storage, error) {
	var _ Storage = &inmemory.InMemoryStore{} // Ensure InMemoryStore implements Storage interface
	return inmemory.New()
}
