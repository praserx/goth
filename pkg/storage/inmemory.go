package storage

import (
	"context"
	"errors"
	"fmt"
	"time"

	ac "github.com/praserx/atomic-cache/v2"
)

// InMemoryStore implements the storage.Storage interface using an in-memory cache.
type InMemoryStore struct {
	client *ac.AtomicCache
}

// New creates a new InMemoryStore instance.
// It initializes a cache with a default expiration and cleanup interval.
func NewInMemoryStore() (*InMemoryStore, error) {
	var _ Storage = &InMemoryStore{} // Ensure InMemoryStore implements Storage interface
	c := ac.New(ac.OptionMaxRecords(512))
	return &InMemoryStore{client: c}, nil
}

// Get retrieves a value by key from the in-memory cache.
func (s *InMemoryStore) Get(_ context.Context, key string) (string, error) {
	val, err := s.client.Get(key)
	if errors.Is(err, ac.ErrNotFound) {
		return "", fmt.Errorf("key not found in cache: %s", key)
	}

	return string(val), nil
}

// Set stores a key-value pair in the cache with no expiration.
func (s *InMemoryStore) Set(_ context.Context, key string, value string) error {
	err := s.client.Set(key, []byte(value), 30*time.Minute) // Default expiration of 30 minutes
	if err != nil {
		return fmt.Errorf("failed to set key in cache: %w", err)
	}

	return nil
}

// SetWithTTL stores a key-value pair in the cache with a specified time-to-live (TTL).
func (s *InMemoryStore) SetWithTTL(_ context.Context, key string, value string, ttl time.Duration) error {
	s.client.Set(key, []byte(value), ttl)
	return nil
}

func (s *InMemoryStore) Update(_ context.Context, key string, value string) error {
	// In-memory cache does not have a specific update operation; SetWithTTL can be used to update the value.
	err := s.SetWithTTL(context.Background(), key, value, ac.KeepTTL)
	if err != nil {
		return fmt.Errorf("failed to update key in cache: %w", err)
	}
	return nil
}

// Delete removes a key from the cache.
func (s *InMemoryStore) Delete(_ context.Context, key string) error {
	if err := s.client.Delete(key); err != nil {
		return fmt.Errorf("failed to delete key from cache: %w", err)
	}
	return nil
}

// Exists checks if a key exists in the cache.
func (s *InMemoryStore) Exists(_ context.Context, key string) (bool, error) {
	return s.client.Exists(key), nil
}

// Close is a no-op for the in-memory store as there is.
func (s *InMemoryStore) Close() error {
	return nil
}
