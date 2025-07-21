package storage

import (
	"context"
	"fmt"
	"time"

	"github.com/go-redis/redis/v8"
)

// RedisStore implements the storage.Storage interface using Redis as the backend.
type RedisStore struct {
	client *redis.Client
	// close is a function that closes the client. It's a no-op if the client
	// was provided externally.
	close func() error
}

// Option is a functional option for configuring the RedisStore.
type RedisOption func(*RedisStore) error

// WithClient allows providing an existing redis client.
// The provided client will not be closed when Close() is called.
func WithClient(client *redis.Client) RedisOption {
	return func(s *RedisStore) error {
		s.client = client
		s.close = func() error { return nil } // Do not close externally managed client.
		return nil
	}
}

// New creates a new RedisStore instance and connects to the Redis server.
// It takes a Redis connection URL (e.g., "redis://user:password@localhost:6379/0")
// or functional options.
func NewRedisStore(url string, opts ...RedisOption) (*RedisStore, error) {
	var _ Storage = &RedisStore{} // Ensure RedisStore implements Storage interface

	s := &RedisStore{}

	// Apply functional options first. If a client is provided, we use it.
	for _, opt := range opts {
		if err := opt(s); err != nil {
			return nil, err
		}
	}

	// If no client was provided via options, create a new one from the URL.
	if s.client == nil {
		if url == "" {
			return nil, fmt.Errorf("redis URL or client must be provided")
		}
		o, err := redis.ParseURL(url)
		if err != nil {
			return nil, fmt.Errorf("failed to parse redis URL: %w", err)
		}
		client := redis.NewClient(o)
		if err := client.Ping(context.Background()).Err(); err != nil {
			return nil, fmt.Errorf("failed to connect to redis: %w", err)
		}
		s.client = client
		s.close = s.client.Close // Set the close function.
	}

	return s, nil
}

// Get retrieves a value by key from Redis.
func (s *RedisStore) Get(ctx context.Context, key string) (string, error) {
	return s.client.Get(ctx, key).Result()
}

// Set stores a key-value pair in Redis with no expiration.
func (s *RedisStore) Set(ctx context.Context, key string, value string) error {
	return s.client.Set(ctx, key, value, 0).Err()
}

// SetWithTTL stores a key-value pair in Redis with a specified time-to-live (TTL).
func (s *RedisStore) SetWithTTL(ctx context.Context, key string, value string, ttl time.Duration) error {
	return s.client.Set(ctx, key, value, ttl).Err()
}

// Delete removes a key from Redis.
func (s *RedisStore) Delete(ctx context.Context, key string) error {
	return s.client.Del(ctx, key).Err()
}

// Exists checks if a key exists in Redis.
func (s *RedisStore) Exists(ctx context.Context, key string) (bool, error) {
	val, err := s.client.Exists(ctx, key).Result()
	if err != nil {
		return false, err
	}
	return val == 1, nil
}

// Close closes the connection to the Redis server.
func (s *RedisStore) Close() error {
	if s.close == nil {
		return nil
	}
	return s.close()
}
