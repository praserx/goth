package storage

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestInMemoryStore(t *testing.T) {
	ctx := context.Background()

	// Test case 1: Basic Set, Get, Exists, and Delete
	t.Run("should set and get a value", func(t *testing.T) {
		store, err := NewInMemoryStore()
		assert.NoError(t, err)

		key := "test-key"
		value := "test-value"

		// Set value
		err = store.Set(ctx, key, value)
		assert.NoError(t, err)

		// Check if exists
		exists, err := store.Exists(ctx, key)
		assert.NoError(t, err)
		assert.True(t, exists)

		// Get value
		retrievedValue, err := store.Get(ctx, key)
		assert.NoError(t, err)
		assert.Equal(t, value, retrievedValue)

		// Delete value
		err = store.Delete(ctx, key)
		assert.NoError(t, err)

		time.Sleep(1 * time.Second)

		// Verify it's deleted
		exists, err = store.Exists(ctx, key)
		assert.NoError(t, err)
		assert.False(t, exists)
	})

	// Test case 2: Get a non-existent key
	t.Run("should return not found for non-existent key", func(t *testing.T) {
		store, err := NewInMemoryStore()
		assert.NoError(t, err)

		// Get non-existent key
		_, err = store.Get(ctx, "non-existent-key")
		assert.Error(t, err) // Assuming Get returns an error for non-existent keys

		// Check Exists for non-existent key
		exists, err := store.Exists(ctx, "non-existent-key")
		assert.NoError(t, err)
		assert.False(t, exists)
	})

	// Test case 3: TTL expiration
	t.Run("should expire a key after its TTL", func(t *testing.T) {
		// Use a custom store with a very short default expiration for the test
		store, err := NewInMemoryStore()
		assert.NoError(t, err)

		key := "ttl-key"
		value := "ttl-value"

		// Set value with a short TTL
		err = store.SetWithTTL(ctx, key, value, 10*time.Millisecond)
		assert.NoError(t, err)

		// Check it exists immediately
		exists, err := store.Exists(ctx, key)
		assert.NoError(t, err)
		assert.True(t, exists)

		// Wait for the key to expire
		time.Sleep(100 * time.Millisecond)

		// Check that the key has expired
		exists, err = store.Exists(ctx, key)
		assert.NoError(t, err)
		assert.False(t, exists)
	})
}
