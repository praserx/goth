package storage

import (
	"context"
	"testing"
	"time"

	"github.com/go-redis/redis/v8"
	"github.com/go-redis/redismock/v8"
	"github.com/stretchr/testify/assert"
)

func TestRedisStorage(t *testing.T) {
	db, mock := redismock.NewClientMock()

	storage, err := NewRedisStore("", WithClient(db))
	assert.NoError(t, err)
	defer storage.Close()

	ctx := context.Background()
	key := "test_key"
	value := "test_value"
	ttl := 5 * time.Second

	// Test SetWithTTL
	mock.ExpectSet(key, value, ttl).SetVal("OK")
	err = storage.SetWithTTL(ctx, key, value, ttl)
	assert.NoError(t, err)

	// Test Get
	mock.ExpectGet(key).SetVal(value)
	retrievedValue, err := storage.Get(ctx, key)
	assert.NoError(t, err)
	assert.Equal(t, value, retrievedValue)

	// Test Exists - true
	mock.ExpectExists(key).SetVal(1)
	exists, err := storage.Exists(ctx, key)
	assert.NoError(t, err)
	assert.True(t, exists)

	// Test Delete
	mock.ExpectDel(key).SetVal(1)
	err = storage.Delete(ctx, key)
	assert.NoError(t, err)

	// Test Exists - false
	mock.ExpectExists(key).SetVal(0)
	exists, err = storage.Exists(ctx, key)
	assert.NoError(t, err)
	assert.False(t, exists)

	// Test Get after Delete
	mock.ExpectGet(key).SetErr(redis.Nil)
	_, err = storage.Get(ctx, key)
	assert.Error(t, err)
	assert.Equal(t, redis.Nil, err)

	// Test Set (no TTL)
	mock.ExpectSet(key, value, 0).SetVal("OK")
	err = storage.Set(ctx, key, value)
	assert.NoError(t, err)

	// Verify all expectations were met
	assert.NoError(t, mock.ExpectationsWereMet())
}
