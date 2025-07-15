package session

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

// MockStorage is a mock implementation of the storage.Storage interface.
type MockStorage struct {
	mock.Mock
}

func (m *MockStorage) Get(ctx context.Context, key string) (string, error) {
	args := m.Called(ctx, key)
	return args.String(0), args.Error(1)
}

func (m *MockStorage) Set(ctx context.Context, key string, value string) error {
	args := m.Called(ctx, key, value)
	return args.Error(0)
}

func (m *MockStorage) SetWithTTL(ctx context.Context, key string, value string, ttl time.Duration) error {
	args := m.Called(ctx, key, value, ttl)
	return args.Error(0)
}

func (m *MockStorage) Delete(ctx context.Context, key string) error {
	args := m.Called(ctx, key)
	return args.Error(0)
}

func (m *MockStorage) Exists(ctx context.Context, key string) (bool, error) {
	args := m.Called(ctx, key)
	return args.Bool(0), args.Error(1)
}

func (m *MockStorage) Close() error {
	args := m.Called()
	return args.Error(0)
}

func TestNewManager(t *testing.T) {
	t.Run("with default in-memory storage", func(t *testing.T) {
		manager, err := NewManager()
		assert.NoError(t, err)
		assert.NotNil(t, manager)
		assert.NotNil(t, manager.Store)
	})

	t.Run("with provided storage", func(t *testing.T) {
		mockStore := new(MockStorage)
		manager, err := NewManager(WithStorage(mockStore))
		assert.NoError(t, err)
		assert.NotNil(t, manager)
		assert.Equal(t, mockStore, manager.Store)
	})
}

func TestManager_Set(t *testing.T) {
	mockStore := new(MockStorage)
	manager, _ := NewManager(WithStorage(mockStore))
	ctx := context.Background()
	session := Session{AccessToken: "abc", RefreshToken: "def", IDToken: "ghi"}
	sessionJSON := `{"access_token":"abc","refresh_token":"def","id_token":"ghi"}`

	t.Run("success", func(t *testing.T) {
		mockStore.On("Set", ctx, "123", sessionJSON).Return(nil).Once()
		err := manager.Set(ctx, "123", session)
		assert.NoError(t, err)
		mockStore.AssertExpectations(t)
	})

	t.Run("storage set error", func(t *testing.T) {
		expectedErr := errors.New("storage error")
		mockStore.On("Set", ctx, "123", sessionJSON).Return(expectedErr).Once()
		err := manager.Set(ctx, "123", session)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "storage set error")
		mockStore.AssertExpectations(t)
	})
}

func TestManager_Get(t *testing.T) {
	mockStore := new(MockStorage)
	manager, _ := NewManager(WithStorage(mockStore))
	ctx := context.Background()
	sessionID := "123"
	sessionJSON := `{"access_token":"abc","refresh_token":"def","id_token":"ghi"}`

	t.Run("success", func(t *testing.T) {
		mockStore.On("Exists", ctx, sessionID).Return(true, nil).Once()
		mockStore.On("Get", ctx, sessionID).Return(sessionJSON, nil).Once()

		session, found, err := manager.Get(ctx, sessionID)
		assert.NoError(t, err)
		assert.True(t, found)
		assert.Equal(t, "abc", session.AccessToken)
		assert.Equal(t, "def", session.RefreshToken)
		assert.Equal(t, "ghi", session.IDToken)
		mockStore.AssertExpectations(t)
	})

	t.Run("not found", func(t *testing.T) {
		mockStore.On("Exists", ctx, sessionID).Return(false, nil).Once()
		_, found, err := manager.Get(ctx, sessionID)
		assert.NoError(t, err)
		assert.False(t, found)
		mockStore.AssertExpectations(t)
	})

	t.Run("exists check error", func(t *testing.T) {
		expectedErr := errors.New("exists error")
		mockStore.On("Exists", ctx, sessionID).Return(false, expectedErr).Once()
		_, _, err := manager.Get(ctx, sessionID)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "storage exists check error")
		mockStore.AssertExpectations(t)
	})

	t.Run("storage get error", func(t *testing.T) {
		expectedErr := errors.New("get error")
		mockStore.On("Exists", ctx, sessionID).Return(true, nil).Once()
		mockStore.On("Get", ctx, sessionID).Return("", expectedErr).Once()
		_, _, err := manager.Get(ctx, sessionID)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "storage get error")
		mockStore.AssertExpectations(t)
	})

	t.Run("unmarshal error", func(t *testing.T) {
		mockStore.On("Exists", ctx, sessionID).Return(true, nil).Once()
		mockStore.On("Get", ctx, sessionID).Return("invalid json", nil).Once()
		_, _, err := manager.Get(ctx, sessionID)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "session unmarshal error")
		mockStore.AssertExpectations(t)
	})
}
