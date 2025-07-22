package session

import (
	"context"
	"testing"
	"time"

	"github.com/praserx/aegis/pkg/storage"
)

func TestNewSession(t *testing.T) {
	store, err := storage.NewInMemoryStore()
	if err != nil {
		t.Fatalf("failed to create in-memory store: %v", err)
	}
	sess, err := NewSession(context.Background(), store)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if sess.GetID() == "" {
		t.Error("expected session ID to be set")
	}
	if sess.ExpiresIn.Before(time.Now()) {
		t.Error("expected ExpiresIn to be in the future")
	}
}

func TestSessionString(t *testing.T) {
	store, err := storage.NewInMemoryStore()
	if err != nil {
		t.Fatalf("failed to create in-memory store: %v", err)
	}
	sess, _ := NewSession(context.Background(), store)
	str := sess.String()
	if str == "" {
		t.Error("expected non-empty string")
	}
}

func TestIsAuthenticated(t *testing.T) {
	store, err := storage.NewInMemoryStore()
	if err != nil {
		t.Fatalf("failed to create in-memory store: %v", err)
	}
	sess, _ := NewSession(context.Background(), store)
	if sess.IsAuthenticated() {
		t.Error("expected not authenticated by default")
	}
	sess.AccessToken = "token"
	sess.ExpiresIn = time.Now().Add(1 * time.Hour)
	if !sess.IsAuthenticated() {
		t.Error("expected authenticated when token and not expired")
	}
}

func TestSetAndGetID(t *testing.T) {
	store, err := storage.NewInMemoryStore()
	if err != nil {
		t.Fatalf("failed to create in-memory store: %v", err)
	}
	sess, _ := NewSession(context.Background(), store)
	sess.SetID("custom-id")
	if sess.GetID() != "custom-id" {
		t.Errorf("expected custom-id, got %s", sess.GetID())
	}
}

func TestSessionSaveAndLoad(t *testing.T) {
	store, err := storage.NewInMemoryStore()
	if err != nil {
		t.Fatalf("failed to create in-memory store: %v", err)
	}
	sess, _ := NewSession(context.Background(), store)
	sess.AccessToken = "token"
	sess.ExpiresIn = time.Now().Add(1 * time.Hour)
	if err := sess.Save(context.Background()); err != nil {
		t.Fatalf("save failed: %v", err)
	}

	loaded, _ := NewSession(context.Background(), store)
	if err := loaded.Load(context.Background(), sess.GetID()); err != nil {
		t.Fatalf("load failed: %v", err)
	}
	if loaded.AccessToken != "token" {
		t.Errorf("expected token, got %s", loaded.AccessToken)
	}
}

func TestSessionSaveNoStorage(t *testing.T) {
	sess := Session{}
	err := sess.Save(context.Background())
	if err == nil {
		t.Error("expected error when storage client is nil")
	}
}

func TestSessionLoadNoStorage(t *testing.T) {
	sess := Session{}
	err := sess.Load(context.Background(), "id")
	if err == nil {
		t.Error("expected error when storage client is nil")
	}
}

func TestSessionLoadNotFound(t *testing.T) {
	store, err := storage.NewInMemoryStore()
	if err != nil {
		t.Fatalf("failed to create in-memory store: %v", err)
	}
	sess := Session{storageClient: store}
	err = sess.Load(context.Background(), "notfound")
	if err == nil {
		t.Error("expected error for not found session")
	}
}

func TestSessionSaveMarshalError(t *testing.T) {
	store, err := storage.NewInMemoryStore()
	if err != nil {
		t.Fatalf("failed to create in-memory store: %v", err)
	}
	sess, _ := NewSession(context.Background(), store)
	sess.Claims = map[string]interface{}{"bad": func() {}} // func is not marshalable
	err = sess.Save(context.Background())
	if err == nil {
		t.Error("expected marshal error")
	}
}
