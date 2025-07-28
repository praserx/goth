package session

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/praserx/goth/pkg/storage"
)

func TestUserSession_MarshalUnmarshal(t *testing.T) {
	s := UserSession{
		AccessToken:  "token",
		RefreshToken: "refresh",
		ExpiresIn:    time.Now().Add(1 * time.Hour),
		IDToken:      "idtoken",
		Sub:          "sub",
		Email:        "user@example.com",
		Username:     "user",
		Claims:       map[string]interface{}{"role": "admin"},
	}
	data, err := json.Marshal(s)
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}
	var s2 UserSession
	if err := json.Unmarshal(data, &s2); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}
	if s2.AccessToken != s.AccessToken || s2.Email != s.Email {
		t.Errorf("unmarshal mismatch: got %+v, want %+v", s2, s)
	}
}

func TestUserSession_IsAuthenticated(t *testing.T) {
	s := UserSession{AccessToken: "a", ExpiresIn: time.Now().Add(1 * time.Hour)}
	if !s.IsAuthenticated() {
		t.Error("expected authenticated")
	}
	s2 := UserSession{AccessToken: "", ExpiresIn: time.Now().Add(1 * time.Hour)}
	if s2.IsAuthenticated() {
		t.Error("expected not authenticated (no token)")
	}
	s3 := UserSession{AccessToken: "a", ExpiresIn: time.Now().Add(-1 * time.Hour)}
	if s3.IsAuthenticated() {
		t.Error("expected not authenticated (expired)")
	}
}

func TestAuthSession_MarshalUnmarshal(t *testing.T) {
	s := AuthSession{State: "state", OrigURL: nil}
	data, err := json.Marshal(s)
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}
	var s2 AuthSession
	if err := json.Unmarshal(data, &s2); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}
	if s2.State != s.State {
		t.Errorf("unmarshal mismatch: got %+v, want %+v", s2, s)
	}
}

func TestSessionIDGeneration(t *testing.T) {
	store, err := storage.NewInMemoryStore()
	if err != nil {
		t.Fatalf("failed to create in-memory store: %v", err)
	}
	ctx := context.Background()
	id, err := NewAuthSessionID(ctx, store)
	if err != nil || id == "" {
		t.Fatalf("failed to generate auth session id: %v", err)
	}
	id2, err := NewUserSessionID(ctx, store)
	if err != nil || id2 == "" {
		t.Fatalf("failed to generate user session id: %v", err)
	}
	if id == id2 {
		t.Error("expected unique session ids")
	}
}

func TestSessionStorageRoundTrip(t *testing.T) {
	store, err := storage.NewInMemoryStore()
	if err != nil {
		t.Fatalf("failed to create in-memory store: %v", err)
	}
	ctx := context.Background()
	usid, _ := NewUserSessionID(ctx, store)
	sess := UserSession{AccessToken: "tok", ExpiresIn: time.Now().Add(1 * time.Hour)}
	if err := SetUserSession(ctx, store, usid, sess); err != nil {
		t.Fatalf("set user session failed: %v", err)
	}
	got, err := GetUserSession(ctx, store, usid)
	if err != nil {
		t.Fatalf("get user session failed: %v", err)
	}
	if got.AccessToken != sess.AccessToken {
		t.Errorf("got %+v, want %+v", got, sess)
	}
}
