package middleware

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"golang.org/x/oauth2"

	"github.com/praserx/goth/pkg/provider"
	"github.com/praserx/goth/pkg/session"
	"github.com/praserx/goth/pkg/storage"
)

const testAuthURL = "/auth"

type dummyProvider struct{}

func (d *dummyProvider) AuthorizeAnonymousRequest(ctx context.Context, r *http.Request) (bool, error) {
	return false, nil
}
func (d *dummyProvider) GetAuthURL(state string) string { return testAuthURL }
func (d *dummyProvider) AuthorizeRequest(ctx context.Context, r *http.Request, accessToken string) (bool, error) {
	return false, nil
}
func (d *dummyProvider) Exchange(ctx context.Context, code string) (*oauth2.Token, error) {
	return &oauth2.Token{}, nil
}
func (d *dummyProvider) GetUserInfo(ctx context.Context, token *oauth2.Token) (provider.UserInfo, error) {
	return nil, nil
}

func TestAuthorizationMiddleware_ProviderNil(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	rw := httptest.NewRecorder()
	mw := AuthorizationMiddleware(nil, nil, session.CookieOptions{SessionCookieName: "sid"})
	h := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}))
	h.ServeHTTP(rw, req)
	if rw.Code != http.StatusInternalServerError {
		t.Errorf("expected 500, got %d", rw.Code)
	}
}

func TestAuthorizationMiddleware_SessionCookieError(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	rw := httptest.NewRecorder()
	c, _ := storage.NewInMemoryStore()
	// Simulate error by using a cookie name that will not be present
	mw := AuthorizationMiddleware(&dummyProvider{}, c, session.CookieOptions{SessionCookieName: "sid"})
	h := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}))
	h.ServeHTTP(rw, req)
	// Debug output
	println("TestAuthorizationMiddleware_SessionCookieError: code=", rw.Code, " location=", rw.Header().Get("Location"))
	if rw.Code != http.StatusFound && rw.Code != http.StatusUnauthorized && rw.Code != http.StatusInternalServerError {
		t.Errorf("unexpected status code: %d", rw.Code)
	}
}

func TestAuthorizationMiddleware_AnonymousAllowed(t *testing.T) {
	p := &dummyProviderAllow{}
	req := httptest.NewRequest("GET", "/", nil)
	rw := httptest.NewRecorder()
	mw := AuthorizationMiddleware(p, nil, session.CookieOptions{SessionCookieName: "sid"})
	h := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}))
	h.ServeHTTP(rw, req)
	if rw.Code != 200 {
		t.Errorf("expected 200, got %d", rw.Code)
	}
}

type dummyProviderAllow struct{}

func (d *dummyProviderAllow) AuthorizeAnonymousRequest(ctx context.Context, r *http.Request) (bool, error) {
	return true, nil
}
func (d *dummyProviderAllow) GetAuthURL(state string) string { return testAuthURL }
func (d *dummyProviderAllow) AuthorizeRequest(ctx context.Context, r *http.Request, accessToken string) (bool, error) {
	return true, nil
}
func (d *dummyProviderAllow) Exchange(ctx context.Context, code string) (*oauth2.Token, error) {
	return &oauth2.Token{}, nil
}
func (d *dummyProviderAllow) GetUserInfo(ctx context.Context, token *oauth2.Token) (provider.UserInfo, error) {
	return nil, nil
}

func TestAuthorizationMiddleware_AnonymousDenied(t *testing.T) {
	p := &dummyProviderDeny{}
	req := httptest.NewRequest("GET", "/", nil)
	rw := httptest.NewRecorder()
	c, _ := storage.NewInMemoryStore()
	mw := AuthorizationMiddleware(p, c, session.CookieOptions{SessionCookieName: "sid"})
	h := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}))
	h.ServeHTTP(rw, req)
	if rw.Code != http.StatusFound {
		t.Errorf("expected redirect (302), got %d", rw.Code)
	}
}

type dummyProviderDeny struct{}

func (d *dummyProviderDeny) AuthorizeAnonymousRequest(ctx context.Context, r *http.Request) (bool, error) {
	return false, nil
}
func (d *dummyProviderDeny) GetAuthURL(state string) string { return testAuthURL }
func (d *dummyProviderDeny) AuthorizeRequest(ctx context.Context, r *http.Request, accessToken string) (bool, error) {
	return false, nil
}
func (d *dummyProviderDeny) Exchange(ctx context.Context, code string) (*oauth2.Token, error) {
	return &oauth2.Token{}, nil
}
func (d *dummyProviderDeny) GetUserInfo(ctx context.Context, token *oauth2.Token) (provider.UserInfo, error) {
	return nil, nil
}

// --- Proxy-Authorization header tests ---
type dummyProviderProxyAuth struct {
	allow    bool
	authzErr error
}

func (d *dummyProviderProxyAuth) AuthorizeRequest(_ context.Context, _ *http.Request, token string) (bool, error) {
	if d.authzErr != nil {
		return false, d.authzErr
	}
	if token == "valid-token" {
		return d.allow, nil
	}
	return false, nil
}
func (d *dummyProviderProxyAuth) AuthorizeAnonymousRequest(_ context.Context, _ *http.Request) (bool, error) {
	return false, nil
}
func (d *dummyProviderProxyAuth) GetAuthURL(_ string) string { return "/auth" }
func (d *dummyProviderProxyAuth) Exchange(_ context.Context, _ string) (*oauth2.Token, error) {
	return &oauth2.Token{}, nil
}
func (d *dummyProviderProxyAuth) GetUserInfo(_ context.Context, _ *oauth2.Token) (provider.UserInfo, error) {
	return nil, nil
}

func TestHandleAuthorization_ProxyAuthorizationHeader_Allowed(t *testing.T) {
	prov := &dummyProviderProxyAuth{allow: true}
	store, _ := storage.NewInMemoryStore()
	opts := session.CookieOptions{SessionCookieName: "sid"}

	r := httptest.NewRequest("GET", "/protected", nil)
	r.Header.Set("Proxy-Authorization", "Bearer valid-token")
	rw := httptest.NewRecorder()

	handled := handleAuthorization(rw, r, prov, store, opts)
	if handled {
		t.Errorf("should not handle response if authorized via Proxy-Authorization header")
	}
	if rw.Code != 200 {
		t.Errorf("expected 200, got %d", rw.Code)
	}
}

func TestHandleAuthorization_ProxyAuthorizationHeader_Denied(t *testing.T) {
	prov := &dummyProviderProxyAuth{allow: false}
	store, _ := storage.NewInMemoryStore()
	opts := session.CookieOptions{SessionCookieName: "sid"}

	r := httptest.NewRequest("GET", "/protected", nil)
	r.Header.Set("Proxy-Authorization", "Bearer valid-token")
	rw := httptest.NewRecorder()

	handled := handleAuthorization(rw, r, prov, store, opts)
	if !handled {
		t.Errorf("should handle response if denied via Proxy-Authorization header")
	}
	if rw.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d", rw.Code)
	}
}

func TestHandleAuthorization_ProxyAuthorizationHeader_Error(t *testing.T) {
	prov := &dummyProviderProxyAuth{allow: false, authzErr: errors.New("fail")}
	store, _ := storage.NewInMemoryStore()
	opts := session.CookieOptions{SessionCookieName: "sid"}

	r := httptest.NewRequest("GET", "/protected", nil)
	r.Header.Set("Proxy-Authorization", "Bearer valid-token")
	rw := httptest.NewRecorder()

	handled := handleAuthorization(rw, r, prov, store, opts)
	if !handled {
		t.Errorf("should handle response if error from provider")
	}
	if rw.Code != http.StatusInternalServerError {
		t.Errorf("expected 500, got %d", rw.Code)
	}
}
