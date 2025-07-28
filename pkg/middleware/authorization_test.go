package middleware

import (
	"context"
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
