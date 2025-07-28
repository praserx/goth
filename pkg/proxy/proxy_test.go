package proxy

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"golang.org/x/oauth2"

	"github.com/praserx/goth/pkg/provider"
	"github.com/praserx/goth/pkg/session"
)

// dummyProvider for test
type dummyProvider struct{}

func (d *dummyProvider) GetAuthURL(state string) string { return "/auth" }
func (d *dummyProvider) Exchange(ctx context.Context, code string) (*oauth2.Token, error) {
	return &oauth2.Token{}, nil
}
func (d *dummyProvider) GetUserInfo(ctx context.Context, token *oauth2.Token) (provider.UserInfo, error) {
	return nil, nil
}
func (d *dummyProvider) AuthorizeAnonymousRequest(ctx context.Context, req *http.Request) (bool, error) {
	return true, nil
}
func (d *dummyProvider) AuthorizeRequest(ctx context.Context, req *http.Request, accessToken string) (bool, error) {
	return true, nil
}

func dummyCookieOptions() session.CookieOptions {
	return session.CookieOptions{
		SessionCookieName:  "sid",
		TrackingCookieName: "tid",
		AuthCookieName:     "aid",
		MaxAge:             3600,
		Secure:             false,
	}
}

func TestProxy_New_InvalidConfig(t *testing.T) {
	_, err := New()
	if err == nil {
		t.Error("expected error for missing provider and upstream URL")
	}

	_, err = New(WithProvider(nil), WithUpstreamURL(nil))
	if err == nil {
		t.Error("expected error for nil provider and upstream URL")
	}
}

func TestProxy_ServeHTTP_NotFound(t *testing.T) {
	u, _ := url.Parse("http://example.com")
	p, err := New(WithProvider(&dummyProvider{}), WithUpstreamURL(u), WithCookieOptions(dummyCookieOptions()))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	r := httptest.NewRequest("GET", "/notfound", nil)
	rw := httptest.NewRecorder()
	p.ServeHTTP(rw, r)
	if rw.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", rw.Code)
	}
}
