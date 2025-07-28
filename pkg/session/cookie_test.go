package session

import (
	"net/http"
	"testing"
)

func TestNewSessionCookie(t *testing.T) {
	opts := CookieOptions{
		SessionCookieName:  "sid",
		TrackingCookieName: "tid",
		AuthCookieName:     "aid",
		MaxAge:             3600,
		Secure:             true,
		SameSite:           "Strict",
	}
	cookie := NewSessionCookie("val", 3600, opts)
	if cookie.Name != "sid" || cookie.Value != "val" {
		t.Errorf("unexpected cookie: %+v", cookie)
	}
	if cookie.Secure != true {
		t.Error("expected Secure=true")
	}
	if cookie.SameSite != http.SameSiteStrictMode {
		t.Errorf("expected SameSiteStrictMode, got %v", cookie.SameSite)
	}
}

func TestNewAuthCookie(t *testing.T) {
	opts := CookieOptions{
		SessionCookieName:  "sid",
		TrackingCookieName: "tid",
		AuthCookieName:     "aid",
		MaxAge:             3600,
		Secure:             false,
	}
	cookie := NewAuthCookie("authval", opts)
	if cookie.Name != "aid" || cookie.Value != "authval" {
		t.Errorf("unexpected auth cookie: %+v", cookie)
	}
	if cookie.Secure != false {
		t.Error("expected Secure=false")
	}
	if cookie.SameSite != http.SameSiteLaxMode {
		t.Errorf("expected SameSiteLaxMode, got %v", cookie.SameSite)
	}
}

func TestNewTrackingCookie(t *testing.T) {
	opts := CookieOptions{
		SessionCookieName:  "sid",
		TrackingCookieName: "tid",
		AuthCookieName:     "aid",
		MaxAge:             3600,
		Secure:             true,
		SameSite:           "Lax",
	}
	cookie := NewTrackingCookie("track", 1800, opts)
	if cookie.Name != "tid" || cookie.Value != "track" {
		t.Errorf("unexpected tracking cookie: %+v", cookie)
	}
	if cookie.SameSite != http.SameSiteLaxMode {
		t.Errorf("expected SameSiteLaxMode, got %v", cookie.SameSite)
	}
}

func TestGetSameSiteAttribute(t *testing.T) {
	if getSameSiteAttribute("Strict") != http.SameSiteStrictMode {
		t.Error("Strict should map to SameSiteStrictMode")
	}
	if getSameSiteAttribute("Lax") != http.SameSiteLaxMode {
		t.Error("Lax should map to SameSiteLaxMode")
	}
	if getSameSiteAttribute("None") != http.SameSiteNoneMode {
		t.Error("None should map to SameSiteNoneMode")
	}
	if getSameSiteAttribute("bogus") != http.SameSiteDefaultMode {
		t.Error("unknown should map to SameSiteDefaultMode")
	}
}
