package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/praserx/goth/pkg/session"
)

func TestSetStartTime(t *testing.T) {
	r := httptest.NewRequest("GET", "/", nil)
	r2 := setStartTime(r)
	if r2 == nil {
		t.Fatal("setStartTime returned nil request")
	}
	val := r2.Context().Value(RequestStartTimeContextKey)
	if val == nil {
		t.Error("RequestStartTimeContextKey not set in context")
	}
	if _, ok := val.(time.Time); !ok {
		t.Error("RequestStartTimeContextKey is not time.Time")
	}
}

func TestSetRequestID(t *testing.T) {
	r := httptest.NewRequest("GET", "/", nil)
	r2, requestID := setRequestID(r)
	if r2 == nil {
		t.Fatal("setRequestID returned nil request")
	}
	if requestID == "" {
		t.Error("setRequestID did not return a request ID")
	}
	val := r2.Context().Value(RequestIDContextKey)
	if val == nil {
		t.Error("RequestIDContextKey not set in context")
	}
	if v, ok := val.(string); !ok || v != requestID {
		t.Error("RequestIDContextKey does not match returned requestID")
	}
}

func TestSetTrackingCookie_New(t *testing.T) {
	r := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()
	opts := session.CookieOptions{TrackingCookieName: "trackid"}
	setTrackingCookie(w, r, opts)
	cookies := w.Result().Cookies()
	found := false
	for _, c := range cookies {
		if c.Name == "trackid" {
			found = true
			if c.Value == "" {
				t.Error("Tracking cookie value is empty")
			}
		}
	}
	if !found {
		t.Error("Tracking cookie not set")
	}
}

func TestSetTrackingCookie_Renew(t *testing.T) {
	w := httptest.NewRecorder()
	opts := session.CookieOptions{TrackingCookieName: "trackid"}
	oldCookie := &http.Cookie{
		Name:    "trackid",
		Value:   "oldvalue",
		Expires: time.Now().Add(5 * time.Hour), // less than renewBefore
	}
	r := httptest.NewRequest("GET", "/", nil)
	r.AddCookie(oldCookie)
	setTrackingCookie(w, r, opts)
	cookies := w.Result().Cookies()
	found := false
	for _, c := range cookies {
		if c.Name == "trackid" && c.Value != "oldvalue" {
			found = true
		}
	}
	if !found {
		t.Error("Tracking cookie was not renewed")
	}
}

func TestContextMiddleware_Propagation(t *testing.T) {
	opts := session.CookieOptions{TrackingCookieName: "trackid"}
	var gotRequestID, gotStartTime bool
	h := ContextMiddleware(opts)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Context().Value(RequestIDContextKey) != nil {
			gotRequestID = true
		}
		if r.Context().Value(RequestStartTimeContextKey) != nil {
			gotStartTime = true
		}
	}))
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/", nil)
	h.ServeHTTP(w, r)
	if !gotRequestID {
		t.Error("RequestIDContextKey not propagated to handler context")
	}
	if !gotStartTime {
		t.Error("RequestStartTimeContextKey not propagated to handler context")
	}
	if w.Header().Get(RequestIDHeader) == "" {
		t.Error("RequestIDHeader not set on response")
	}
	found := false
	for _, c := range w.Result().Cookies() {
		if c.Name == "trackid" {
			found = true
		}
	}
	if !found {
		t.Error("Tracking cookie not set by middleware")
	}
}
