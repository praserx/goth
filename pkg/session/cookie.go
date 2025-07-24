package session

import "net/http"

// CookieOptions represent general configuration for session cookies.
type CookieOptions struct {
	SessionCookieName  string // Name of the session cookie
	TrackingCookieName string // Name of the tracking cookie
	AuthCookieName     string // Name of the authentication cookie
	MaxAge             int    // Maximum age of the session cookie in seconds
	Secure             bool   // Indicates if the cookie should only be sent over HTTPS
	SameSite           string // SameSite attribute for the cookie (e.g., "Strict", "Lax", "None")
}

// NewTrackingCookie creates a new tracking cookie with the specified value and options.
func NewTrackingCookie(value string, maxAge int, opts CookieOptions) *http.Cookie {
	return &http.Cookie{
		Name:     opts.TrackingCookieName,
		Value:    value,
		Path:     "/",
		MaxAge:   maxAge,
		Secure:   opts.Secure,
		HttpOnly: true,
		SameSite: http.SameSiteNoneMode,
	}
}

// NewSessionCookie creates a new session cookie with the specified value and options.
func NewAuthCookie(value string, opts CookieOptions) *http.Cookie {
	return &http.Cookie{
		Name:     opts.AuthCookieName,
		Value:    value,
		Path:     "/",
		MaxAge:   int(AuthSessionTTL.Seconds()),
		Secure:   opts.Secure,
		HttpOnly: true,
		SameSite: http.SameSiteNoneMode,
	}
}

// NewSessionCookie creates a new session cookie with the specified value and options.
func NewSessionCookie(value string, maxAge int, opts CookieOptions) *http.Cookie {
	return &http.Cookie{
		Name:     opts.SessionCookieName,
		Value:    value,
		Path:     "/",
		MaxAge:   maxAge,
		Secure:   opts.Secure,
		HttpOnly: true,
		SameSite: getSameSiteAttribute(opts.SameSite),
	}
}

// getSameSiteAttribute converts a string representation of SameSite to http.SameSite type.
func getSameSiteAttribute(sameSite string) http.SameSite {
	switch sameSite {
	case "Strict":
		return http.SameSiteStrictMode
	case "Lax":
		return http.SameSiteLaxMode
	case "None":
		return http.SameSiteNoneMode
	default:
		return http.SameSiteDefaultMode
	}
}
