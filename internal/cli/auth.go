package cli

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"net/http"
	"strings"
)

// Dashboard credentials. In a real deployment these should be sourced from
// environment variables / config rather than hard-coded, but the dashboard is
// scoped to the rebel:crow account requested for this build.
var (
	authUsername = "rebel"
	authPassword = "crow"
)

// authorizeBasic validates the request's Authorization header against the
// configured dashboard credentials using a constant-time comparison. It
// returns the authenticated username on success or "" on failure.
func authorizeBasic(r *http.Request) string {
	header := r.Header.Get("Authorization")
	if header == "" {
		return ""
	}

	const prefix = "Basic "
	if !strings.HasPrefix(header, prefix) {
		return ""
	}

	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(header[len(prefix):]))
	if err != nil {
		return ""
	}

	user, pass, found := strings.Cut(string(raw), ":")
	if !found {
		return ""
	}

	if credsEqual(user, authUsername) && credsEqual(pass, authPassword) {
		return user
	}
	return ""
}

// credsEqual does a constant-time comparison over SHA-256 digests so that
// timing does not leak how much of the supplied credential matched.
func credsEqual(a, b string) bool {
	ha := sha256.Sum256([]byte(a))
	hb := sha256.Sum256([]byte(b))
	return subtle.ConstantTimeCompare(ha[:], hb[:]) == 1
}

// requireAuth wraps a handler so that only authenticated requests pass through.
// We intentionally omit the WWW-Authenticate header on failure so the browser
// does not show its native popup — the SPA renders its own login screen instead.
func requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := authorizeBasic(r)
		if user == "" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"error":"unauthorized","message":"Please sign in with your dashboard credentials."}`))
			return
		}
		next(w, r)
	}
}
