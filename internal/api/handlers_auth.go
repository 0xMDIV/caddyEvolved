package api

import (
	"errors"
	"net"
	"net/http"
	"strings"
	"time"

	"caddyevolved/internal/auth"
	"caddyevolved/internal/buildinfo"
	"caddyevolved/internal/events"
)

// handleVersion is public so a deployment script can check reachability before
// it knows a password exists.
func (s *Server) handleVersion(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"name":       "caddyEvolved",
		"version":    buildinfo.Version,
		"commit":     buildinfo.Commit,
		"date":       buildinfo.Date,
		"api":        1,
		"setup":      !s.Auth.HasPassword(),
		"serverTime": time.Now().UTC(),
	})
}

type loginRequest struct {
	Password string `json:"password"`
	// KeepMeLoggedIn extends the session past the default lifetime.
	KeepMeLoggedIn bool `json:"keepMeLoggedIn,omitempty"`
}

// handleLogin issues a session cookie. On a fresh install no password exists
// yet: the first successful call with the bootstrap token sets it.
func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	var req loginRequest
	if err := decode(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", errText(err))
		return
	}
	ttl := 12 * time.Hour
	if req.KeepMeLoggedIn {
		ttl = 30 * 24 * time.Hour
	}
	sess, err := s.Auth.Login(req.Password, r.UserAgent(), clientIP(r), ttl)
	if err != nil {
		s.Events.Record(events.Event{
			Kind: events.KindAuth, Step: "login", OK: false,
			Error:   errText(err),
			Summary: "fehlgeschlagener Login-Versuch",
			Meta:    map[string]any{"remote": clientIP(r)},
		})
		writeErr(w, http.StatusUnauthorized, "bad_credentials", errText(err))
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookie,
		Value:    sess.ID,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   !s.Insecure,
		Expires:  sess.Expires,
		MaxAge:   int(time.Until(sess.Expires).Seconds()),
	})
	s.Events.Record(events.Event{
		Kind: events.KindAuth, Step: "login", OK: true,
		Summary: "Angemeldet",
		Meta:    map[string]any{"remote": clientIP(r)},
	})
	writeJSON(w, http.StatusOK, map[string]any{"expires": sess.Expires, "sessionId": sess.ID})
}

// handleLogout revokes the presenting session only.
func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	sess, _ := sessionFromContext(r.Context())
	if err := s.Auth.Logout(sess.ID); err != nil {
		s.fail(w, r, err, 0)
		return
	}
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: "", Path: "/", MaxAge: -1, HttpOnly: true})
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// handleSession reports the caller's own login, and on a fresh install the
// bootstrap token so the setup wizard can complete.
func (s *Server) handleSession(w http.ResponseWriter, r *http.Request) {
	sess, _ := sessionFromContext(r.Context())
	out := map[string]any{
		"sessionId": sess.ID,
		"remote":    sess.Remote,
		"sessions":  s.Auth.ListSessions(),
	}
	writeJSON(w, http.StatusOK, out)
}

// handleChangePassword replaces the UI password and signs every other session
// out, because a reset usually follows "someone else knows it".
func (s *Server) handleChangePassword(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Current string `json:"current"`
		New     string `json:"new"`
	}
	if err := decode(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", errText(err))
		return
	}
	sess, _ := sessionFromContext(r.Context())
	if !s.Auth.Check(req.Current) {
		writeErr(w, http.StatusUnauthorized, "bad_credentials", "Aktuelles Passwort falsch")
		return
	}
	if err := s.Auth.SetPassword(req.New); err != nil {
		if errors.Is(err, auth.ErrWeakPassword) {
			writeErr(w, http.StatusBadRequest, "weak_password", errText(err))
			return
		}
		s.fail(w, r, err, 0)
		return
	}
	s.Events.Record(events.Event{Kind: events.KindAuth, Step: "password", OK: true, Summary: "UI-Passwort geändert"})
	// Our own session died with the rotation too; the UI must log in again.
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: "", Path: "/", MaxAge: -1, HttpOnly: true})
	_ = sess
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "reauth": true})
}

// clientIP prefers the real peer. X-Forwarded-For is only honoured when the
// request demonstrably came from our own caddy on loopback.
func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	if isLoopback(host) {
		if fwd := r.Header.Get("X-Forwarded-For"); fwd != "" {
			first, _, _ := strings.Cut(fwd, ",")
			return strings.TrimSpace(first)
		}
	}
	return host
}

func isLoopback(host string) bool {
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
