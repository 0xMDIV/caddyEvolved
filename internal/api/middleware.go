package api

import (
	"context"
	"net"
	"net/http"
	"net/url"
	"strings"

	"caddyevolved/internal/auth"
)

// sessionCookie is the only credential the browser keeps.
const sessionCookie = "cev_session"

// HeaderGate is the custom header a mutation must carry. A cross-site form
// post cannot set custom headers, so this is the CSRF defence for a JSON API.
const HeaderGate = "X-CaddyEvolved"

type ctxKey int

const sessionCtxKey ctxKey = 1

// Session is the validated login attached to a request.
type Session struct {
	ID     string
	Remote string
	// Bearer is true when the credential came in an Authorization header:
	// browsers never send that on their own, so the CSRF gate does not apply.
	Bearer bool
	// Token is set for API tokens (name), Scope then limits what it may do.
	Token string
	Scope string
}

// sessionFromContext returns the login for handlers that need the actor.
func sessionFromContext(ctx context.Context) (Session, bool) {
	sess, ok := ctx.Value(sessionCtxKey).(Session)
	return sess, ok && sess.ID != ""
}

// middleware wraps every route with transport-level headers.
func (s *Server) middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Only internalCall may say a request came from the AI or MCP; it
		// calls the mux directly and never passes here.
		r.Header.Del("X-CaddyEvolved-Via")
		r.Header.Del("X-CaddyEvolved-Chat")
		h := w.Header()
		// A management UI on a LAN must not be embeddable by another origin.
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "same-origin")
		h.Add("Vary", "Accept-Encoding")
		if r.URL.Path != "/api/events/stream" {
			h.Set("Cache-Control", "no-store")
		}
		if routable(s.Bind) && !s.Insecure {
			h.Set("Strict-Transport-Security", "max-age=31536000")
		}
		next.ServeHTTP(w, r)
	})
}

// auth guards a handler: valid session (cookie or bearer), same origin, and
// for unsafe methods the HeaderGate marker.
func (s *Server) auth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !sameOrigin(r) {
			writeErr(w, http.StatusForbidden, "cross_origin", "Fremde Herkunft verweigert", "Origin/Referer passt nicht zu Host "+r.Host)
			return
		}
		sess, ok := s.resolveSession(r)
		if !ok {
			writeErr(w, http.StatusUnauthorized, "unauthenticated", "Login erforderlich")
			return
		}
		if !safeMethod(r.Method) && !sess.Bearer && r.Header.Get(HeaderGate) != "1" {
			writeErr(w, http.StatusForbidden, "csrf", "Header "+HeaderGate+": 1 fehlt (Formulare können ihn nicht setzen)")
			return
		}
		if !safeMethod(r.Method) && sess.Token != "" && sess.Scope != auth.ScopeWrite {
			writeErr(w, http.StatusForbidden, "token_readonly", "Dieses API-Token darf nur lesen")
			return
		}
		r = r.WithContext(context.WithValue(r.Context(), sessionCtxKey, sess))
		if !safeMethod(r.Method) {
			s.audit(w, r, sess, next)
			return
		}
		next(w, r)
	}
}

func safeMethod(m string) bool {
	switch m {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return true
	default:
		return false
	}
}

// resolveSession accepts the cookie or an equivalent bearer token, so the CLI
// and the browser share one session model.
func (s *Server) resolveSession(r *http.Request) (Session, bool) {
	if !s.Auth.HasPassword() {
		return Session{}, false
	}
	id, bearer := "", false
	if hdr := r.Header.Get("Authorization"); strings.HasPrefix(hdr, "Bearer ") {
		id, bearer = strings.TrimSpace(strings.TrimPrefix(hdr, "Bearer ")), true
	}
	if strings.HasPrefix(id, auth.TokenPrefix) {
		t, ok := s.Auth.ValidateToken(id)
		if !ok {
			return Session{}, false
		}
		return Session{ID: t.ID, Remote: clientIP(r), Bearer: true, Token: t.Name, Scope: t.Scope}, true
	}
	if id == "" {
		if c, err := r.Cookie(sessionCookie); err == nil {
			id = c.Value
		}
	}
	if id == "" {
		return Session{}, false
	}
	sess, ok := s.Auth.Validate(id)
	if !ok {
		return Session{}, false
	}
	return Session{ID: sess.ID, Remote: sess.Remote, Bearer: bearer}, true
}

// routable reports whether a bind address is reachable from other machines.
func routable(bind string) bool {
	switch bind {
	case "", "0.0.0.0", "::", "[::]":
		return true
	}
	ip := net.ParseIP(bind)
	if ip == nil {
		return !strings.EqualFold(bind, "localhost")
	}
	return !ip.IsLoopback() && !ip.IsLinkLocalUnicast()
}

// sameOrigin refuses requests from another origin: the UI is same-origin by
// construction, so anything else is a probe or a replay.
func sameOrigin(r *http.Request) bool {
	if r.Host == "" {
		return true
	}
	for _, key := range []string{"Origin", "Referer"} {
		v := r.Header.Get(key)
		if v == "" {
			continue
		}
		u, err := url.Parse(v)
		if err != nil {
			return false
		}
		if !strings.EqualFold(u.Host, r.Host) {
			return false
		}
	}
	return true
}
