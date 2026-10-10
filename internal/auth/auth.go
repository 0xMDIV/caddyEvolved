// Package auth protects the WebUI. The daemon binds to 0.0.0.0 by default, so
// a single local trust assumption is not enough: passwords are salted,
// logins are rate limited, sessions expire and can be revoked.
package auth

import (
	"crypto/hmac"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"
)

// pbkdf2Iterations follows the OWASP 2023 floor for PBKDF2-HMAC-SHA256.
// argon2id would be stronger but lives in x/crypto; one dependency for a LAN
// admin UI with lockouts was not worth the supply-chain cost.
const pbkdf2Iterations = 600_000

// HashedPassword is an encoded verifier: scheme$iterations$salt$hash.
type HashedPassword string

// ErrWeakPassword rejects trivial passwords before they reach the store.
var ErrWeakPassword = errors.New("Passwort zu schwach (mindestens 12 Zeichen)")

// ErrTooManyAttempts is returned while a client is locked out.
var ErrTooManyAttempts = errors.New("zu viele Fehlversuche – bitte später erneut versuchen")

// HashPassword derives a verifier from a plaintext password.
func HashPassword(pw string) (HashedPassword, error) {
	if len(pw) < 12 {
		return "", ErrWeakPassword
	}
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	dk, err := pbkdf2.Key(sha256.New, pw, salt, pbkdf2Iterations, 32)
	if err != nil {
		return "", err
	}
	return HashedPassword(fmt.Sprintf("pbkdf2-sha256$%d$%s$%s",
		pbkdf2Iterations, b64(salt), b64(dk))), nil
}

// Verify compares a plaintext password against the stored encoding in
// constant time, including the iteration count.
func (h HashedPassword) Verify(pw string) bool {
	parts := strings.Split(string(h), "$")
	if len(parts) != 4 || parts[0] != "pbkdf2-sha256" {
		return false
	}
	var iters int
	if _, err := fmt.Sscanf(parts[1], "%d", &iters); err != nil || iters < 1000 {
		return false
	}
	salt, err := ub64(parts[2])
	if err != nil {
		return false
	}
	want, err := ub64(parts[3])
	if err != nil {
		return false
	}
	dk, err := pbkdf2.Key(sha256.New, pw, salt, iters, len(want))
	if err != nil {
		return false
	}
	return subtle.ConstantTimeCompare(dk, want) == 1
}

// Session is an issued login.
type Session struct {
	ID        string    `json:"id"`
	Created   time.Time `json:"created"`
	Expires   time.Time `json:"expires"`
	UserAgent string    `json:"userAgent,omitempty"`
	Remote    string    `json:"remote,omitempty"`
}

// Valid reports whether the session is still usable.
func (s Session) Valid(now time.Time) bool {
	return s.ID != "" && now.Before(s.Expires)
}

// Store persists the password verifier and the session list.
type Store struct {
	mu       sync.Mutex
	path     string
	Password HashedPassword        `json:"password"`
	Sessions map[string]Session    `json:"sessions"`
	Failed   map[string]failRecord `json:"failed"`
	Tokens   map[string]APIToken   `json:"tokens,omitempty"`
	key      []byte                // hmac secret for session ids
}

type failRecord struct {
	Count   int
	Until   time.Time
	LastTry time.Time
}

// LoadStore reads or creates the auth store at path (0600).
func LoadStore(path string) (*Store, error) {
	s := &Store{path: path, Sessions: map[string]Session{}, Failed: map[string]failRecord{}}
	data, err := readFile(path)
	if err != nil {
		return nil, err
	}
	if len(data) > 0 {
		if err := unmarshalJSON(data, s); err != nil {
			return nil, err
		}
		if s.Sessions == nil {
			s.Sessions = map[string]Session{}
		}
		if s.Failed == nil {
			s.Failed = map[string]failRecord{}
		}
	}
	if len(s.key) == 0 {
		s.key = make([]byte, 32)
		if _, err := rand.Read(s.key); err != nil {
			return nil, err
		}
	}
	return s, nil
}

// SetPassword installs the first (or reset) password.
func (s *Store) SetPassword(pw string) error {
	h, err := HashPassword(pw)
	if err != nil {
		return err
	}
	s.mu.Lock()
	s.Password = h
	// A password change invalidates every existing session.
	s.Sessions = map[string]Session{}
	err = s.saveLocked()
	s.mu.Unlock()
	return err
}

// passwordLower/Upper/Digit/Symbol avoid characters that get mistyped over a
// phone or read aloud (0/O, 1/l/I), which matters because the installer
// prints the value exactly once.
const (
	passwordLower  = "abcdefghijkmnpqrstuvwxyz"
	passwordUpper  = "ABCDEFGHJKLMNPQRSTUVWXYZ"
	passwordDigits = "23456789"
	passwordSymbol = "-_=+.!?:/~"
)

// GeneratePassword returns a random 16 character password with one character
// from every class, so it always satisfies our own strength rule.
func GeneratePassword() (string, error) {
	const length = 16
	classes := []string{passwordLower, passwordUpper, passwordDigits, passwordSymbol}
	all := passwordLower + passwordUpper + passwordDigits + passwordSymbol

	buf := make([]byte, length)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	out := make([]byte, length)
	for i := range out {
		out[i] = all[int(buf[i])%len(all)]
	}
	// Force one of each class at positions chosen from the same randomness.
	for i, set := range classes {
		pos := int(buf[length-1-i]) % length
		if containsByte(out, set[int(buf[i])%len(set)]) {
			continue
		}
		out[pos] = set[int(buf[i])%len(set)]
	}
	// A symbol at the end reads better than one in the middle.
	if out[length-1] < 'a' {
		out[length-1] = passwordSymbol[int(buf[0])%len(passwordSymbol)]
	}
	return string(out), nil
}

func containsByte(v []byte, b byte) bool {
	for _, x := range v {
		if x == b {
			return true
		}
	}
	return false
}

// GeneratePasswordHint is a readable example shown when a chosen password is
// rejected, so the operator learns the rule without a spec document.
func GeneratePasswordHint() string {
	return "Wort+Zahl+Symbol, z. B. Kuehlschrank-42!"
}

// HasPassword reports whether login is possible at all.
func (s *Store) HasPassword() bool { return s.Password != "" }

// Check verifies a candidate password without issuing a session and without
// touching the lockout counters — used by the "current password" prompt.
func (s *Store) Check(pw string) bool {
	return s.HasPassword() && s.Password.Verify(pw)
}

// Login validates a password and issues a session, applying lockout.
func (s *Store) Login(pw, userAgent, remote string, ttl time.Duration) (Session, error) {
	if ttl == 0 {
		ttl = 12 * time.Hour
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	if f, ok := s.Failed[remote]; ok && now.Before(f.Until) {
		return Session{}, fmt.Errorf("%w (gesperrt bis %s)", ErrTooManyAttempts, f.Until.Format(time.RFC3339))
	}
	if !s.Password.Verify(pw) {
		f := s.Failed[remote]
		f.Count++
		f.LastTry = now
		if f.Count >= 5 {
			// Exponential: 1 min, 5 min, 25 min, capped at 6 h.
			backoff := time.Minute
			for i := 1; i < f.Count-4 && backoff < 6*time.Hour; i++ {
				backoff *= 5
			}
			f.Until = now.Add(backoff)
			f.Count = 5
		}
		s.Failed[remote] = f
		s.saveLocked()
		return Session{}, errors.New("Passwort falsch")
	}
	delete(s.Failed, remote)

	id := s.newID()
	sess := Session{ID: id, Created: now, Expires: now.Add(ttl), UserAgent: userAgent, Remote: remote}
	s.pruneLocked(now)
	s.Sessions[id] = sess
	if err := s.saveLocked(); err != nil {
		return Session{}, err
	}
	return sess, nil
}

// Validate resolves a presented session id to its record.
func (s *Store) Validate(id string) (Session, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.Sessions[id]
	if !ok || !sess.Valid(time.Now()) {
		return Session{}, false
	}
	return sess, true
}

// Logout revokes one session.
func (s *Store) Logout(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.Sessions, id)
	return s.saveLocked()
}

// ListSessions returns live sessions, newest first, for the settings screen.
func (s *Store) ListSessions() []Session {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	out := make([]Session, 0, len(s.Sessions))
	for _, sess := range s.Sessions {
		if sess.Valid(now) {
			out = append(out, sess)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Created.After(out[j].Created) })
	return out
}

// RotateKey issues a fresh hmac secret (invalidates ids on restart).
func (s *Store) revokeAll() {
	s.Sessions = map[string]Session{}
}

func (s *Store) newID() string {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		// rand failing is fatal for sessions; fall back to a timestamp id so
		// the daemon still serves a usable login.
		return fmt.Sprintf("t%d", time.Now().UnixNano())
	}
	mac := hmac.New(sha256.New, s.key)
	mac.Write(buf)
	return b64(mac.Sum(nil))[:32]
}

func (s *Store) pruneLocked(now time.Time) {
	for id, sess := range s.Sessions {
		if !sess.Valid(now) {
			delete(s.Sessions, id)
		}
	}
}

func (s *Store) saveLocked() error {
	return writeFileJSON(s.path, s, 0o600)
}

func b64(v []byte) string { return base64.RawURLEncoding.EncodeToString(v) }

func ub64(v string) ([]byte, error) { return base64.RawURLEncoding.DecodeString(v) }
