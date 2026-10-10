package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"sort"
	"strings"
	"time"
)

// TokenPrefix marks API tokens so the middleware can tell them from session
// ids and secret scanners can find leaked ones.
const TokenPrefix = "cfx_"

// Scopes an API token can carry.
const (
	ScopeRead  = "read"
	ScopeWrite = "write"
)

// APIToken is a long-lived credential for scripts and AI clients. Only the
// SHA-256 of the secret is stored; the plaintext is shown once at creation.
type APIToken struct {
	ID       string    `json:"id"`
	Name     string    `json:"name"`
	Scope    string    `json:"scope"`
	Hash     string    `json:"hash"`
	Prefix   string    `json:"prefix"` // first characters, to recognise it in a list
	Created  time.Time `json:"created"`
	LastUsed time.Time `json:"lastUsed,omitzero"`
	Expires  time.Time `json:"expires,omitzero"`
}

// Expired reports whether the token has run out.
func (t APIToken) Expired(now time.Time) bool { return !t.Expires.IsZero() && now.After(t.Expires) }

// CreateToken issues a token and returns its plaintext exactly once.
func (s *Store) CreateToken(name, scope string, ttl time.Duration) (string, APIToken, error) {
	name = strings.TrimSpace(name)
	if name == "" || len(name) > 64 {
		return "", APIToken{}, errors.New("Name fehlt oder ist länger als 64 Zeichen")
	}
	if scope != ScopeRead && scope != ScopeWrite {
		return "", APIToken{}, errors.New("Scope ist read oder write")
	}
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return "", APIToken{}, err
	}
	idb := make([]byte, 6)
	if _, err := rand.Read(idb); err != nil {
		return "", APIToken{}, err
	}
	plain := TokenPrefix + b64(secret)
	sum := sha256.Sum256([]byte(plain))
	t := APIToken{
		ID: hex.EncodeToString(idb), Name: name, Scope: scope,
		Hash: hex.EncodeToString(sum[:]), Prefix: plain[:10], Created: time.Now().UTC(),
	}
	if ttl > 0 {
		t.Expires = t.Created.Add(ttl)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.Tokens == nil {
		s.Tokens = map[string]APIToken{}
	}
	s.Tokens[t.ID] = t
	return plain, t, s.saveLocked()
}

// ValidateToken checks a presented token. Every stored hash is compared in
// constant time, so timing reveals neither which token nor how much matched.
func (s *Store) ValidateToken(plain string) (APIToken, bool) {
	if !strings.HasPrefix(plain, TokenPrefix) {
		return APIToken{}, false
	}
	sum := sha256.Sum256([]byte(plain))
	want := hex.EncodeToString(sum[:])
	now := time.Now().UTC()
	s.mu.Lock()
	defer s.mu.Unlock()
	var found APIToken
	ok := false
	for _, t := range s.Tokens {
		if subtle.ConstantTimeCompare([]byte(t.Hash), []byte(want)) == 1 {
			found, ok = t, true
		}
	}
	if !ok || found.Expired(now) {
		return APIToken{}, false
	}
	// Persist last use at most once a minute; a busy script must not turn
	// every request into a disk write.
	if now.Sub(found.LastUsed) > time.Minute {
		found.LastUsed = now
		s.Tokens[found.ID] = found
		s.saveLocked()
	}
	return found, true
}

// ListTokens returns the tokens without their hashes, newest first.
func (s *Store) ListTokens() []APIToken {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]APIToken, 0, len(s.Tokens))
	for _, t := range s.Tokens {
		t.Hash = ""
		out = append(out, t)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Created.After(out[j].Created) })
	return out
}

// RevokeToken deletes a token.
func (s *Store) RevokeToken(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.Tokens[id]; !ok {
		return errors.New("Token nicht gefunden")
	}
	delete(s.Tokens, id)
	return s.saveLocked()
}
