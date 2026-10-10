package auth

import (
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestHashVerifyRoundTrip(t *testing.T) {
	const password = "Kuehlschrank-42!"
	h, err := HashPassword(password)
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	if string(h) == password {
		t.Fatal("Passwort steht im Klartext im Hash")
	}
	if !h.Verify(password) {
		t.Error("Verify lehnt das richtige Passwort ab")
	}
	if h.Verify("Kuehlschrank-43!") {
		t.Error("Verify akzeptiert ein falsches Passwort")
	}
	// Two hashes of the same password must differ (salted), yet both verify.
	other, err := HashPassword(password)
	if err != nil {
		t.Fatalf("HashPassword 2: %v", err)
	}
	if other == h {
		t.Error("identischer Hash bei gleichem Passwort: Salt fehlt")
	}
	if !other.Verify(password) {
		t.Error("zweiter Hash verifiziert nicht")
	}
}

func TestHashPasswordRejectsWeak(t *testing.T) {
	for _, pw := range []string{"", "kurz", strings.Repeat("a", 11)} {
		if _, err := HashPassword(pw); err == nil {
			t.Errorf("HashPassword(%q) ließ zu, wollen ErrWeakPassword", pw)
		} else if !errors.Is(err, ErrWeakPassword) {
			t.Errorf("HashPassword(%q) Fehler = %v, wollen ErrWeakPassword", pw, err)
		}
	}
}

func TestVerifyToleratesUnknownFormat(t *testing.T) {
	// A hand-edited or future-format store must refuse, never panic.
	for _, h := range []HashedPassword{"", "pbkdf2-sha256$600000$abc", "sha1$1$2$3", "pbkdf2-sha256$0$a$b"} {
		if h.Verify("Kuehlschrank-42!") {
			t.Errorf("Verify(%q) ließ ein Passwort durch", h)
		}
	}
}

func TestGeneratePasswordShape(t *testing.T) {
	for i := 0; i < 20; i++ {
		pw, err := GeneratePassword()
		if err != nil {
			t.Fatalf("GeneratePassword: %v", err)
		}
		if len(pw) != 16 {
			t.Fatalf("Länge = %d (%q), wollen 16", len(pw), pw)
		}
		if _, err := HashPassword(pw); err != nil {
			t.Errorf("erzeugtes Passwort %q wird als schwach abgelehnt", pw)
		}
		if strings.ContainsAny(pw, "01lI") {
			t.Errorf("erzeugtes Passwort %q enthält verwechselbare Zeichen", pw)
		}
	}
}

func TestStoreLoginValidateLogout(t *testing.T) {
	path := filepath.Join(t.TempDir(), "auth.json")
	store, err := LoadStore(path)
	if err != nil {
		t.Fatalf("LoadStore: %v", err)
	}
	if store.HasPassword() {
		t.Fatal("frischer Store meldet ein Passwort")
	}
	if _, err := store.Login("egal", "test", "10.0.0.1", time.Hour); err == nil {
		t.Fatal("Login ohne Passwort durfte nicht gelingen")
	}

	const password = "Kuehlschrank-42!"
	if err := store.SetPassword(password); err != nil {
		t.Fatalf("SetPassword: %v", err)
	}
	if !store.Check(password) {
		t.Error("Check nach SetPassword falsch")
	}

	sess, err := store.Login(password, "Mozilla/test", "10.0.0.1", time.Hour)
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	if _, ok := store.Validate(sess.ID); !ok {
		t.Error("frische Session wird nicht validiert")
	}
	if len(store.ListSessions()) != 1 {
		t.Errorf("ListSessions = %d, wollen 1", len(store.ListSessions()))
	}

	// Persistence: a daemon restart must not log everybody out.
	reopened, err := LoadStore(path)
	if err != nil {
		t.Fatalf("LoadStore 2: %v", err)
	}
	if !reopened.Check(password) {
		t.Error("Passwort nach Reload nicht mehr prüfbar")
	}
	if _, ok := reopened.Validate(sess.ID); !ok {
		t.Error("Session nach Reload nicht mehr gültig")
	}

	if err := store.Logout(sess.ID); err != nil {
		t.Fatalf("Logout: %v", err)
	}
	if _, ok := store.Validate(sess.ID); ok {
		t.Error("Session überlebt Logout")
	}
}

func TestSetPasswordRevokesSessions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "auth.json")
	store, err := LoadStore(path)
	if err != nil {
		t.Fatalf("LoadStore: %v", err)
	}
	const first = "Kuehlschrank-42!"
	if err := store.SetPassword(first); err != nil {
		t.Fatalf("SetPassword: %v", err)
	}
	sess, err := store.Login(first, "test", "10.0.0.2", time.Hour)
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	if err := store.SetPassword("Anderes-Passwort-1!"); err != nil {
		t.Fatalf("SetPassword 2: %v", err)
	}
	if _, ok := store.Validate(sess.ID); ok {
		t.Error("alte Session gilt nach Passwortwechsel noch – Abmelden unterblieben")
	}
	if store.Check(first) {
		t.Error("das alte Passwort gilt noch")
	}
}

func TestLoginLocksOutRepeatedFailures(t *testing.T) {
	path := filepath.Join(t.TempDir(), "auth.json")
	store, err := LoadStore(path)
	if err != nil {
		t.Fatalf("LoadStore: %v", err)
	}
	if err := store.SetPassword("Kuehlschrank-42!"); err != nil {
		t.Fatalf("SetPassword: %v", err)
	}
	var lastErr error
	for i := 0; i < 12; i++ {
		_, err := store.Login("falsch", "test", "10.0.0.3", time.Hour)
		if err == nil {
			t.Fatal("falsches Passwort wurde akzeptiert")
		}
		lastErr = err
	}
	if !errors.Is(lastErr, ErrTooManyAttempts) {
		t.Errorf("nach 12 Fehlversuchen Fehler = %v, wollen ErrTooManyAttempts", lastErr)
	}
	// A different client must not be affected by somebody else's lockout.
	if _, err := store.Login("Kuehlschrank-42!", "test", "10.0.0.4", time.Hour); err != nil {
		t.Errorf("Login von anderer Adresse trotz Sperrung eines Clients abgelehnt: %v", err)
	}
}

func TestExpiredSessionRejected(t *testing.T) {
	now := time.Now()
	if (Session{ID: "x", Expires: now.Add(-time.Second)}).Valid(now) {
		t.Error("abgelaufene Session gilt")
	}
	if (Session{ID: "", Expires: now.Add(time.Hour)}).Valid(now) {
		t.Error("Session ohne ID gilt")
	}
}
