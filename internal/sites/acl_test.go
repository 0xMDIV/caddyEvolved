package sites

import (
	"context"
	"errors"
	"strings"
	"testing"
)

const testHash = "$2a$14$Zkx19XLiW6VYouLHR5NmfOFU0z2GTNmpkT/5qqR7hx4IjWJPDhjvG"

func TestACLRenderOrder(t *testing.T) {
	acl := AccessList{ID: "lan", Name: "LAN", Allow: []string{"private_ranges"}, Deny: []string{"10.0.0.66"},
		Users: []ACLUser{{Username: "nico", Hash: testHash}}}
	acl.Normalize()
	if err := acl.Validate(); err != nil {
		t.Fatal(err)
	}
	s := Site{ID: "app", Domains: []string{"app.lan"}, Upstreams: []string{"10.0.0.5:80"}, AccessList: "lan"}
	s.Normalize()
	got := RenderWith(s, &acl, Options{})
	deny := strings.Index(got, "respond @cf_acl_deny")
	allow := strings.Index(got, "respond @cf_acl_notallowed")
	auth := strings.Index(got, "basic_auth")
	proxy := strings.Index(got, "reverse_proxy")
	if !strings.Contains(got, "\troute {") || deny < 0 || allow < deny || auth < allow || proxy < auth {
		t.Fatalf("falsche Reihenfolge oder kein route-Block:\n%s", got)
	}
	if !balanced(got) {
		t.Fatalf("Klammern unausgeglichen:\n%s", got)
	}
}

func TestACLValidate(t *testing.T) {
	bad := []AccessList{
		{ID: "a", Name: "x", Allow: []string{"10.0.0.0/8 }"}},
		{ID: "a", Name: "x", Deny: []string{"evil.com"}},
		{ID: "a", Name: "x", AllowCountries: []string{"DE"}},                      // no db
		{ID: "a", Name: "x", Users: []ACLUser{{Username: "u", Hash: "plain"}}},    // not bcrypt
		{ID: "a", Name: "x", Users: []ACLUser{{Username: "u x", Hash: testHash}}}, // bad name
		{ID: "a", Name: "x"}, // empty
	}
	for i, a := range bad {
		a.Normalize()
		if a.Validate() == nil {
			t.Errorf("Fall %d hätte abgelehnt werden müssen: %+v", i, a)
		}
	}
}

func TestACLLifecycle(t *testing.T) {
	m, _ := newTestManager(t)
	ctx := context.Background()
	acl, err := m.UpsertACL(ctx, AccessList{Name: "Nur LAN", Allow: []string{"private_ranges"}}, true, ok)
	if err != nil {
		t.Fatal(err)
	}
	if acl.ID != "nur-lan" {
		t.Errorf("id = %q", acl.ID)
	}
	if _, err := m.Upsert(ctx, Site{ID: "app", Domains: []string{"app.lan"}, Upstreams: []string{"a:1"}, AccessList: "missing", Enabled: true}, true, ok); err == nil {
		t.Fatal("Site mit unbekannter Access List angelegt")
	}
	if _, err := m.Upsert(ctx, Site{ID: "app", Domains: []string{"app.lan"}, Upstreams: []string{"a:1"}, AccessList: acl.ID, Enabled: true}, true, ok); err != nil {
		t.Fatal(err)
	}
	var verr *ValidationError
	if err := m.DeleteACL(ctx, acl.ID, ok); !errors.As(err, &verr) {
		t.Fatalf("benutzte Access List gelöscht: %v", err)
	}
	// Keeping a user's password: an empty hash on update keeps the stored one.
	acl.Users = []ACLUser{{Username: "nico", Hash: testHash}}
	if _, err := m.UpsertACL(ctx, acl, false, ok); err != nil {
		t.Fatal(err)
	}
	acl.Users = []ACLUser{{Username: "nico"}}
	if _, err := m.UpsertACL(ctx, acl, false, ok); err != nil {
		t.Fatalf("Update ohne neues Passwort: %v", err)
	}
	lists, _ := m.ListACL()
	if lists[0].Users[0].Hash != testHash {
		t.Errorf("Hash verloren: %+v", lists[0].Users)
	}
}
