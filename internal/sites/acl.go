package sites

import (
	"context"
	"fmt"
	"net/netip"
	"os"
	"regexp"
	"strings"
	"time"
)

// AccessList restricts who reaches a site: IP ranges, countries (with the
// maxmind-geolocation module) and basic-auth users. It is rendered inline into
// every site that references it, so a change re-renders those sites in one
// transaction.
type AccessList struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	// Allow, when non-empty, admits only these ranges. "private_ranges" is
	// caddy's shorthand for RFC1918 + loopback + ULA.
	Allow []string `json:"allow,omitempty"`
	Deny  []string `json:"deny,omitempty"`
	// Countries are ISO-3166 alpha-2 codes; they need GeoDB.
	AllowCountries []string `json:"allowCountries,omitempty"`
	DenyCountries  []string `json:"denyCountries,omitempty"`
	GeoDB          string   `json:"geoDb,omitempty"`
	// Users hold bcrypt hashes only; the plaintext never reaches disk.
	Users     []ACLUser `json:"users,omitempty"`
	UpdatedAt time.Time `json:"updatedAt,omitzero"`
}

// ACLUser is one basic-auth login.
type ACLUser struct {
	Username string `json:"username"`
	Hash     string `json:"hash"`
}

var (
	reUser    = regexp.MustCompile(`^[A-Za-z0-9._@-]{1,64}$`)
	reHash    = regexp.MustCompile(`^\$2[aby]\$[0-9]{2}\$[./A-Za-z0-9]{53}$`)
	reCountry = regexp.MustCompile(`^[A-Z]{2}$`)
)

// Normalize trims and upper-cases the list.
func (a *AccessList) Normalize() {
	a.ID = strings.TrimSpace(strings.ToLower(a.ID))
	a.Name = strings.TrimSpace(a.Name)
	a.Allow = cleanList(a.Allow)
	a.Deny = cleanList(a.Deny)
	a.AllowCountries = upper(cleanList(a.AllowCountries))
	a.DenyCountries = upper(cleanList(a.DenyCountries))
	a.GeoDB = strings.TrimSpace(a.GeoDB)
}

func upper(v []string) []string {
	for i := range v {
		v[i] = strings.ToUpper(v[i])
	}
	return v
}

// Validate refuses anything that is not a plain IP, CIDR or country code;
// the values land in a Caddyfile verbatim.
func (a AccessList) Validate() error {
	var problems []string
	if !reID.MatchString(a.ID) {
		problems = append(problems, "ID: nur a-z, 0-9 und Bindestrich")
	}
	if a.Name == "" || strings.ContainsAny(a.Name, "\n\r{}") {
		problems = append(problems, "Name fehlt oder enthält Zeilenumbrüche/Klammern")
	}
	for _, r := range append(append([]string{}, a.Allow...), a.Deny...) {
		if !validRange(r) {
			problems = append(problems, fmt.Sprintf("%q ist keine IP, kein CIDR und nicht private_ranges", r))
		}
	}
	for _, c := range append(append([]string{}, a.AllowCountries...), a.DenyCountries...) {
		if !reCountry.MatchString(c) {
			problems = append(problems, fmt.Sprintf("Ländercode %q ungültig (zwei Buchstaben, z. B. DE)", c))
		}
	}
	if len(a.AllowCountries)+len(a.DenyCountries) > 0 {
		if !strings.HasPrefix(a.GeoDB, "/") || strings.ContainsAny(a.GeoDB, " \t\n{}\"") {
			problems = append(problems, "Länderregeln brauchen den absoluten Pfad zur GeoLite2-Country.mmdb")
		}
	}
	seen := map[string]bool{}
	for _, u := range a.Users {
		if !reUser.MatchString(u.Username) {
			problems = append(problems, fmt.Sprintf("Benutzername %q ungültig", u.Username))
		}
		if !reHash.MatchString(u.Hash) {
			problems = append(problems, fmt.Sprintf("Benutzer %s: Passwort-Hash fehlt", u.Username))
		}
		if seen[u.Username] {
			problems = append(problems, fmt.Sprintf("Benutzer %s doppelt", u.Username))
		}
		seen[u.Username] = true
	}
	if len(a.Allow)+len(a.Deny)+len(a.AllowCountries)+len(a.DenyCountries)+len(a.Users) == 0 {
		problems = append(problems, "leere Access List – mindestens eine Regel oder einen Benutzer angeben")
	}
	if len(problems) > 0 {
		return &ValidationError{Problems: problems}
	}
	return nil
}

func validRange(r string) bool {
	if r == "private_ranges" {
		return true
	}
	if _, err := netip.ParsePrefix(r); err == nil {
		return true
	}
	_, err := netip.ParseAddr(r)
	return err == nil
}

// UsesGeo reports whether rendering needs the maxmind matcher.
func (a AccessList) UsesGeo() bool { return len(a.AllowCountries)+len(a.DenyCountries) > 0 }

// ListACL returns all access lists.
func (m *Manager) ListACL() ([]AccessList, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	doc, err := m.loadDoc()
	return doc.AccessLists, err
}

// UpsertACL creates or replaces a list and re-renders the sites using it.
func (m *Manager) UpsertACL(ctx context.Context, a AccessList, create bool, commit Commit) (AccessList, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	doc, err := m.loadDoc()
	if err != nil {
		return AccessList{}, err
	}
	if a.ID == "" {
		taken := map[string]bool{}
		for _, x := range doc.AccessLists {
			taken[x.ID] = true
		}
		a.ID = Slug(a.Name)
		for i := 2; taken[a.ID]; i++ {
			a.ID = fmt.Sprintf("%s-%d", Slug(a.Name), i)
		}
	}
	a.Normalize()
	idx := -1
	for i, x := range doc.AccessLists {
		if x.ID == a.ID {
			idx = i
		}
	}
	if create && idx >= 0 {
		return AccessList{}, &ValidationError{Problems: []string{fmt.Sprintf("Access List %q existiert bereits", a.ID)}}
	}
	if !create && idx < 0 {
		return AccessList{}, fmt.Errorf("Access List %q: %w", a.ID, os.ErrNotExist)
	}
	// Users sent without a hash keep their stored one: the UI never sees
	// hashes back, so "unchanged password" arrives as an empty hash.
	if idx >= 0 {
		old := map[string]string{}
		for _, u := range doc.AccessLists[idx].Users {
			old[u.Username] = u.Hash
		}
		for i, u := range a.Users {
			if u.Hash == "" {
				a.Users[i].Hash = old[u.Username]
			}
		}
	}
	if err := a.Validate(); err != nil {
		return AccessList{}, err
	}
	a.UpdatedAt = time.Now().UTC()
	next := doc
	next.AccessLists = append([]AccessList(nil), doc.AccessLists...)
	if idx >= 0 {
		next.AccessLists[idx] = a
	} else {
		next.AccessLists = append(next.AccessLists, a)
	}
	if err := m.applyDoc(ctx, doc, next, commit); err != nil {
		return AccessList{}, err
	}
	return a, nil
}

// DeleteACL removes a list that no site references.
func (m *Manager) DeleteACL(ctx context.Context, id string, commit Commit) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	doc, err := m.loadDoc()
	if err != nil {
		return err
	}
	var users []string
	for _, s := range doc.Sites {
		if s.AccessList == id {
			users = append(users, s.ID)
		}
	}
	if len(users) > 0 {
		return &ValidationError{Problems: []string{"Access List wird noch benutzt von: " + strings.Join(users, ", ")}}
	}
	next := doc
	next.AccessLists = nil
	found := false
	for _, a := range doc.AccessLists {
		if a.ID == id {
			found = true
			continue
		}
		next.AccessLists = append(next.AccessLists, a)
	}
	if !found {
		return fmt.Errorf("Access List %q: %w", id, os.ErrNotExist)
	}
	return m.applyDoc(ctx, doc, next, commit)
}
