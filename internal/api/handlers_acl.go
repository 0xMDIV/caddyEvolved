package api

import (
	"context"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"caddyevolved/internal/builder"
	"caddyevolved/internal/certs"
	"caddyevolved/internal/config"
	"caddyevolved/internal/events"
	"caddyevolved/internal/plugins"
	"caddyevolved/internal/sites"
)

// aclUserIn is what the UI sends: a password only when it changes.
type aclUserIn struct {
	Username string `json:"username"`
	Password string `json:"password,omitempty"`
}

type aclIn struct {
	ID             string      `json:"id"`
	Name           string      `json:"name"`
	Allow          []string    `json:"allow"`
	Deny           []string    `json:"deny"`
	AllowCountries []string    `json:"allowCountries"`
	DenyCountries  []string    `json:"denyCountries"`
	GeoDB          string      `json:"geoDb"`
	Users          []aclUserIn `json:"users"`
}

// aclOut never carries hashes back to the browser.
type aclOut struct {
	sites.AccessList
	Users   []aclUserOut `json:"users"`
	UsedBy  []string     `json:"usedBy"`
	NeedGeo bool         `json:"needsGeo"`
}

type aclUserOut struct {
	Username    string `json:"username"`
	HasPassword bool   `json:"hasPassword"`
}

func (s *Server) handleACLList(w http.ResponseWriter, r *http.Request) {
	lists, err := s.Sites.ListACL()
	if err != nil {
		s.fail(w, r, err, 0)
		return
	}
	siteList, _ := s.Sites.List()
	used := map[string][]string{}
	for _, st := range siteList {
		if st.AccessList != "" {
			used[st.AccessList] = append(used[st.AccessList], st.ID)
		}
	}
	out := make([]aclOut, 0, len(lists))
	for _, a := range lists {
		o := aclOut{AccessList: a, UsedBy: used[a.ID], NeedGeo: a.UsesGeo(), Users: []aclUserOut{}}
		if o.UsedBy == nil {
			o.UsedBy = []string{}
		}
		for _, u := range a.Users {
			o.Users = append(o.Users, aclUserOut{Username: u.Username, HasPassword: u.Hash != ""})
		}
		o.AccessList.Users = nil
		out = append(out, o)
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"accessLists":  out,
		"geoAvailable": s.pluginCompiled(r.Context(), "maxmind-geolocation"),
	})
}

func (s *Server) handleACLCreate(w http.ResponseWriter, r *http.Request) { s.upsertACL(w, r, true) }
func (s *Server) handleACLUpdate(w http.ResponseWriter, r *http.Request) { s.upsertACL(w, r, false) }

func (s *Server) upsertACL(w http.ResponseWriter, r *http.Request, create bool) {
	var in aclIn
	if err := decode(r, &in); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", errText(err))
		return
	}
	if !create {
		in.ID = r.PathValue("id")
	}
	a := sites.AccessList{
		ID: in.ID, Name: in.Name, Allow: in.Allow, Deny: in.Deny,
		AllowCountries: in.AllowCountries, DenyCountries: in.DenyCountries, GeoDB: in.GeoDB,
	}
	for _, u := range in.Users {
		hash := ""
		if u.Password != "" {
			if len(u.Password) < 8 {
				writeErr(w, http.StatusUnprocessableEntity, "invalid_site", "Eingaben prüfen", "Passwort für "+u.Username+": mindestens 8 Zeichen")
				return
			}
			h, err := s.Caddy.HashPassword(r.Context(), u.Password)
			if err != nil {
				s.fail(w, r, err, 0)
				return
			}
			hash = h
		}
		a.Users = append(a.Users, sites.ACLUser{Username: strings.TrimSpace(u.Username), Hash: hash})
	}
	var reloaded bool
	saved, err := s.Sites.UpsertACL(r.Context(), a, create, s.siteCommit(&reloaded))
	verb := "geändert"
	if create {
		verb = "angelegt"
	}
	id := saved.ID
	if id == "" {
		id = a.ID
	}
	s.Events.Record(events.Event{
		Kind: events.KindProxy, Step: "access-list", OK: err == nil,
		Summary: "Access List " + id + " " + verb, Error: errText(err),
		Meta: map[string]any{"accessList": id},
	})
	if err != nil {
		s.siteError(w, r, err)
		return
	}
	status := http.StatusOK
	if create {
		status = http.StatusCreated
	}
	saved.Users = nil
	writeJSON(w, status, map[string]any{"accessList": saved, "reloaded": reloaded})
}

func (s *Server) handleACLDelete(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var reloaded bool
	err := s.Sites.DeleteACL(r.Context(), id, s.siteCommit(&reloaded))
	s.Events.Record(events.Event{
		Kind: events.KindProxy, Step: "access-list", OK: err == nil,
		Summary: "Access List " + id + " gelöscht", Error: errText(err),
	})
	if err != nil {
		s.siteError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "reloaded": reloaded})
}

// --- certificates ---------------------------------------------------------

type certOut struct {
	certs.Cert
	Sites []string `json:"sites"`
}

func (s *Server) handleCertificates(w http.ResponseWriter, r *http.Request) {
	list, err := certs.List(s.Paths.CaddyStorage)
	if err != nil {
		s.fail(w, r, err, 0)
		return
	}
	siteList, _ := s.Sites.List()
	out := make([]certOut, 0, len(list))
	for _, c := range list {
		o := certOut{Cert: c, Sites: []string{}}
		for _, st := range siteList {
			if siteCovers(st, c.Domains) {
				o.Sites = append(o.Sites, st.ID)
			}
		}
		out = append(out, o)
	}
	_, rootErr := certs.RootCA(s.Paths.CaddyStorage)
	writeJSON(w, http.StatusOK, map[string]any{
		"certificates": out, "storage": s.Paths.CaddyStorage, "internalCA": rootErr == nil,
	})
}

// siteCovers reports whether any certificate name serves a site domain,
// counting a wildcard for one label.
func siteCovers(st sites.Site, names []string) bool {
	for _, d := range st.Domains {
		host := strings.ToLower(d)
		if i := strings.LastIndex(host, ":"); i >= 0 {
			host = host[:i]
		}
		for _, n := range names {
			n = strings.ToLower(n)
			if n == host {
				return true
			}
			if rest, ok := strings.CutPrefix(n, "*."); ok {
				if _, after, found := strings.Cut(host, "."); found && after == rest {
					return true
				}
			}
		}
	}
	return false
}

// handleRootCA serves the internal CA root so LAN clients can trust
// `tls internal` sites.
func (s *Server) handleRootCA(w http.ResponseWriter, r *http.Request) {
	data, err := certs.RootCA(s.Paths.CaddyStorage)
	if err != nil {
		if os.IsNotExist(err) {
			writeErr(w, http.StatusNotFound, "not_found", "Noch keine interne CA – sie entsteht mit der ersten Site mit TLS „intern“")
			return
		}
		s.fail(w, r, err, 0)
		return
	}
	w.Header().Set("Content-Type", "application/x-x509-ca-cert")
	w.Header().Set("Content-Disposition", `attachment; filename="caddy-local-root.crt"`)
	w.Write(data)
}

// --- plugin navigation ------------------------------------------------------

// moduleCache remembers the installed binary's modules until the file changes:
// list-modules is cheap but runs on every page load otherwise.
type moduleCache struct {
	mu    sync.Mutex
	mtime time.Time
	size  int64
	mods  []builder.Module
}

func (s *Server) installedModules(ctx context.Context) []builder.Module {
	st, err := os.Stat(s.Paths.CaddyBin)
	if err != nil {
		return nil
	}
	s.modules.mu.Lock()
	defer s.modules.mu.Unlock()
	if st.ModTime().Equal(s.modules.mtime) && st.Size() == s.modules.size && s.modules.mods != nil {
		return s.modules.mods
	}
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	mods, err := builder.ListModules(ctx, s.Paths.CaddyBin)
	if err != nil {
		return nil
	}
	if mods == nil {
		mods = []builder.Module{}
	}
	s.modules.mtime, s.modules.size, s.modules.mods = st.ModTime(), st.Size(), mods
	return mods
}

// pluginCompiled reports whether a catalog plugin is in the installed binary.
func (s *Server) pluginCompiled(ctx context.Context, id string) bool {
	e, ok := plugins.ByID(id)
	if !ok {
		return false
	}
	return builder.HasPackage(s.installedModules(ctx), e.Module)
}

type navItem struct {
	Page     string `json:"page"`
	Label    string `json:"label"`
	Icon     string `json:"icon,omitempty"`
	PluginID string `json:"pluginId"`
	Plugin   string `json:"plugin"`
}

// handleNav lists the sidebar pages contributed by compiled-in plugins. Two
// plugins may share a page (Coraza and caddy-waf are both "WAF"); the first
// one wins, they cannot be built together anyway.
func (s *Server) handleNav(w http.ResponseWriter, r *http.Request) {
	mods := s.installedModules(r.Context())
	items := []navItem{}
	seen := map[string]bool{}
	for _, e := range plugins.All() {
		if e.UI == nil || seen[e.UI.Page] || !builder.HasPackage(mods, e.Module) {
			continue
		}
		seen[e.UI.Page] = true
		items = append(items, navItem{Page: e.UI.Page, Label: e.UI.Label, Icon: e.UI.Icon, PluginID: e.ID, Plugin: e.Name})
	}
	st, _ := config.LoadState(s.Paths.StateFile)
	writeJSON(w, http.StatusOK, map[string]any{"plugins": items, "caddyVersion": st.CaddyVersion})
}
