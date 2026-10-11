package cli

import (
	"context"
	"errors"
	"fmt"
	"net/mail"
	"sort"
	"strconv"
	"strings"

	"caddyevolved/internal/buildinfo"
	"caddyevolved/internal/install"
	"caddyevolved/internal/platform"
	"caddyevolved/internal/plugins"
	"caddyevolved/internal/releases"
	"caddyevolved/internal/tui"
)

// wizard collects an install.Answers interactively.
//
// It asks in the order the answers depend on each other: the Caddy variant
// decides whether plugins are chosen now, the plugins decide which credentials
// are asked for, and the certificate mode decides whether an email is needed.
type wizard struct {
	ui     tui.UI
	host   platform.Info
	ctx    context.Context
	dryRun bool
}

func newWizard(ctx context.Context, ui tui.UI, host platform.Info, dryRun bool) *wizard {
	return &wizard{ui: ui, host: host, ctx: ctx, dryRun: dryRun}
}

const (
	srcOfficial = iota
	srcCustom
	srcBundle
)

func (w *wizard) run() (install.Answers, error) {
	var a install.Answers
	w.ui.Banner("caddyEvolved Installer "+buildinfo.Version,
		fmt.Sprintf("%s %s · %s · Virtualisierung %s", w.host.Distro, w.host.DistroVer, w.host.Init, orNone(w.host.Virt)))
	if w.dryRun {
		w.ui.Note("Trockendurchlauf", "Es wird nichts geschrieben und kein Passwort gesetzt.")
	}
	if w.host.Init != platform.InitSystemd {
		w.ui.Warn("Kein systemd gefunden – die Dienste starten dann über `caddyevolved start` statt über Units.")
	}

	w.ui.Section("Caddy")
	src, err := w.askSource()
	if err != nil {
		return a, err
	}
	a.BinarySource = []string{"official", "custom", "bundle"}[src]
	if a.CaddyVersion, err = w.askVersion(); err != nil {
		return a, err
	}

	w.ui.Section("Plugins")
	if src == srcCustom {
		if a.Plugins, err = w.askPlugins(); err != nil {
			return a, err
		}
		if len(a.Plugins) == 0 {
			w.ui.Warn("Keine Plugins gewählt – es wird das offizielle Caddy installiert.")
			a.BinarySource = "official"
		}
		if a.Credentials, err = w.askCredentials(a.Plugins); err != nil {
			return a, err
		}
	} else {
		w.notePluginsLater()
	}

	w.ui.Section("Zertifikate")
	if err := w.askCertificates(&a); err != nil {
		return a, err
	}

	w.ui.Section("Ports und WebUI")
	if err := w.askPorts(&a); err != nil {
		return a, err
	}

	w.ui.Section("Erste Site")
	if a.SiteDomain, a.SiteTarget, err = w.askSite(); err != nil {
		return a, err
	}

	a.Force, err = w.askForce(a)
	return a, err
}

func (w *wizard) askSource() (int, error) {
	return w.ui.Select("Welches Caddy soll installiert werden?", []tui.Option{
		{
			Label: "Offizielles Caddy", Tag: "empfohlen",
			Desc: "Original von GitHub, Prüfsumme geprüft, in Sekunden installiert.\n" +
				"Plugins baust du danach jederzeit in der WebUI dazu (Plugins & Build).",
		},
		{
			Label: "Caddy mit Plugins (custom)",
			Desc: "Plugins jetzt auswählen – caddyserver.com baut Caddy damit (1–3 Minuten,\n" +
				"ohne veröffentlichte Prüfsumme). Auch danach in der WebUI änderbar.",
		},
		{
			Label: "Fertiges Paket (bundle)", Disabled: true, Reason: "kommt in einer späteren Version",
			Desc: "Vorgebautes Caddy mit den gängigen Plugins, so schnell wie das offizielle.",
		},
	}, srcOfficial)
}

func (w *wizard) askVersion() (string, error) {
	def := ""
	if rel, err := releases.Latest(w.ctx, "caddyserver/caddy"); err == nil {
		def = rel.Version
	} else {
		w.ui.Warn(fmt.Sprintf("Aktuelle Caddy-Version nicht abrufbar (%v)", err))
	}
	v, err := w.ui.Input("Caddy-Version", tui.InputOpts{Default: def, Help: "Enter = neueste"})
	return strings.TrimPrefix(v, "v"), err
}

// notePluginsLater tells an "official" install where plugins come from.
func (w *wizard) notePluginsLater() {
	var rec []string
	for _, e := range plugins.All() {
		if e.Recommended {
			rec = append(rec, e.Name)
		}
	}
	w.ui.Note("Plugins kommen nach der Installation",
		"In der WebUI unter „Plugins & Build“ ankreuzen, bauen, aktivieren – jederzeit,",
		"ohne Neuinstallation. Die alte Caddy-Binary bleibt als Rollback erhalten.",
		"Empfohlen: "+strings.Join(rec, ", ")+".",
		"Dazu ein DNS-Plugin deines Anbieters, wenn du Wildcard-Zertifikate brauchst.")
}

// pluginGroups orders the catalog for the checklist; recommended entries form
// their own group at the top.
var pluginGroups = []struct {
	cat   plugins.Category
	label string
}{
	{plugins.CatSecurity, "Sicherheit – WAF, Bots, CrowdSec, Geo, Rate Limit"},
	{plugins.CatAuth, "Login und SSO"},
	{plugins.CatDNS, "DNS-Provider – für Wildcard-Zertifikate"},
	{plugins.CatInfra, "Infrastruktur"},
	{plugins.CatStorage, "Zertifikatsspeicher (Cluster)"},
	{plugins.CatCert, "Zertifikate"},
	{plugins.CatObserv, "Monitoring"},
	{plugins.CatUnclassified, "Sonstiges"},
}

var recommendedDesc = map[string]string{
	"coraza":          "Blockt SQL-Injection, XSS und andere Angriffe (OWASP Core Rule Set)",
	"caddy-defender":  "Sperrt KI-Crawler und Bot-Netze",
	"caddy-ratelimit": "Begrenzt Anfragen pro IP gegen Brute-Force und Überlast",
}

func pluginItems() []tui.Item {
	var recommended, rest []tui.Item
	order := map[plugins.Category]int{}
	label := map[plugins.Category]string{}
	for i, g := range pluginGroups {
		order[g.cat], label[g.cat] = i, g.label
	}
	all := plugins.All()
	sort.SliceStable(all, func(i, j int) bool {
		if all[i].Category != all[j].Category {
			return order[all[i].Category] < order[all[j].Category]
		}
		return all[i].Name < all[j].Name
	})
	for _, e := range all {
		if e.Deprecated {
			continue
		}
		it := tui.Item{ID: e.ID, Label: e.Name}
		switch {
		case recommendedDesc[e.ID] != "":
			it.Desc = recommendedDesc[e.ID]
		case e.Category == plugins.CatDNS:
			it.Desc = "DNS-Challenge über " + e.Name
		}
		if len(e.Env) > 0 {
			if it.Desc != "" {
				it.Desc += " · "
			}
			it.Desc += "braucht Zugangsdaten"
		}
		if e.Recommended {
			it.Group, it.Tag, it.Selected = "Empfohlen", "empfohlen", true
			recommended = append(recommended, it)
			continue
		}
		it.Group = label[e.Category]
		if it.Group == "" {
			it.Group = "Sonstiges"
		}
		rest = append(rest, it)
	}
	return append(recommended, rest...)
}

// conflictIn names the first pair of selected plugins that cannot be built
// together, so the wizard can ask again instead of failing at build time.
func conflictIn(ids []string) string {
	sel := map[string]bool{}
	for _, id := range ids {
		sel[id] = true
	}
	for _, id := range ids {
		e, ok := plugins.ByID(id)
		if !ok {
			continue
		}
		for _, c := range e.Conflicts {
			if o, ok := plugins.ByID(c); ok && sel[c] {
				return e.Name + " und " + o.Name + " schließen sich aus (gleiche Caddy-Modul-ID) – bitte eins abwählen."
			}
		}
	}
	return ""
}

func (w *wizard) askPlugins() ([]string, error) {
	items := pluginItems()
	var ids []string
	for {
		var err error
		ids, err = w.ui.Multi("Welche Plugins sollen eingebaut werden?",
			"Die empfohlenen sind vorausgewählt. Später jederzeit in der WebUI änderbar.", items)
		if err != nil {
			return nil, err
		}
		msg := conflictIn(ids)
		if msg == "" {
			break
		}
		w.ui.Warn(msg)
		chosen := map[string]bool{}
		for _, id := range ids {
			chosen[id] = true
		}
		for i := range items {
			items[i].Selected = chosen[items[i].ID]
		}
	}
	extra, err := w.ui.Input("Weitere Go-Module", tui.InputOpts{Help: "optional, kommagetrennt, z. B. github.com/mholt/caddy-l4"})
	if err != nil {
		return nil, err
	}
	for _, tok := range strings.Split(extra, ",") {
		if tok = strings.TrimSpace(tok); tok != "" {
			ids = append(ids, tok)
		}
	}
	return ids, nil
}

// askCredentials walks the env vars the selected modules need. Input is
// hidden; the values end up in /etc/caddyevolved/env (0600, root only).
func (w *wizard) askCredentials(ids []string) (map[string]string, error) {
	out := map[string]string{}
	noted := false
	for _, id := range ids {
		e, ok := plugins.ByID(id)
		if !ok || len(e.Env) == 0 {
			continue
		}
		if !noted {
			w.ui.Section("Zugangsdaten")
			w.ui.Note("", "Eingaben bleiben verborgen und landen nur in /etc/caddyevolved/env (nur root lesbar).",
				"Leer lassen geht auch – später in der WebUI unter „Plugins & Build“ nachtragen.")
			noted = true
		}
		for _, v := range e.Env {
			label := e.Name + ": " + v.Label
			help := v.Help
			if v.Required {
				help = strings.TrimSpace("Pflicht · " + help)
			}
			val, err := w.ui.Input(label, tui.InputOpts{Help: help, Secret: v.Secret})
			if err != nil {
				return nil, err
			}
			if val == "" && v.Required {
				w.ui.Warn(v.Name + " fehlt – " + e.Name + " funktioniert erst, wenn es in der WebUI nachgetragen ist.")
			}
			if val != "" {
				out[v.Name] = val
			}
		}
	}
	return out, nil
}

func (w *wizard) askCertificates(a *install.Answers) error {
	mode, err := w.ui.Select("Woher sollen die HTTPS-Zertifikate kommen?", []tui.Option{
		{
			Label: "Let's Encrypt / ZeroSSL", Tag: "empfohlen",
			Desc: "Für Domains, die aus dem Internet erreichbar sind. Kostenlos, erneuert sich selbst.",
		},
		{
			Label: "Interne CA",
			Desc:  "Nur im LAN (z. B. nas.lan). Die Root-CA importierst du einmal auf deinen Geräten.",
		},
	}, 0)
	if err != nil {
		return err
	}
	a.Managed = mode == 0
	if !a.Managed {
		return nil
	}
	a.Email, err = w.ui.Input("E-Mail für Let's Encrypt", tui.InputOpts{
		Help:     "Warnungen zu ablaufenden Zertifikaten",
		Validate: validEmail,
	})
	return err
}

func validEmail(v string) error {
	addr, err := mail.ParseAddress(v)
	if err != nil || addr.Address != v || !strings.Contains(v[strings.LastIndex(v, "@"):], ".") {
		return errors.New("bitte eine gültige E-Mail-Adresse eingeben")
	}
	domain := strings.ToLower(v[strings.LastIndex(v, "@")+1:])
	if domain == "example.com" || domain == "example.org" || domain == "example.net" {
		return errors.New("Let's Encrypt lehnt example.* ab – bitte eine echte Adresse")
	}
	return nil
}

func validPort(v string) error {
	n, err := strconv.Atoi(v)
	if err != nil || n < 1 || n > 65535 {
		return errors.New("bitte eine Portnummer von 1 bis 65535")
	}
	return nil
}

func (w *wizard) askPorts(a *install.Answers) error {
	a.HTTPPort, a.HTTPSPort, a.AdminPort, a.UIPort, a.UIBind = 80, 443, 2019, 8484, "0.0.0.0"
	w.ui.Note("Standard", "HTTP 80 · HTTPS 443 · Admin-API 2019 (nur localhost) · WebUI 8484 auf allen Adressen")
	std, err := w.ui.Confirm("Standard-Ports verwenden?", true)
	if err != nil || std {
		return err
	}
	ask := func(label string, def int) (int, error) {
		v, err := w.ui.Input(label, tui.InputOpts{Default: strconv.Itoa(def), Validate: validPort})
		if err != nil {
			return 0, err
		}
		return strconv.Atoi(v)
	}
	if a.HTTPPort, err = ask("HTTP-Port", 80); err != nil {
		return err
	}
	if a.HTTPSPort, err = ask("HTTPS-Port", 443); err != nil {
		return err
	}
	if a.AdminPort, err = ask("Admin-Port (nur localhost)", 2019); err != nil {
		return err
	}
	if a.UIPort, err = ask("Port der WebUI", 8484); err != nil {
		return err
	}
	a.UIBind, err = w.ui.Input("Bind-Adresse der WebUI", tui.InputOpts{Default: "0.0.0.0", Help: "127.0.0.1 = nur lokal"})
	return err
}

func (w *wizard) askSite() (string, string, error) {
	now, err := w.ui.Confirm("Jetzt schon eine erste Site anlegen? (geht auch später in der WebUI)", false)
	if err != nil || !now {
		return "", "", err
	}
	domain, err := w.ui.Input("Domain", tui.InputOpts{Help: "z. B. cloud.example.com", Validate: func(v string) error {
		if v == "" || strings.ContainsAny(v, " /{}") {
			return errors.New("bitte einen Hostnamen ohne Leerzeichen und Pfad")
		}
		return nil
	}})
	if err != nil {
		return "", "", err
	}
	target, err := w.ui.Input("Ziel im LAN", tui.InputOpts{Help: "z. B. 192.168.10.40:80", Validate: func(v string) error {
		if v == "" {
			return errors.New("bitte ein Ziel angeben")
		}
		return nil
	}})
	return domain, target, err
}

// askForce only asks when something else already holds the HTTP(S) ports.
func (w *wizard) askForce(a install.Answers) (bool, error) {
	var busy []string
	for _, st := range platform.CheckPorts(w.ctx, a.HTTPPort, a.HTTPSPort) {
		if !st.Free && !st.Own {
			busy = append(busy, fmt.Sprintf("%d (%s)", st.Port, orDefault(st.UsedBy, "unbekannt")))
		}
	}
	if len(busy) == 0 {
		return false, nil
	}
	w.ui.Section("Achtung")
	w.ui.Warn("Belegt: " + strings.Join(busy, ", ") + ". Caddy kann dort sonst nicht starten.")
	return w.ui.Confirm("Bestehende Dienste und Dateien übernehmen (--force)?", false)
}

// summary shows the plan and asks for the go.
func (w *wizard) summary(a install.Answers) (bool, error) {
	w.ui.Section("Zusammenfassung")
	src := map[string]string{"official": "offiziell", "custom": "mit Plugins (caddyserver.com)", "bundle": "Paket"}[a.BinarySource]
	lines := []string{
		"Caddy        " + orDefault(a.CaddyVersion, "neueste") + " · " + orDefault(src, a.BinarySource),
	}
	if len(a.Plugins) > 0 {
		lines = append(lines, "Plugins      "+strings.Join(a.Plugins, ", "))
	}
	if a.Managed {
		lines = append(lines, "Zertifikate  Let's Encrypt · "+a.Email)
	} else {
		lines = append(lines, "Zertifikate  interne CA")
	}
	lines = append(lines, fmt.Sprintf("Ports        HTTP %d · HTTPS %d · Admin %d", a.HTTPPort, a.HTTPSPort, a.AdminPort))
	lines = append(lines, "WebUI        "+install.UIURL(a))
	if a.SiteDomain != "" {
		lines = append(lines, "Erste Site   "+a.SiteDomain+" → "+a.SiteTarget)
	}
	if a.Force {
		lines = append(lines, "Übernehmen   ja (--force)")
	}
	w.ui.Note("", lines...)
	return w.ui.Confirm("Jetzt installieren?", true)
}

func orNone(s string) string {
	if s == "" {
		return "keine"
	}
	return s
}
