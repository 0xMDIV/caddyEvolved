package cli

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"caddyevolved/internal/certs"
	"caddyevolved/internal/config"
	"caddyevolved/internal/platform"
	"caddyevolved/internal/sites"
	"caddyevolved/internal/tui"
)

// doctor checks the whole path a visitor takes: services and ports on this
// host, firewall, public IP and port forwarding, DNS of every site and the
// certificates caddy obtained. Each finding carries the fix.

type checkLevel string

const (
	levelOK   checkLevel = "ok"
	levelWarn checkLevel = "warn"
	levelFail checkLevel = "fail"
	levelInfo checkLevel = "info"
)

type finding struct {
	Group  string     `json:"group"`
	Level  checkLevel `json:"level"`
	Title  string     `json:"title"`
	Detail string     `json:"detail,omitempty"`
	Hint   string     `json:"hint,omitempty"`
}

type doctor struct {
	ctx      context.Context
	l        *layout
	st       config.State
	findings []finding
	group    string
	publicIP string
	extern   bool
}

func (d *doctor) add(level checkLevel, title, detail, hint string) {
	d.findings = append(d.findings, finding{Group: d.group, Level: level, Title: title, Detail: detail, Hint: hint})
}

func cmdDoctor(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("doctor", flag.ContinueOnError)
	fs.SetOutput(stderr)
	root := fs.String("root", envDefault("CADDYEVOLVED_ROOT", ""), "Installation in diesem Baum prüfen")
	extern := fs.Bool("extern", false, "Ports 80/443 zusätzlich von außen prüfen (über check-host.net)")
	jsonOut := fs.Bool("json", false, "JSON ausgeben")
	if err := fs.Parse(args); err != nil {
		return err
	}

	view, err := collectStatus(ctx, *root, true)
	if err != nil {
		return err
	}
	l := newLayout(ctx, *root)
	st, _ := l.state()
	d := &doctor{ctx: ctx, l: l, st: st, extern: *extern}
	paint := tui.PaintFor(stdout)
	if !*jsonOut {
		fmt.Fprintln(stdout, paint.Bold(paint.Cyan("◆ caddyEvolved Doctor")))
	}
	if !view.Installed {
		d.group = "Installation"
		d.add(levelFail, "caddyEvolved ist hier nicht installiert", "", "sudo caddyevolved install")
		return d.finish(stdout, *jsonOut)
	}

	enabled := d.enabledSites()
	d.checkServices(view)
	d.checkPorts(view, enabled)
	d.checkFirewall()
	d.checkPublic(enabled)
	d.checkDomains(enabled)
	d.checkCertificates(enabled)
	return d.finish(stdout, *jsonOut)
}

// ---- local -----------------------------------------------------------------

func (d *doctor) checkServices(v statusView) {
	d.group = "Dienste"
	if v.Service.Problem == "" {
		d.add(levelOK, "Caddy läuft", v.Service.Active, "")
	} else {
		d.add(levelFail, "Caddy läuft nicht", v.Service.Problem, "journalctl -u caddy -n 50  zeigt den Grund; danach systemctl restart caddy")
	}
	if v.DaemonService != nil {
		if v.DaemonService.Problem == "" {
			d.add(levelOK, "caddyEvolved-Dienst läuft", v.DaemonService.Active, "")
		} else {
			d.add(levelFail, "caddyEvolved-Dienst läuft nicht", v.DaemonService.Problem, "journalctl -u caddyevolved -n 50; systemctl restart caddyevolved")
		}
	}
	if v.Admin.Reach == "ja" {
		d.add(levelOK, "Admin-API antwortet", v.Admin.URL, "")
	} else {
		d.add(levelFail, "Admin-API antwortet nicht", v.Admin.URL+" "+v.Admin.Problem, "Ohne Admin-API kann caddyEvolved Caddy nicht neu laden – Caddy neu starten")
	}
	if v.UI.Reach == "antwortet" {
		d.add(levelOK, "WebUI antwortet", v.UI.URL, "")
	} else {
		d.add(levelFail, "WebUI antwortet nicht", v.UI.URL+" "+v.UI.Problem, "systemctl status caddyevolved")
	}
}

func (d *doctor) checkPorts(v statusView, enabled []sites.Site) {
	d.group = "Ports auf diesem Server"
	needsWeb := false
	for _, s := range enabled {
		if len(s.Domains) > 0 {
			needsWeb = true
		}
	}
	for _, p := range v.Ports {
		name := map[int]string{d.st.HTTPPort: "HTTP", d.st.HTTPSPort: "HTTPS", d.st.AdminPort: "Admin-API", d.st.UIPort: "WebUI"}[p.Port]
		label := fmt.Sprintf("Port %d (%s)", p.Port, name)
		switch {
		case p.Own:
			d.add(levelOK, label+" lauscht", "", "")
		case p.Listener:
			d.add(levelFail, label+" ist von einem anderen Programm belegt", orDefault(p.UsedBy, "unbekannter Prozess"),
				"Das andere Programm stoppen (z. B. systemctl disable --now apache2 nginx), dann systemctl restart caddy")
		case (p.Port == d.st.HTTPPort || p.Port == d.st.HTTPSPort) && !needsWeb:
			d.add(levelInfo, label+" noch frei", "Caddy öffnet 80/443 erst, wenn eine Site angelegt ist", "")
		default:
			d.add(levelFail, label+" lauscht nicht", "", "systemctl restart caddy caddyevolved; Fehler: journalctl -u caddy -n 50")
		}
	}
}

// checkFirewall reads ufw, the firewall Ubuntu ships. Other firewalls are
// only mentioned, their rule sets are too varied to judge reliably.
func (d *doctor) checkFirewall() {
	d.group = "Firewall"
	out, err := exec.CommandContext(d.ctx, "ufw", "status").Output()
	if err != nil {
		if _, lookErr := exec.LookPath("ufw"); lookErr != nil {
			d.add(levelInfo, "ufw nicht installiert", "eine andere Firewall (nftables, Proxmox) wird nicht geprüft", "")
		} else {
			d.add(levelWarn, "ufw-Status nicht lesbar", err.Error(), "als root ausführen: sudo caddyevolved doctor")
		}
		return
	}
	text := string(out)
	if !strings.Contains(text, "Status: active") {
		d.add(levelInfo, "ufw ist aus", "alle Ports offen – Port "+strconv.Itoa(d.st.UIPort)+" (WebUI) nur im LAN lassen", "")
		return
	}
	for _, p := range []int{d.st.HTTPPort, d.st.HTTPSPort} {
		if ufwAllows(text, p) {
			d.add(levelOK, fmt.Sprintf("ufw lässt Port %d durch", p), "", "")
		} else {
			d.add(levelFail, fmt.Sprintf("ufw blockiert Port %d", p), "", fmt.Sprintf("sudo ufw allow %d/tcp", p))
		}
	}
	if ufwAllows(text, d.st.UIPort) {
		d.add(levelOK, fmt.Sprintf("ufw lässt die WebUI (Port %d) durch", d.st.UIPort), "", "")
	} else {
		d.add(levelWarn, fmt.Sprintf("ufw blockiert die WebUI (Port %d)", d.st.UIPort), "",
			fmt.Sprintf("nur aus dem LAN freigeben: sudo ufw allow from 192.168.0.0/16 to any port %d proto tcp", d.st.UIPort))
	}
}

// ufwAllows looks for an ALLOW rule naming the port (plain, /tcp, or a
// "Apache Full"-style app profile is not resolved).
func ufwAllows(status string, port int) bool {
	p := strconv.Itoa(port)
	sc := bufio.NewScanner(strings.NewReader(status))
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) < 2 || !strings.Contains(sc.Text(), "ALLOW") {
			continue
		}
		to := strings.Split(f[0], "/")[0]
		for _, part := range strings.Split(to, ",") {
			if part == p {
				return true
			}
			if lo, hi, ok := strings.Cut(part, ":"); ok {
				a, _ := strconv.Atoi(lo)
				b, _ := strconv.Atoi(hi)
				if port >= a && port <= b {
					return true
				}
			}
		}
	}
	return false
}

// ---- internet --------------------------------------------------------------

func (d *doctor) checkPublic(enabled []sites.Site) {
	d.group = "Internet"
	lan := platform.PrimaryIP()
	ip, err := publicIP(d.ctx)
	if err != nil {
		d.add(levelFail, "Öffentliche IP nicht ermittelbar", err.Error(), "Hat der Server Internet? ping 1.1.1.1; DNS: resolvectl status")
		return
	}
	d.publicIP = ip
	if ip == lan {
		d.add(levelOK, "Öffentliche IP "+ip, "liegt direkt auf dem Server, keine Portweiterleitung nötig", "")
	} else {
		d.add(levelInfo, "Öffentliche IP "+ip, "Server-IP im LAN: "+lan+" – der Router muss 80/443 dorthin weiterleiten", "")
	}

	// Without a site caddy does not listen yet; testing the forwarding would
	// only report a refusal that is expected.
	host := ""
	for _, s := range enabled {
		for _, dom := range s.Domains {
			if publicDomain(dom) && s.TLS != sites.TLSInternal {
				host = strings.TrimPrefix(dom, "*.")
				break
			}
		}
		if host != "" {
			break
		}
	}
	if host == "" {
		d.add(levelInfo, "Weiterleitung nicht geprüft", "noch keine öffentliche Site angelegt", "")
		return
	}

	// Hairpin: from inside to our own public IP. Proves the forwarding when
	// it works; many routers cannot do it, so a failure is only a warning.
	if server, err := probeHTTP(d.ctx, ip, d.st.HTTPPort, host); err == nil && strings.Contains(strings.ToLower(server), "caddy") {
		d.add(levelOK, fmt.Sprintf("Port %d über die öffentliche IP erreicht Caddy", d.st.HTTPPort), "aus dem eigenen Netz geprüft (Hairpin-NAT)", "")
	} else {
		detail := "keine Antwort von Caddy"
		if err != nil {
			detail = err.Error()
		} else if server != "" {
			detail = "antwortet: " + server + " – die Weiterleitung zeigt auf ein anderes Gerät"
		}
		d.add(levelWarn, fmt.Sprintf("Port %d über die öffentliche IP nicht bestätigt", d.st.HTTPPort), detail,
			"Viele Router können das von innen nicht (Hairpin-NAT). Sicher prüfen: sudo caddyevolved doctor --extern")
	}

	if !d.extern {
		return
	}
	for _, port := range []int{d.st.HTTPPort, d.st.HTTPSPort} {
		ok, total, detail, err := externalTCP(d.ctx, net.JoinHostPort(ip, strconv.Itoa(port)))
		switch {
		case err != nil:
			d.add(levelWarn, fmt.Sprintf("Externer Test Port %d nicht möglich", port), err.Error(), "")
		case ok == total:
			d.add(levelOK, fmt.Sprintf("Port %d von außen erreichbar", port), fmt.Sprintf("%d von %d Messpunkten weltweit", ok, total), "")
		case ok == 0:
			d.add(levelFail, fmt.Sprintf("Port %d von außen NICHT erreichbar", port), detail,
				fmt.Sprintf("Im Router TCP %d → %s:%d weiterleiten; beim Provider prüfen, ob Port %d gesperrt ist (DS-Lite/CGNAT?)", port, platform.PrimaryIP(), port, port))
		default:
			d.add(levelWarn, fmt.Sprintf("Port %d nur teilweise erreichbar", port), fmt.Sprintf("%d von %d Messpunkten: %s", ok, total, detail), "")
		}
	}
}

func publicIP(ctx context.Context) (string, error) {
	var last error
	for _, u := range []string{"https://api.ipify.org", "https://ifconfig.me/ip", "https://icanhazip.com"} {
		ctx, cancel := context.WithTimeout(ctx, 6*time.Second)
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
		req.Header.Set("User-Agent", "caddyevolved-doctor")
		resp, err := http.DefaultClient.Do(req)
		if err == nil {
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 100))
			resp.Body.Close()
			cancel()
			if ip := net.ParseIP(strings.TrimSpace(string(body))); ip != nil && ip.To4() != nil {
				return ip.String(), nil
			}
			last = fmt.Errorf("%s: unerwartete Antwort", u)
			continue
		}
		cancel()
		last = err
	}
	return "", last
}

// probeHTTP sends one plain request to ip:port with the given Host and returns
// the Server header. Redirects are not followed: caddy answers port 80 with a
// redirect to HTTPS, which already proves it is caddy.
func probeHTTP(ctx context.Context, ip string, port int, host string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 6*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+net.JoinHostPort(ip, strconv.Itoa(port))+"/", nil)
	if err != nil {
		return "", err
	}
	req.Host = host
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	resp.Body.Close()
	return resp.Header.Get("Server"), nil
}

// externalTCP asks check-host.net to open a TCP connection from several
// places on the internet. It only learns the IP and port, not the domain.
func externalTCP(ctx context.Context, hostport string) (ok, total int, detail string, err error) {
	get := func(u string, into any) error {
		c, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		req, _ := http.NewRequestWithContext(c, http.MethodGet, u, nil)
		req.Header.Set("Accept", "application/json")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("check-host.net: %s", resp.Status)
		}
		return json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(into)
	}
	var start struct {
		OK        int    `json:"ok"`
		RequestID string `json:"request_id"`
	}
	if err := get("https://check-host.net/check-tcp?max_nodes=4&host="+hostport, &start); err != nil {
		return 0, 0, "", err
	}
	if start.OK != 1 || start.RequestID == "" {
		return 0, 0, "", errors.New("check-host.net hat die Prüfung abgelehnt")
	}
	var errs []string
	for i := 0; i < 8; i++ {
		select {
		case <-ctx.Done():
			return 0, 0, "", ctx.Err()
		case <-time.After(2 * time.Second):
		}
		var res map[string][]struct {
			Address string  `json:"address"`
			Time    float64 `json:"time"`
			Error   string  `json:"error"`
		}
		if err := get("https://check-host.net/check-result/"+start.RequestID, &res); err != nil {
			return 0, 0, "", err
		}
		pending := false
		ok, total, errs = 0, len(res), nil
		for _, r := range res {
			switch {
			case r == nil:
				pending = true
			case len(r) > 0 && r[0].Error == "" && r[0].Address != "":
				ok++
			case len(r) > 0:
				errs = append(errs, r[0].Error)
			}
		}
		if !pending {
			break
		}
	}
	return ok, total, strings.Join(uniq(errs), "; "), nil
}

func uniq(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if s != "" && !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

// ---- domains and certificates ---------------------------------------------

func (d *doctor) enabledSites() []sites.Site {
	list, err := sites.New(d.l.paths.SitesFile, d.l.paths.SitesDir, d.l.paths.Caddyfile).List()
	if err != nil {
		return nil
	}
	var out []sites.Site
	for _, s := range list {
		if s.Enabled {
			out = append(out, s)
		}
	}
	return out
}

// publicDomain is a name a public CA can issue for and DNS on the internet
// can resolve: no IP, no port-only address, no LAN-only suffix.
func publicDomain(d string) bool {
	d = strings.TrimPrefix(strings.TrimPrefix(strings.TrimPrefix(d, "http://"), "https://"), "*.")
	if h, _, err := net.SplitHostPort(d); err == nil {
		d = h
	}
	if d == "" || net.ParseIP(d) != nil || !strings.Contains(d, ".") || d == "localhost" {
		return false
	}
	for _, suf := range []string{".lan", ".local", ".home", ".internal", ".localhost", ".home.arpa", ".fritz.box"} {
		if strings.HasSuffix("."+d, suf) {
			return false
		}
	}
	return true
}

func (d *doctor) checkDomains(enabled []sites.Site) {
	d.group = "DNS"
	any := false
	for _, s := range enabled {
		for _, dom := range s.Domains {
			if !publicDomain(dom) {
				continue
			}
			any = true
			host := strings.TrimPrefix(dom, "*.")
			if strings.HasPrefix(dom, "*.") {
				// Any name below the wildcard must resolve; test a random one.
				host = "caddyevolved-doctor-" + strconv.FormatInt(time.Now().Unix()%100000, 10) + "." + host
			}
			c, cancel := context.WithTimeout(d.ctx, 5*time.Second)
			ips, err := net.DefaultResolver.LookupHost(c, host)
			cancel()
			switch {
			case err != nil:
				d.add(levelFail, dom+" löst nicht auf", err.Error(), "Beim DNS-Anbieter einen A-Eintrag "+dom+" → "+orDefault(d.publicIP, "<öffentliche IP>")+" anlegen")
			case d.publicIP == "":
				d.add(levelInfo, dom+" → "+strings.Join(ips, ", "), "öffentliche IP unbekannt, nicht verglichen", "")
			case contains(ips, d.publicIP):
				d.add(levelOK, dom+" zeigt auf diesen Server", strings.Join(ips, ", "), "")
			case s.TLS == sites.TLSDNS:
				d.add(levelWarn, dom+" zeigt nicht auf diesen Server", strings.Join(ips, ", ")+" statt "+d.publicIP,
					"Für das Zertifikat egal (DNS-Challenge), Besucher landen aber dort – Proxy wie Cloudflare? Dann ok.")
			default:
				d.add(levelFail, dom+" zeigt nicht auf diesen Server", strings.Join(ips, ", ")+" statt "+d.publicIP,
					"A-Eintrag auf "+d.publicIP+" ändern. Cloudflare-Proxy (orange Wolke) blockiert die HTTP-Challenge nicht, verdeckt aber die IP – dann ist das hier normal.")
			}
		}
	}
	if !any {
		d.add(levelInfo, "Keine öffentlichen Domains", "nur LAN-Namen oder noch keine Site", "")
	}
}

func contains(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

func (d *doctor) checkCertificates(enabled []sites.Site) {
	d.group = "Zertifikate"
	list, err := certs.List(d.l.paths.CaddyStorage)
	if err != nil {
		d.add(levelWarn, "Zertifikatsspeicher nicht lesbar", err.Error(), "als root ausführen: sudo caddyevolved doctor")
		return
	}
	acmeErrs := recentACMEErrors(d.ctx)
	checked := false
	for _, s := range enabled {
		if s.TLS == sites.TLSOff || s.TLS == sites.TLSInternal {
			continue
		}
		for _, dom := range s.Domains {
			if !publicDomain(dom) {
				continue
			}
			checked = true
			c, found := coveringCert(list, dom)
			switch {
			case found && c.DaysLeft < 0:
				d.add(levelFail, dom+": Zertifikat abgelaufen", c.NotAfter.Format("02.01.2006"), "Logs prüfen: journalctl -u caddy | grep -i "+dom)
			case found && c.DaysLeft < 14:
				d.add(levelWarn, dom+": Zertifikat läuft bald ab", fmt.Sprintf("noch %d Tage – Caddy erneuert ab 30 Tagen, das klappt gerade nicht", c.DaysLeft), "Logs prüfen: journalctl -u caddy | grep -i "+dom)
			case found:
				d.add(levelOK, dom+": Zertifikat gültig", fmt.Sprintf("%s, noch %d Tage", c.Issuer, c.DaysLeft), "")
			default:
				msg := acmeErrs[strings.TrimPrefix(dom, "*.")]
				if msg == "" {
					msg = acmeErrs[dom]
				}
				hint := "Domain einmal im Browser aufrufen; Caddy holt das Zertifikat beim ersten Zugriff bzw. kurz nach dem Anlegen."
				if msg != "" {
					hint = acmeHint(msg)
				}
				d.add(levelFail, dom+": noch kein Zertifikat", msg, hint)
			}
		}
	}
	if !checked {
		d.add(levelInfo, "Keine öffentlichen Zertifikate erwartet", "", "")
	}
}

func coveringCert(list []certs.Cert, dom string) (certs.Cert, bool) {
	var best certs.Cert
	found := false
	for _, c := range list {
		if c.Staging {
			continue
		}
		for _, n := range c.Domains {
			if n == dom || (strings.HasPrefix(n, "*.") && strings.Count(dom, ".") == strings.Count(n, ".") && strings.HasSuffix(dom, n[1:])) {
				if !found || c.NotAfter.After(best.NotAfter) {
					best, found = c, true
				}
			}
		}
	}
	return best, found
}

// recentACMEErrors maps domains to the last certificate error caddy logged in
// the past day.
func recentACMEErrors(ctx context.Context) map[string]string {
	out := map[string]string{}
	c, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	data, err := exec.CommandContext(c, "journalctl", "-u", "caddy", "--since", "-24h", "-o", "cat", "--no-pager").Output()
	if err != nil {
		return out
	}
	for _, line := range bytes.Split(data, []byte("\n")) {
		if !bytes.Contains(line, []byte(`"error"`)) || !bytes.Contains(line, []byte(`"tls`)) {
			continue
		}
		var e struct {
			Level      string `json:"level"`
			Logger     string `json:"logger"`
			Identifier string `json:"identifier"`
			Msg        string `json:"msg"`
			Error      string `json:"error"`
		}
		if json.Unmarshal(line, &e) != nil || e.Level != "error" || e.Identifier == "" {
			continue
		}
		msg := e.Msg
		if e.Error != "" {
			msg = e.Error
		}
		if len(msg) > 220 {
			msg = msg[:220] + "…"
		}
		out[e.Identifier] = msg
	}
	return out
}

// acmeHint turns the usual ACME failures into the step that fixes them.
func acmeHint(msg string) string {
	m := strings.ToLower(msg)
	switch {
	case strings.Contains(m, "timeout") || strings.Contains(m, "connection refused") || strings.Contains(m, "connection reset"):
		return "Let's Encrypt erreicht den Server nicht: Portweiterleitung 80/443 und Firewall prüfen (sudo caddyevolved doctor --extern)."
	case strings.Contains(m, "nxdomain") || strings.Contains(m, "no valid a records") || strings.Contains(m, "dns problem"):
		return "DNS-Eintrag fehlt oder ist noch nicht verbreitet – A-Eintrag prüfen, ein paar Minuten warten."
	case strings.Contains(m, "rejectedidentifier"):
		return "Für diesen Namen stellt Let's Encrypt grundsätzlich nicht aus (Test-/gesperrte Domain) – echte Domain verwenden oder TLS „Intern“."
	case strings.Contains(m, "rate limit") || strings.Contains(m, "ratelimit"):
		return "Let's-Encrypt-Limit erreicht – Caddy versucht es automatisch später erneut, nichts weiter tun."
	case strings.Contains(m, "unauthorized") || strings.Contains(m, "403"):
		return "Die Challenge landete woanders: zeigt der A-Eintrag wirklich hierher, leitet der Router auf diesen Server?"
	case strings.Contains(m, "dns") && (strings.Contains(m, "token") || strings.Contains(m, "auth") || strings.Contains(m, "credential")):
		return "DNS-Plugin kann sich nicht anmelden – API-Token unter „Plugins & Build“ prüfen."
	}
	return "Details: journalctl -u caddy -n 100"
}

// ---- output ----------------------------------------------------------------

func (d *doctor) finish(w io.Writer, jsonOut bool) error {
	fails, warns := 0, 0
	for _, f := range d.findings {
		switch f.Level {
		case levelFail:
			fails++
		case levelWarn:
			warns++
		}
	}
	if jsonOut {
		if err := encode(w, map[string]any{"findings": d.findings, "failures": fails, "warnings": warns}); err != nil {
			return err
		}
	} else {
		p := tui.PaintFor(w)
		group := ""
		for _, f := range d.findings {
			if f.Group != group {
				group = f.Group
				fmt.Fprintf(w, "\n%s\n", p.Bold(group))
			}
			mark := map[checkLevel]string{levelOK: p.Green("✔"), levelWarn: p.Yellow("!"), levelFail: p.Red("✖"), levelInfo: p.Cyan("ℹ")}[f.Level]
			line := "  " + mark + " " + f.Title
			if f.Detail != "" {
				line += "  " + p.Dim(f.Detail)
			}
			fmt.Fprintln(w, line)
			if f.Hint != "" && f.Level != levelOK {
				fmt.Fprintln(w, "      "+p.Cyan("→ ")+f.Hint)
			}
		}
		fmt.Fprintln(w)
		switch {
		case fails > 0:
			fmt.Fprintln(w, p.Red(fmt.Sprintf("%d Problem(e), %d Hinweis(e) – die Pfeile zeigen, was zu tun ist.", fails, warns)))
		case warns > 0:
			fmt.Fprintln(w, p.Yellow(fmt.Sprintf("Keine Fehler, %d Hinweis(e).", warns)))
		default:
			fmt.Fprintln(w, p.Green("Alles in Ordnung."))
		}
		if !d.extern && d.publicIP != "" {
			fmt.Fprintln(w, p.Dim("Tipp: --extern prüft die Ports zusätzlich von außen (über check-host.net, übermittelt nur IP und Port)."))
		}
	}
	if fails > 0 {
		return errDoctorFailed{fails}
	}
	return nil
}

// errDoctorFailed sets a non-zero exit code; the report already said why.
type errDoctorFailed struct{ n int }

func (e errDoctorFailed) Error() string { return fmt.Sprintf("%d Problem(e) gefunden", e.n) }
