// Package probe tests sites the way visitors reach them. The doctor command
// and the WebUI's per-site test button share it, so both say the same thing.
package probe

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"caddyevolved/internal/certs"
	"caddyevolved/internal/sites"
)

// Level grades a finding.
type Level string

const (
	OK   Level = "ok"
	Warn Level = "warn"
	Fail Level = "fail"
	Info Level = "info"
)

// Finding is one checked fact plus, when it is not ok, what to do.
type Finding struct {
	Group  string `json:"group"`
	Level  Level  `json:"level"`
	Title  string `json:"title"`
	Detail string `json:"detail,omitempty"`
	Hint   string `json:"hint,omitempty"`
}

// Env is what a site test needs to know about the host.
type Env struct {
	HTTPPort  int
	HTTPSPort int
	// PublicIP is this host's internet address; empty skips the comparison.
	PublicIP string
	// LANIP names the forwarding target in hints.
	LANIP string
	// Extern adds checks from the internet through check-host.net.
	Extern bool
	// Certs are caddy's stored certificates, ACMEErrors the last issuance
	// error per domain.
	Certs      []certs.Cert
	ACMEErrors map[string]string
}

// ---- site ------------------------------------------------------------------

// Site checks every domain of s: DNS, certificate, the route through caddy on
// this host and the public path.
func Site(ctx context.Context, s sites.Site, env Env) []Finding {
	var out []Finding
	group := "Site " + s.ID
	add := func(l Level, title, detail, hint string) {
		out = append(out, Finding{Group: group, Level: l, Title: title, Detail: detail, Hint: hint})
	}
	if !s.Enabled {
		add(Info, "Site ist deaktiviert", "", "In der Liste aktivieren, dann erneut testen")
		return out
	}
	for _, dom := range s.Domains {
		host, ok := Host(dom)
		if !ok {
			add(Info, dom, "Wildcard oder reiner Port – einzelne Namen im Browser testen", "")
			continue
		}
		public := PublicDomain(host) && s.TLS != sites.TLSInternal
		behindCF := false
		if PublicDomain(host) {
			var f Finding
			f, behindCF = dnsFinding(ctx, host, s, env)
			f.Group = group
			out = append(out, f)
		}
		if s.TLS == sites.TLSAuto || s.TLS == sites.TLSDNS {
			if PublicDomain(host) {
				f := certFinding(host, s, env, behindCF)
				f.Group = group
				out = append(out, f)
			}
		}
		for _, f := range localFindings(ctx, s, host, env) {
			f.Group = group
			out = append(out, f)
		}
		if public {
			for _, f := range publicFindings(ctx, s, host, env, behindCF) {
				f.Group = group
				out = append(out, f)
			}
		}
	}
	return out
}

func dnsFinding(ctx context.Context, host string, s sites.Site, env Env) (Finding, bool) {
	c, cancel := context.WithTimeout(ctx, 5*time.Second)
	ips, err := net.DefaultResolver.LookupHost(c, host)
	cancel()
	if err != nil {
		return Finding{Level: Fail, Title: "DNS: " + host + " löst nicht auf", Detail: shortErr(err),
			Hint: "Beim DNS-Anbieter einen A-Eintrag " + host + " → " + orDefault(env.PublicIP, "<öffentliche IP>") + " anlegen"}, false
	}
	if allCloudflare(ips) {
		f := Finding{Level: Info, Title: "DNS: " + host + " läuft über den Cloudflare-Proxy (orange Wolke)", Detail: strings.Join(ips, ", ")}
		if s.TLS == sites.TLSAuto {
			f.Level = Warn
			f.Hint = "Mit Cloudflare-Proxy am besten HTTPS für Besucher auf „DNS-Challenge“ (Cloudflare-Plugin) stellen. " +
				"Sonst in Cloudflare: SSL/TLS-Modus „Full (strict)“ und „Always Use HTTPS“ aus, bis das Zertifikat da ist."
		}
		return f, true
	}
	switch {
	case env.PublicIP == "":
		return Finding{Level: Info, Title: "DNS: " + host + " → " + strings.Join(ips, ", "), Detail: "öffentliche IP unbekannt, nicht verglichen"}, false
	case contains(ips, env.PublicIP):
		return Finding{Level: OK, Title: "DNS: " + host + " zeigt auf diesen Server", Detail: strings.Join(ips, ", ")}, false
	case s.TLS == sites.TLSDNS:
		return Finding{Level: Warn, Title: "DNS: " + host + " zeigt nicht auf diesen Server", Detail: strings.Join(ips, ", ") + " statt " + env.PublicIP,
			Hint: "Fürs Zertifikat egal (DNS-Challenge), Besucher landen aber dort."}, false
	}
	return Finding{Level: Fail, Title: "DNS: " + host + " zeigt nicht auf diesen Server", Detail: strings.Join(ips, ", ") + " statt " + env.PublicIP,
		Hint: "A-Eintrag auf " + env.PublicIP + " ändern."}, false
}

func certFinding(host string, s sites.Site, env Env, behindCF bool) Finding {
	c, found := CoveringCert(env.Certs, host)
	switch {
	case found && c.DaysLeft < 0:
		return Finding{Level: Fail, Title: "Zertifikat für " + host + " abgelaufen", Detail: c.NotAfter.Format("02.01.2006"), Hint: "Logs prüfen: journalctl -u caddy | grep -i " + host}
	case found && c.DaysLeft < 14:
		return Finding{Level: Warn, Title: "Zertifikat für " + host + " läuft bald ab", Detail: fmt.Sprintf("noch %d Tage – die Erneuerung klappt gerade nicht", c.DaysLeft), Hint: "Logs prüfen: journalctl -u caddy | grep -i " + host}
	case found:
		return Finding{Level: OK, Title: "Zertifikat für " + host + " gültig", Detail: fmt.Sprintf("%s, noch %d Tage", c.Issuer, c.DaysLeft)}
	}
	msg := env.ACMEErrors[host]
	hint := "Caddy holt das Zertifikat kurz nach dem Anlegen; eine Minute warten und erneut testen."
	if msg != "" {
		hint = ACMEHint(msg, behindCF, env.LANIP)
	}
	return Finding{Level: Fail, Title: "Noch kein Zertifikat für " + host, Detail: msg, Hint: hint}
}

// ---- local route -----------------------------------------------------------

// Answer is what caddy on this host returned for a site.
type Answer struct {
	Code    int
	Server  string
	CertErr error
	Chain   []*x509.Certificate
}

// Local connects to caddy on 127.0.0.1 but asks for host by name, so SNI,
// certificate and routing are exactly what a visitor gets.
func Local(ctx context.Context, s sites.Site, host string, env Env) (Answer, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	scheme, port := "https", env.HTTPSPort
	if s.TLS == sites.TLSOff {
		scheme, port = "http", env.HTTPPort
	}
	target := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
	get := func(insecure bool) (*http.Response, error) {
		tr := &http.Transport{
			DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, network, target)
			},
			TLSClientConfig: &tls.Config{ServerName: host, InsecureSkipVerify: insecure},
		}
		defer tr.CloseIdleConnections()
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, scheme+"://"+host+"/", nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("User-Agent", "caddyevolved-probe")
		client := &http.Client{Transport: tr, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
		return client.Do(req)
	}
	// Internal-CA certificates are not in the system trust store; the route
	// is what matters here.
	resp, err := get(s.TLS == sites.TLSInternal)
	var ans Answer
	if err != nil && scheme == "https" && IsCertError(err) && !IsNoCertAlert(err) {
		ans.CertErr = err
		resp, err = get(true)
	}
	if err != nil {
		return ans, err
	}
	io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	resp.Body.Close()
	ans.Code, ans.Server = resp.StatusCode, resp.Header.Get("Server")
	if resp.TLS != nil {
		ans.Chain = resp.TLS.PeerCertificates
	}
	return ans, nil
}

func localFindings(ctx context.Context, s sites.Site, host string, env Env) []Finding {
	ans, err := Local(ctx, s, host, env)
	label := host + " auf dem Server"
	switch {
	case err != nil && IsNoCertAlert(err):
		return []Finding{{Level: Fail, Title: label + ": Caddy hat noch kein Zertifikat für diesen Namen", Detail: shortErr(err),
			Hint: "Ohne Zertifikat kann Caddy die Site nicht ausliefern – siehe Zertifikat oben."}}
	case err != nil:
		return []Finding{{Level: Fail, Title: label + ": keine Antwort von Caddy", Detail: shortErr(err),
			Hint: "Caddy-Log prüfen: journalctl -u caddy -n 50"}}
	}
	var out []Finding
	if ans.CertErr != nil {
		out = append(out, Finding{Level: Warn, Title: host + ": Zertifikat noch nicht gültig", Detail: shortErr(ans.CertErr)})
	}
	level, detail, hint := Classify(ans.Code, s)
	if ans.Server != "" && !strings.EqualFold(ans.Server, "caddy") {
		detail += " · Server: " + ans.Server
	}
	return append(out, Finding{Level: level, Title: label + ": HTTP " + strconv.Itoa(ans.Code), Detail: detail, Hint: hint})
}

// Classify explains what an HTTP status means for a proxied site, including
// the 52x codes Cloudflare answers with when it cannot reach the origin.
func Classify(code int, s sites.Site) (Level, string, string) {
	target := strings.Join(s.Upstreams, ", ")
	if s.UpstreamTLS {
		target = "https://" + target
	} else if target != "" {
		target = "http://" + target
	}
	switch {
	case code >= 200 && code < 400:
		return OK, "funktioniert", ""
	case code == 401 || code == 407:
		return OK, "Login verlangt (Access List / Basic Auth)", ""
	case code == 403:
		return Warn, "verboten – Access List, WAF oder Bot-Abwehr hat geblockt", "Ist die eigene IP gesperrt? Analytics → Geblockt zeigt den Grund."
	case code == 404:
		return Info, "Ziel antwortet, aber nicht auf „/“", ""
	case code == 421:
		return Fail, "falsche Zuordnung (421)", "Das Ziel erwartet vermutlich HTTPS – unter „Weiterleiten an“ HTTPS wählen."
	case code == 502 || code == 504:
		return Fail, "Caddy erreicht das Ziel " + target + " nicht",
			"Läuft der Dienst? Stimmen Host, Port und HTTP/HTTPS? Lauscht er nur auf 127.0.0.1 statt im LAN?"
	case code == 503:
		return Fail, "Ziel nicht verfügbar (alle Ziele ausgefallen oder Health-Check rot)", "Dienst und Health-Check-Pfad prüfen"
	case code == 521:
		return Fail, "Cloudflare erreicht deinen Server nicht (521)", "Portweiterleitung 443 im Router auf diesen Server prüfen."
	case code == 522 || code == 523 || code == 524:
		return Fail, fmt.Sprintf("Cloudflare bekommt keine Antwort von deinem Server (%d)", code), "Portweiterleitung und Firewall für 443 prüfen."
	case code == 525:
		return Fail, "TLS zwischen Cloudflare und deinem Server scheitert (525)", "Der Server hat noch kein Zertifikat für den Namen – siehe Zertifikat."
	case code == 526:
		return Fail, "Cloudflare lehnt das Zertifikat deines Servers ab (526)", "Noch kein gültiges Zertifikat; SSL-Modus „Full (strict)“ verlangt eins – siehe Zertifikat."
	case code == 520:
		return Fail, "Cloudflare bekam eine ungültige Antwort (520)", "Caddy-Log prüfen."
	case code >= 500:
		return Warn, "Fehler im Ziel-Dienst", "Log des Dienstes prüfen"
	}
	return Warn, "unerwartete Antwort", ""
}

// ---- public path -----------------------------------------------------------

func publicFindings(ctx context.Context, s sites.Site, host string, env Env, behindCF bool) []Finding {
	scheme := "https"
	if s.TLS == sites.TLSOff {
		scheme = "http"
	}
	url := scheme + "://" + host + "/"
	if env.Extern {
		res, err := ExternalHTTP(ctx, url)
		if err != nil {
			return []Finding{{Level: Warn, Title: host + " öffentlich: externer Test nicht möglich", Detail: err.Error()}}
		}
		reached, tlsOnly, codes, errs := 0, 0, map[int]int{}, []string{}
		for _, r := range res {
			switch {
			case r.Code > 0:
				reached++
				codes[r.Code]++
			case IsNoCertAlert(errors.New(r.Msg)) || strings.Contains(strings.ToLower(r.Msg), "ssl"):
				tlsOnly++
				errs = append(errs, r.Msg)
			case r.Msg != "":
				errs = append(errs, r.Msg)
			}
		}
		switch {
		case reached == 0 && tlsOnly > 0:
			return []Finding{{Level: Fail, Title: fmt.Sprintf("%s von außen erreichbar (%d von %d), aber ohne gültiges Zertifikat", host, tlsOnly, len(res)),
				Detail: strings.Join(Uniq(errs), "; "), Hint: "Der Weg von außen klappt, der Server hat aber kein Zertifikat für den Namen. Zeigt die Portweiterleitung auf " + orDefault(env.LANIP, "diesen Server") + "?"}}
		case reached == 0:
			return []Finding{{Level: Fail, Title: fmt.Sprintf("%s ist von außen NICHT erreichbar (0 von %d Messpunkten)", host, len(res)),
				Detail: strings.Join(Uniq(errs), "; "), Hint: "Portweiterleitung 443/80 im Router, Firewall und DNS prüfen."}}
		}
		code := mostCommon(codes)
		level, detail, hint := Classify(code, s)
		title := fmt.Sprintf("%s von außen erreichbar (%d von %d Messpunkten), HTTP %d", host, reached, len(res), code)
		if level == Fail {
			title = fmt.Sprintf("%s von außen: HTTP %d", host, code)
		}
		if reached < len(res) && level == OK {
			level = Warn
			detail += " · nicht von allen Messpunkten: " + strings.Join(Uniq(errs), "; ")
		}
		return []Finding{{Level: level, Title: title, Detail: detail, Hint: hint}}
	}

	// Without extern: the visitor's path over DNS, from inside. Proves it when
	// it works; through Cloudflare it truly leaves the network, otherwise a
	// failure may be the router's missing hairpin NAT, hence only a warning.
	ctx, cancel := context.WithTimeout(ctx, 12*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	req.Header.Set("User-Agent", "caddyevolved-probe")
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := client.Do(req)
	if err != nil {
		hint := "Von innen oft nicht testbar (Hairpin-NAT). Sicher: Test „von außen“ bzw. doctor --extern, oder am Handy über Mobilfunk öffnen."
		if behindCF {
			hint = "Über Cloudflare geprüft – der Weg Cloudflare → dein Server klappt nicht. Portweiterleitung 443 und Zertifikat prüfen."
		}
		return []Finding{{Level: Warn, Title: host + " öffentlich nicht bestätigt", Detail: shortErr(err), Hint: hint}}
	}
	resp.Body.Close()
	level, detail, hint := Classify(resp.StatusCode, s)
	via := " · über DNS und öffentliche IP geprüft"
	if behindCF {
		via = " · über Cloudflare geprüft"
	}
	return []Finding{{Level: level, Title: fmt.Sprintf("%s öffentlich: HTTP %d", host, resp.StatusCode), Detail: detail + via, Hint: hint}}
}

// ---- certificate view ------------------------------------------------------

// CertInfo describes one certificate of a chain for the WebUI.
type CertInfo struct {
	Subject     string    `json:"subject"`
	Issuer      string    `json:"issuer"`
	DNSNames    []string  `json:"dnsNames,omitempty"`
	NotBefore   time.Time `json:"notBefore"`
	NotAfter    time.Time `json:"notAfter"`
	DaysLeft    int       `json:"daysLeft"`
	Serial      string    `json:"serial"`
	SHA256      string    `json:"sha256"`
	KeyType     string    `json:"keyType"`
	IsCA        bool      `json:"isCa"`
	SelfSigned  bool      `json:"selfSigned"`
	SignatureAl string    `json:"signatureAlgorithm"`
}

// Presented asks caddy on this host which certificate it serves for host and
// whether the system trusts it.
func Presented(ctx context.Context, host string, httpsPort int) (chain []CertInfo, trusted bool, verifyErr string, err error) {
	ctx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	d := tls.Dialer{Config: &tls.Config{ServerName: host, InsecureSkipVerify: true}}
	conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(httpsPort)))
	if err != nil {
		return nil, false, "", err
	}
	defer conn.Close()
	state := conn.(*tls.Conn).ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return nil, false, "", errors.New("keine Zertifikate präsentiert")
	}
	for _, c := range state.PeerCertificates {
		chain = append(chain, Describe(c))
	}
	inter := x509.NewCertPool()
	for _, c := range state.PeerCertificates[1:] {
		inter.AddCert(c)
	}
	if _, verr := state.PeerCertificates[0].Verify(x509.VerifyOptions{DNSName: host, Intermediates: inter}); verr != nil {
		return chain, false, verr.Error(), nil
	}
	return chain, true, "", nil
}

// Describe turns an x509 certificate into its display form.
func Describe(c *x509.Certificate) CertInfo {
	sum := sha256.Sum256(c.Raw)
	key := c.PublicKeyAlgorithm.String()
	return CertInfo{
		Subject:     c.Subject.String(),
		Issuer:      c.Issuer.String(),
		DNSNames:    c.DNSNames,
		NotBefore:   c.NotBefore,
		NotAfter:    c.NotAfter,
		DaysLeft:    int(time.Until(c.NotAfter).Hours() / 24),
		Serial:      strings.ToUpper(c.SerialNumber.Text(16)),
		SHA256:      strings.ToUpper(hex.EncodeToString(sum[:])),
		KeyType:     key,
		IsCA:        c.IsCA,
		SelfSigned:  c.Subject.String() == c.Issuer.String(),
		SignatureAl: c.SignatureAlgorithm.String(),
	}
}

// ---- helpers ---------------------------------------------------------------

// Host turns a site address into a name to request; false for wildcards and
// bare ports.
func Host(dom string) (string, bool) {
	h := strings.TrimPrefix(strings.TrimPrefix(dom, "https://"), "http://")
	if strings.HasPrefix(h, "*.") || strings.HasPrefix(h, ":") || h == "" {
		return "", false
	}
	if host, _, err := net.SplitHostPort(h); err == nil {
		h = host
	}
	return h, true
}

// PublicDomain is a name a public CA can issue for: no IP, no LAN suffix.
func PublicDomain(d string) bool {
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

// CoveringCert finds the newest stored certificate valid for dom.
func CoveringCert(list []certs.Cert, dom string) (certs.Cert, bool) {
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

// IsNoCertAlert is the TLS alert a server sends when it has no certificate
// for the requested name (Caddy: "internal error").
func IsNoCertAlert(err error) bool {
	m := strings.ToLower(err.Error())
	return strings.Contains(m, "tls: internal error") || strings.Contains(m, "alert internal error") || strings.Contains(m, "unrecognized name")
}

// IsCertError matches x509 verification failures and broken handshakes.
func IsCertError(err error) bool {
	msg := err.Error()
	return strings.Contains(msg, "x509:") || strings.Contains(msg, "certificate") || strings.Contains(msg, "tls: ")
}

func shortErr(err error) string {
	msg := err.Error()
	if i := strings.LastIndex(msg, ": "); i > 0 && len(msg) > 160 {
		msg = msg[i+2:]
	}
	return msg
}

// Uniq drops empty and repeated strings, keeping order.
func Uniq(in []string) []string {
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

func contains(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

func mostCommon(m map[int]int) int {
	best, n := 0, -1
	for k, v := range m {
		if v > n || (v == n && k < best) {
			best, n = k, v
		}
	}
	return best
}

func orDefault(v, def string) string {
	if strings.TrimSpace(v) == "" {
		return def
	}
	return v
}
