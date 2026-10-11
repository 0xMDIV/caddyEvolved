package cli

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"caddyevolved/internal/platform"
	"caddyevolved/internal/sites"
)

// checkSites calls every site the way a visitor would: first straight at
// caddy on this host (does caddy, the certificate and the target work?), then
// over the public path (DNS, router, firewall). Splitting the two tells the
// user which half is broken.
func (d *doctor) checkSites(enabled []sites.Site) {
	d.group = "Sites"
	any := false
	for _, s := range enabled {
		for _, dom := range s.Domains {
			host, ok := probeHost(dom)
			if !ok {
				if strings.HasPrefix(dom, "*.") {
					d.add(levelInfo, dom, "Wildcard – einzelne Namen darunter im Browser testen", "")
				}
				continue
			}
			any = true
			d.checkSiteLocal(s, host)
			if publicDomain(host) && s.TLS != sites.TLSInternal {
				d.checkSitePublic(s, host)
			}
		}
	}
	if !any {
		d.add(levelInfo, "Keine Sites angelegt", "", "In der WebUI unter Sites anlegen")
	}
}

// probeHost turns a site address into a host name to request, or false for
// forms that have none (wildcards, bare ports).
func probeHost(dom string) (string, bool) {
	h := strings.TrimPrefix(strings.TrimPrefix(dom, "https://"), "http://")
	if strings.HasPrefix(h, "*.") || strings.HasPrefix(h, ":") || h == "" {
		return "", false
	}
	if host, _, err := net.SplitHostPort(h); err == nil {
		h = host
	}
	return h, true
}

type siteAnswer struct {
	code    int
	server  string
	certErr error
}

// localSiteProbe connects to caddy on this host but asks for host by name, so
// SNI, certificate and routing are exactly what a visitor gets.
func (d *doctor) localSiteProbe(s sites.Site, host string) (siteAnswer, error) {
	ctx, cancel := context.WithTimeout(d.ctx, 10*time.Second)
	defer cancel()
	scheme, port := "https", d.st.HTTPSPort
	if s.TLS == sites.TLSOff {
		scheme, port = "http", d.st.HTTPPort
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
		req.Header.Set("User-Agent", "caddyevolved-doctor")
		client := &http.Client{Transport: tr, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
		return client.Do(req)
	}
	// Internal CA certificates are not in the system trust store; they are
	// checked under Zertifikate, here only the route matters.
	resp, err := get(s.TLS == sites.TLSInternal)
	var ans siteAnswer
	if err != nil && scheme == "https" && isCertError(err) {
		ans.certErr = err
		resp, err = get(true)
	}
	if err != nil {
		return ans, err
	}
	io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	resp.Body.Close()
	ans.code, ans.server = resp.StatusCode, resp.Header.Get("Server")
	return ans, nil
}

// isNoCertAlert is the TLS alert a server sends when it has no certificate for
// the requested name (Caddy: "internal error").
func isNoCertAlert(err error) bool {
	m := strings.ToLower(err.Error())
	return strings.Contains(m, "tls: internal error") || strings.Contains(m, "alert internal error") || strings.Contains(m, "unrecognized name")
}

// isCertError matches every x509 verification failure (unknown authority,
// wrong name, expired) and a handshake without a usable certificate.
func isCertError(err error) bool {
	msg := err.Error()
	return strings.Contains(msg, "x509:") || strings.Contains(msg, "certificate") || strings.Contains(msg, "tls: ")
}

func (d *doctor) checkSiteLocal(s sites.Site, host string) {
	ans, err := d.localSiteProbe(s, host)
	label := host + " auf dem Server"
	if err != nil && isNoCertAlert(err) {
		// Caddy answers the handshake with an alert when it holds no
		// certificate for the name yet: reached, but not servable.
		d.add(levelFail, label+": Caddy hat noch kein Zertifikat für diesen Namen", shortErr(err), "siehe Abschnitt Zertifikate – dort steht, warum die Ausstellung scheitert")
		return
	}
	if err != nil {
		d.add(levelFail, label+": keine Antwort von Caddy", err.Error(),
			"Caddy-Log prüfen: journalctl -u caddy -n 50 – steht die Site in der Konfiguration (Sites → aktiv)?")
		return
	}
	if ans.certErr != nil {
		d.add(levelWarn, host+": Zertifikat noch nicht gültig", shortErr(ans.certErr), "siehe Abschnitt Zertifikate")
	}
	level, detail, hint := classifyStatus(ans.code, s)
	if ans.server != "" && !strings.EqualFold(ans.server, "caddy") {
		detail += " · Server: " + ans.server
	}
	d.add(level, label+": HTTP "+strconv.Itoa(ans.code), detail, hint)
}

// classifyStatus explains what an HTTP status means for a proxied site.
func classifyStatus(code int, s sites.Site) (checkLevel, string, string) {
	target := strings.Join(s.Upstreams, ", ")
	if s.UpstreamTLS {
		target = "https://" + target
	}
	switch {
	case code >= 200 && code < 400:
		return levelOK, "funktioniert", ""
	case code == 401 || code == 407:
		return levelOK, "Login verlangt (Access List / Basic Auth)", ""
	case code == 403:
		return levelWarn, "verboten – Access List, WAF oder Bot-Abwehr hat geblockt", "Ist die eigene IP gesperrt? Analytics → Geblockt zeigt den Grund."
	case code == 404:
		return levelInfo, "Ziel antwortet, aber nicht auf „/“", ""
	case code == 502 || code == 504:
		return levelFail, "Caddy erreicht das Ziel " + target + " nicht",
			"Läuft der Dienst? Stimmen Host, Port und HTTP/HTTPS? Lauscht er nur auf 127.0.0.1 statt im LAN?"
	case code == 503:
		return levelFail, "Ziel nicht verfügbar (alle Ziele ausgefallen oder Health-Check rot)", "Dienst und Health-Check-Pfad prüfen"
	case code == 421:
		return levelFail, "falsche Domain-Zuordnung (421)", "Das Ziel erwartet HTTPS – unter Weiterleiten an „HTTPS“ wählen"
	case code >= 500:
		return levelWarn, "Fehler im Ziel-Dienst", "Log des Dienstes prüfen"
	}
	return levelWarn, "unerwartete Antwort", ""
}

func shortErr(err error) string {
	msg := err.Error()
	if i := strings.LastIndex(msg, ": "); i > 0 && len(msg) > 160 {
		msg = msg[i+2:]
	}
	return msg
}

func (d *doctor) checkSitePublic(s sites.Site, host string) {
	scheme := "https"
	if s.TLS == sites.TLSOff {
		scheme = "http"
	}
	url := scheme + "://" + host + "/"
	if d.extern {
		res, err := externalHTTP(d.ctx, url)
		if err != nil {
			d.add(levelWarn, host+" öffentlich: externer Test nicht möglich", err.Error(), "")
			return
		}
		reached, tlsOnly, codes, errs := 0, 0, map[int]int{}, []string{}
		for _, r := range res {
			switch {
			case r.code > 0:
				reached++
				codes[r.code]++
			case isNoCertAlert(errors.New(r.msg)) || strings.Contains(strings.ToLower(r.msg), "ssl"):
				tlsOnly++
				errs = append(errs, r.msg)
			case r.msg != "":
				errs = append(errs, r.msg)
			}
		}
		switch {
		case reached == 0 && tlsOnly > 0:
			d.add(levelFail, fmt.Sprintf("%s: von außen erreichbar (%d von %d), aber ohne gültiges Zertifikat", host, tlsOnly, len(res)), strings.Join(uniq(errs), "; "),
				"Der Weg von außen funktioniert, der Server dort hat aber kein Zertifikat für den Namen – siehe Zertifikate. Antwortet hier überhaupt dieser Server? (Portweiterleitung auf "+d.lanIP()+"?)")
		case reached == 0:
			d.add(levelFail, fmt.Sprintf("%s ist von außen NICHT erreichbar (0 von %d Messpunkten)", host, len(res)), strings.Join(uniq(errs), "; "),
				"Portweiterleitung 443/80 im Router, Firewall und DNS prüfen – die Abschnitte oben zeigen, welcher Teil fehlt.")
		default:
			code := mostCommon(codes)
			level, detail, hint := classifyStatus(code, s)
			title := fmt.Sprintf("%s von außen erreichbar (%d von %d Messpunkten), HTTP %d", host, reached, len(res), code)
			if level == levelFail {
				title = fmt.Sprintf("%s von außen erreichbar, aber HTTP %d", host, code)
			}
			if reached < len(res) && level == levelOK {
				level = levelWarn
				detail += " · nicht von allen Messpunkten: " + strings.Join(uniq(errs), "; ")
			}
			d.add(level, title, detail, hint)
		}
		return
	}

	// Without --extern: the normal path over DNS and the public IP, from
	// inside. Proves it when it works; a failure may be the router's lack of
	// hairpin NAT, hence only a warning.
	ctx, cancel := context.WithTimeout(d.ctx, 10*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	req.Header.Set("User-Agent", "caddyevolved-doctor")
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := client.Do(req)
	if err != nil {
		d.add(levelWarn, host+" öffentlich nicht bestätigt", shortErr(err),
			"Von innen oft nicht testbar (Hairpin-NAT). Sicher: sudo caddyevolved doctor --extern, oder am Handy über Mobilfunk öffnen.")
		return
	}
	resp.Body.Close()
	level, detail, hint := classifyStatus(resp.StatusCode, s)
	d.add(level, fmt.Sprintf("%s öffentlich erreichbar, HTTP %d", host, resp.StatusCode), detail+" · über DNS und öffentliche IP geprüft", hint)
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

type hostResult struct {
	code int
	msg  string
}

// externalHTTP asks check-host.net to fetch url from several places. Each
// node answers [[ok, seconds, message, "code"|null, ip|null]].
func externalHTTP(ctx context.Context, url string) ([]hostResult, error) {
	id, err := checkHostStart(ctx, "check-http", url)
	if err != nil {
		return nil, err
	}
	var out []hostResult
	for i := 0; i < 10; i++ {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(2 * time.Second):
		}
		var res map[string][][]any
		if err := checkHostGet(ctx, "https://check-host.net/check-result/"+id, &res); err != nil {
			return nil, err
		}
		out = out[:0]
		pending := false
		for _, node := range res {
			if node == nil {
				pending = true
				continue
			}
			if len(node) == 0 || len(node[0]) < 4 {
				continue
			}
			r := hostResult{}
			if msg, ok := node[0][2].(string); ok {
				r.msg = msg
			}
			if c, ok := node[0][3].(string); ok {
				r.code, _ = strconv.Atoi(c)
			}
			out = append(out, r)
		}
		if !pending && len(out) > 0 {
			return out, nil
		}
	}
	if len(out) == 0 {
		return nil, errors.New("check-host.net hat keine Ergebnisse geliefert")
	}
	return out, nil
}

func checkHostStart(ctx context.Context, kind, host string) (string, error) {
	var start struct {
		OK        int    `json:"ok"`
		RequestID string `json:"request_id"`
	}
	if err := checkHostGet(ctx, "https://check-host.net/"+kind+"?max_nodes=4&host="+host, &start); err != nil {
		return "", err
	}
	if start.OK != 1 || start.RequestID == "" {
		return "", errors.New("check-host.net hat die Prüfung abgelehnt")
	}
	return start.RequestID, nil
}

func checkHostGet(ctx context.Context, u string, into any) error {
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

func (d *doctor) lanIP() string { return orDefault(platform.PrimaryIP(), "diesen Server") }
