package probe

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"caddyevolved/internal/sites"
)

// PublicIP asks a few well-known echo services for this host's IPv4.
func PublicIP(ctx context.Context) (string, error) {
	var last error
	for _, u := range []string{"https://api.ipify.org", "https://ifconfig.me/ip", "https://icanhazip.com"} {
		c, cancel := context.WithTimeout(ctx, 6*time.Second)
		req, _ := http.NewRequestWithContext(c, http.MethodGet, u, nil)
		req.Header.Set("User-Agent", "caddyevolved-probe")
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

// Result is one check-host.net node's answer.
type Result struct {
	Code int
	Msg  string
}

// ExternalHTTP asks check-host.net to fetch url from several places. Each
// node answers [[ok, seconds, message, "code"|null, ip|null]].
func ExternalHTTP(ctx context.Context, url string) ([]Result, error) {
	id, err := checkHostStart(ctx, "check-http", url)
	if err != nil {
		return nil, err
	}
	var out []Result
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
			r := Result{}
			if msg, ok := node[0][2].(string); ok {
				r.Msg = msg
			}
			if c, ok := node[0][3].(string); ok {
				r.Code, _ = strconv.Atoi(c)
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

// ExternalTCP asks check-host.net to open a TCP connection from several
// places. It only learns the IP and port.
func ExternalTCP(ctx context.Context, hostport string) (ok, total int, detail string, err error) {
	id, err := checkHostStart(ctx, "check-tcp", hostport)
	if err != nil {
		return 0, 0, "", err
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
		if err := checkHostGet(ctx, "https://check-host.net/check-result/"+id, &res); err != nil {
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
	return ok, total, strings.Join(Uniq(errs), "; "), nil
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

// ---- ACME ------------------------------------------------------------------

// RecentACMEErrors maps domains to the most telling certificate error caddy
// logged in the past three days.
func RecentACMEErrors(ctx context.Context) map[string]string {
	c, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	data, err := exec.CommandContext(c, "journalctl", "-u", "caddy", "--since", "-72h", "-o", "cat", "--no-pager").Output()
	if err != nil {
		return map[string]string{}
	}
	return parseACMEErrors(data)
}

// parseACMEErrors reads caddy's JSON log lines. The last error of a failed
// attempt is often just "context canceled" or a rate limit; the reason sits in
// an earlier "challenge failed" line, so that one is kept next to it. A
// tls-alpn-01 failure says little (it never works behind a proxy) and only
// counts when nothing else is known. A later success clears the domain.
func parseACMEErrors(data []byte) map[string]string {
	type state struct{ last, challenge, alpn, limited string }
	seen := map[string]*state{}
	for _, line := range bytes.Split(data, []byte("\n")) {
		if !bytes.Contains(line, []byte(`"identifier"`)) {
			continue
		}
		if i := bytes.IndexByte(line, '{'); i > 0 {
			line = line[i:]
		}
		var e struct {
			Level      string `json:"level"`
			Identifier string `json:"identifier"`
			Msg        string `json:"msg"`
			Error      string `json:"error"`
			Challenge  string `json:"challenge_type"`
			Problem    *struct {
				Detail string `json:"detail"`
			} `json:"problem"`
		}
		if json.Unmarshal(line, &e) != nil || e.Identifier == "" {
			continue
		}
		st := seen[e.Identifier]
		if st == nil {
			st = &state{}
			seen[e.Identifier] = st
		}
		switch {
		case e.Msg == "certificate obtained successfully":
			*st = state{}
		case e.Msg == "challenge failed" && e.Problem != nil:
			if e.Challenge == "tls-alpn-01" {
				st.alpn = e.Challenge + ": " + e.Problem.Detail
			} else {
				st.challenge = e.Challenge + ": " + e.Problem.Detail
			}
		case e.Level == "error":
			msg := e.Error
			if msg == "" {
				msg = e.Msg
			}
			if strings.Contains(strings.ToLower(msg), "ratelimited") {
				st.limited = msg
			} else {
				st.last = msg
			}
		}
	}
	out := map[string]string{}
	for id, st := range seen {
		var parts []string
		if st.challenge != "" {
			parts = append(parts, st.challenge)
		} else if st.alpn != "" {
			parts = append(parts, st.alpn)
		}
		if len(parts) == 0 && st.last != "" {
			parts = append(parts, st.last)
		}
		if st.limited != "" {
			parts = append(parts, st.limited)
		}
		if len(parts) == 0 {
			continue
		}
		msg := strings.Join(parts, " · ")
		if len(msg) > 400 {
			msg = msg[:400] + "…"
		}
		out[id] = msg
	}
	return out
}

// ACMEHint turns the usual issuance failures into the step that fixes them.
func ACMEHint(msg string, behindCF bool, lanIP string) string {
	m := strings.ToLower(msg)
	cf := "Mit Cloudflare-Proxy: HTTPS für Besucher auf „DNS-Challenge“ (Cloudflare-Plugin) stellen – das braucht keine offenen Ports. " +
		"Alternativ in Cloudflare „Always Use HTTPS“ aus und unter Security → WAF eine Skip-Regel für den Pfad /.well-known/acme-challenge/ anlegen; " +
		"SSL-Modus „Full (strict)“, sobald das Zertifikat da ist."
	if behindCF && strings.Contains(m, ": 403") {
		h := "Cloudflare blockt die Prüfanfrage von Let's Encrypt (403) – eine Firewall-, Länder- oder Bot-Regel in Cloudflare. " + cf
		if strings.Contains(m, "ratelimited") {
			h += " Nach den Fehlversuchen sperrt Let's Encrypt die Domain gerade für eine Stunde; mit der DNS-Challenge klappt es danach sofort."
		}
		return h
	}
	switch {
	case strings.Contains(m, "ratelimited") && strings.Contains(m, "failed authorizations"):
		h := "Zu viele Fehlversuche – Let's Encrypt sperrt diese Domain für eine Stunde. Erst die Ursache beheben, Caddy versucht es danach selbst erneut."
		if behindCF {
			h += " " + cf
		}
		return h
	case strings.Contains(m, "rate limit") || strings.Contains(m, "ratelimit"):
		return "Let's-Encrypt-Limit erreicht – Caddy versucht es später automatisch erneut."
	case behindCF && (strings.Contains(m, "acme:error:tls") || strings.Contains(m, "unauthorized") || strings.Contains(m, "fetching https://")):
		return cf
	case strings.Contains(m, "acme:error:tls") || strings.Contains(m, "fetching https://"):
		return "Let's Encrypt wurde von Port 80 auf HTTPS umgeleitet – Caddy macht das bei der Challenge nie. Port 80 im Router zeigt wohl auf ein anderes Gerät: auf " + orDefault(lanIP, "diesen Server") + " umstellen."
	case strings.Contains(m, "timeout") || strings.Contains(m, "connection refused") || strings.Contains(m, "connection reset"):
		return "Let's Encrypt erreicht den Server nicht: Portweiterleitung 80/443 und Firewall prüfen (Test von außen)."
	case strings.Contains(m, "nxdomain") || strings.Contains(m, "no valid a records") || strings.Contains(m, "dns problem"):
		return "DNS-Eintrag fehlt oder ist noch nicht verbreitet – A-Eintrag prüfen, ein paar Minuten warten."
	case strings.Contains(m, "rejectedidentifier"):
		return "Für diesen Namen stellt Let's Encrypt grundsätzlich nicht aus (Test-/gesperrte Domain) – echte Domain verwenden oder TLS „Intern“."
	case strings.Contains(m, "unauthorized") || strings.Contains(m, "403"):
		return "Die Challenge landete woanders: zeigt der A-Eintrag wirklich hierher, leitet der Router auf diesen Server?"
	case strings.Contains(m, "dns") && (strings.Contains(m, "token") || strings.Contains(m, "auth") || strings.Contains(m, "credential")):
		return "DNS-Plugin kann sich nicht anmelden – API-Token unter „Plugins & Build“ → Plugins prüfen (beim DNS-Anbieter: Recht „DNS bearbeiten“ für die Zone)."
	}
	return "Details: journalctl -u caddy -n 100"
}

// ---- Cloudflare ------------------------------------------------------------

// cloudflareNets are Cloudflare's published proxy ranges (cloudflare.com/ips).
var cloudflareNets = func() []*net.IPNet {
	var out []*net.IPNet
	for _, c := range sites.CloudflareRanges {
		_, n, _ := net.ParseCIDR(c)
		out = append(out, n)
	}
	return out
}()

// IsCloudflare reports an address in Cloudflare's proxy ranges.
func IsCloudflare(ip string) bool {
	p := net.ParseIP(ip)
	if p == nil {
		return false
	}
	for _, n := range cloudflareNets {
		if n.Contains(p) {
			return true
		}
	}
	return false
}

func allCloudflare(ips []string) bool {
	if len(ips) == 0 {
		return false
	}
	for _, ip := range ips {
		if !IsCloudflare(ip) {
			return false
		}
	}
	return true
}
