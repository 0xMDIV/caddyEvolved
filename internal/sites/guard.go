package sites

import (
	"fmt"
	"path"
	"regexp"
	"strings"
)

// Every managed site refuses paths that typically hold secrets – .env files,
// VCS folders, keys, database dumps, backups – before any other handler runs.
// There is no switch to turn this off: an upstream that happens to serve its
// own .env must never leak it through the proxy.
//
// Matching happens on caddy's cleaned, decoded path, so /%2eenv, //.env and
// /a/../.env are caught as well, and case does not matter.

// guardDotSegment matches any path segment that starts with a dot.
const guardDotSegment = `/\.`

// guardWellKnown is the one dot folder the web needs (ACME, carddav,
// security.txt) – as long as nothing below it is hidden again.
const guardWellKnown = `^/\.well-known(/[^./][^/]*)*/?$`

// guardFiles matches names and extensions that hold credentials or data.
const guardFiles = `(?i)(` +
	// extensions, optionally followed by one more (.sql.gz, .env.local)
	`\.(env|bak|backup|old|orig|save|swp|swo|sql|sqlite|sqlite3|db|dump|key|pem|p12|pfx|jks|keystore|kdbx|ovpn|tfstate|tfvars|log|htpasswd)(\.[a-z0-9]+)?$` +
	// editor backups like config.php~
	`|~$` +
	// SSH keys
	`|/id_(rsa|dsa|ecdsa|ed25519)(\.pub)?$` +
	// deployment and secret files by name
	`|/(docker-compose|compose)(\.[a-z0-9-]+)?\.ya?ml$` +
	`|/(credentials|secrets?|\.?passwords?)\.(json|ya?ml|xml|txt|ini|toml)$` +
	`|/(wp-config|configuration|localsettings|settings)\.php\.[a-z0-9]+$` +
	`|/(phpinfo|info)\.php$` +
	`|/web\.config$` +
	`)`

// guardPad is a single long path so caddy sorts the guard before any
// `handle /path/*` a custom site config might contain: handle blocks are
// ordered by the length of their first path, longest first. The `/*` next to
// it is what actually matches.
const guardPad = "/caddyevolved-guard-runs-before-every-other-handle-block-of-this-site"

var (
	reGuardDot   = regexp.MustCompile(guardDotSegment)
	reGuardWK    = regexp.MustCompile(guardWellKnown)
	reGuardFiles = regexp.MustCompile(guardFiles)
)

// GuardRules describes the built-in rules for the UI.
var GuardRules = []string{
	"Versteckte Dateien und Ordner – alles mit Punkt am Anfang: .env, .git, .ssh, .aws, .htpasswd, .DS_Store … (außer /.well-known)",
	"Konfiguration und Zugangsdaten: *.env, docker-compose.yml, compose.yml, credentials.json, secrets.yml, web.config, phpinfo.php",
	"Schlüssel und Zertifikate mit privatem Teil: *.key, *.pem, *.p12, *.pfx, *.jks, *.kdbx, id_rsa, id_ed25519",
	"Datenbanken und Dumps: *.sql, *.sql.gz, *.sqlite, *.sqlite3, *.db, *.dump",
	"Backups und Editor-Reste: *.bak, *.backup, *.old, *.orig, *.save, *.swp, *~, wp-config.php.bak",
	"Logs und Terraform-State: *.log, *.tfstate, *.tfvars",
}

// GuardBlocks reports whether the built-in rules or one of the extra path
// patterns refuse p. It mirrors what renderGuard asks caddy to do, so the UI
// can answer "would this be blocked?".
func GuardBlocks(p string, extra []string) bool {
	p = cleanURLPath(p)
	if reGuardDot.MatchString(p) && !reGuardWK.MatchString(p) {
		return true
	}
	if reGuardFiles.MatchString(p) {
		return true
	}
	for _, pat := range extra {
		if matchCaddyPath(strings.ToLower(pat), strings.ToLower(p)) {
			return true
		}
	}
	return false
}

// ValidGuardPattern checks one extra pattern: a path like caddy's path
// matcher takes it, with * as wildcard.
func ValidGuardPattern(p string) error {
	switch {
	case p == "":
		return fmt.Errorf("leeres Muster")
	case strings.ContainsAny(p, " \t\n{}\"'`#"):
		return fmt.Errorf("%q: keine Leerzeichen, Klammern, Anführungszeichen oder # erlaubt", p)
	case !strings.HasPrefix(p, "/") && !strings.HasPrefix(p, "*"):
		return fmt.Errorf("%q: muss mit / oder * beginnen, z. B. /backup/* oder *.xlsx", p)
	case p == "*" || p == "/*" || p == "/":
		return fmt.Errorf("%q würde die ganze Site sperren", p)
	}
	return nil
}

// renderGuard emits the matchers and the handle block that refuses them.
// A 404 tells a scanner nothing about whether the file exists.
func renderGuard(extra []string) string {
	var b strings.Builder
	b.WriteString("\t# Schutz: Dateien mit Zugangsdaten sind über den Proxy nie erreichbar (caddyEvolved, nicht abschaltbar)\n")
	fmt.Fprintf(&b, "\t@cev_hidden {\n\t\tpath %s /*\n\t\tpath_regexp %s\n\t\tnot path_regexp %s\n\t}\n", guardPad, guardDotSegment, guardWellKnown)
	fmt.Fprintf(&b, "\thandle @cev_hidden {\n\t\tlog_append cev_block geschuetzt\n\t\trespond 404\n\t}\n")
	fmt.Fprintf(&b, "\t@cev_secret {\n\t\tpath %s /*\n\t\tpath_regexp %s\n\t}\n", guardPad, guardFiles)
	fmt.Fprintf(&b, "\thandle @cev_secret {\n\t\tlog_append cev_block geschuetzt\n\t\trespond 404\n\t}\n")
	if len(extra) > 0 {
		fmt.Fprintf(&b, "\t@cev_custom {\n\t\tpath %s %s\n\t}\n", guardPad, strings.Join(extra, " "))
		fmt.Fprintf(&b, "\thandle @cev_custom {\n\t\tlog_append cev_block geschuetzt\n\t\trespond 404\n\t}\n")
	}
	return b.String()
}

// cleanURLPath is what caddy matches on: decoded, slashes merged, dot
// segments resolved.
func cleanURLPath(p string) string {
	if p == "" {
		return "/"
	}
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	trailing := strings.HasSuffix(p, "/") && len(p) > 1
	p = path.Clean(p)
	if trailing && p != "/" {
		p += "/"
	}
	return p
}

// matchCaddyPath follows caddy's path matcher: *x suffix, x* prefix, *x*
// substring, otherwise a glob or an exact path.
func matchCaddyPath(pat, p string) bool {
	switch {
	case strings.HasPrefix(pat, "*") && strings.HasSuffix(pat, "*") && len(pat) > 1:
		return strings.Contains(p, pat[1:len(pat)-1])
	case strings.HasPrefix(pat, "*") && !strings.Contains(pat[1:], "*"):
		return strings.HasSuffix(p, pat[1:])
	case strings.HasSuffix(pat, "*") && !strings.Contains(pat[:len(pat)-1], "*"):
		return strings.HasPrefix(p, pat[:len(pat)-1])
	case strings.Contains(pat, "*"):
		ok, _ := path.Match(pat, p)
		return ok
	}
	return pat == p
}
