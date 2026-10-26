package accesslog

import (
	"regexp"
	"strings"
)

// DefaultRedactParams are query parameters that usually carry a credential.
// Their values never reach the log in full: caddy writes four characters,
// the parser shortens again for lines written before the filter existed.
var DefaultRedactParams = []string{
	"token", "access_token", "api_key", "apikey", "key", "secret", "password",
	"pass", "auth", "sig", "signature", "code", "session",
}

// DefaultRedactHeaders are request headers caddy does not redact on its own
// (it already hides Authorization, Cookie and Set-Cookie).
var DefaultRedactHeaders = []string{"X-Api-Key", "X-Auth-Token", "Proxy-Authorization"}

const mask = "******"

// RedactValue keeps four characters of a long secret so it stays
// recognisable; short ones are hidden completely.
func RedactValue(v string) string {
	if len(v) < 8 {
		return mask
	}
	return v[:4] + mask
}

// RedactURI shortens the values of the given query parameters, matching
// names without regard to case. Everything else stays byte for byte.
func RedactURI(uri string, params []string) string {
	q := strings.IndexByte(uri, '?')
	if q < 0 {
		return uri
	}
	var b strings.Builder
	b.WriteString(uri[:q+1])
	rest := uri[q+1:]
	frag := ""
	if i := strings.IndexByte(rest, '#'); i >= 0 {
		rest, frag = rest[:i], rest[i:]
	}
	for i, part := range strings.Split(rest, "&") {
		if i > 0 {
			b.WriteByte('&')
		}
		name, val, ok := strings.Cut(part, "=")
		if ok && val != "" && isRedacted(name, params) {
			b.WriteString(name + "=" + RedactValue(val))
			continue
		}
		b.WriteString(part)
	}
	b.WriteString(frag)
	return b.String()
}

func isRedacted(name string, params []string) bool {
	for _, p := range params {
		if strings.EqualFold(name, p) {
			return true
		}
	}
	return false
}

// RedactPattern is the RE2 expression for caddy's regexp log filter, used
// with the replacement ${1}${2}******. RE2 has no lookahead, so values
// shorter than eight characters keep up to four in the file; the parser
// hides those completely when it reads them.
func RedactPattern(params []string) string {
	q := make([]string, len(params))
	for i, p := range params {
		q[i] = regexp.QuoteMeta(p)
	}
	return `(?i)([?&](?:` + strings.Join(q, "|") + `)=)([^&#]{0,4})[^&#]*`
}
