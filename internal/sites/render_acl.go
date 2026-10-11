package sites

import (
	"fmt"
	"path/filepath"
	"strings"
)

// renderACL emits the checks for one list. The caller wraps them and the
// site's handlers in a `route` block: caddy's default order runs basic_auth
// before respond, and a blocked address must not even see a login prompt.
// The checks use `client_ip`, which equals the peer address unless
// trusted_proxies is configured, and stays right behind a proxy once it is.
// Each refusal tags the access log (cev_block) for Analytics.
func renderACL(a AccessList, opt Options) string {
	var b strings.Builder
	fmt.Fprintf(&b, "\t\t# Access List: %s\n", a.Name)
	if len(a.Deny) > 0 {
		fmt.Fprintf(&b, "\t\t@cf_acl_deny client_ip %s\n", strings.Join(a.Deny, " "))
		b.WriteString("\t\tlog_append @cf_acl_deny cev_block acl-ip\n")
		b.WriteString("\t\trespond @cf_acl_deny \"Zugriff verweigert\" 403\n")
	}
	if len(a.Allow) > 0 {
		fmt.Fprintf(&b, "\t\t@cf_acl_notallowed not client_ip %s\n", strings.Join(a.Allow, " "))
		b.WriteString("\t\tlog_append @cf_acl_notallowed cev_block acl-ip\n")
		b.WriteString("\t\trespond @cf_acl_notallowed \"Zugriff verweigert\" 403\n")
	}
	if db := a.geoDB(opt); a.UsesGeo() && db != "" {
		// The maxmind matcher matches *permitted* requests for both
		// allow_countries and deny_countries, so the block is its negation.
		// Private addresses are unknown to every geo database and would fall
		// under "not allowed" – the own network always passes.
		b.WriteString("\t\t@cf_acl_geo {\n\t\t\tnot client_ip private_ranges\n\t\t\tnot {\n\t\t\t\tmaxmind_geolocation {\n")
		fmt.Fprintf(&b, "\t\t\t\t\tdb_path %s\n", filepath.ToSlash(db))
		if len(a.AllowCountries) > 0 {
			fmt.Fprintf(&b, "\t\t\t\t\tallow_countries %s\n", strings.Join(a.AllowCountries, " "))
		}
		if len(a.DenyCountries) > 0 {
			fmt.Fprintf(&b, "\t\t\t\t\tdeny_countries %s\n", strings.Join(a.DenyCountries, " "))
		}
		b.WriteString("\t\t\t\t}\n\t\t\t}\n\t\t}\n")
		b.WriteString("\t\tlog_append @cf_acl_geo cev_block acl-land\n")
		b.WriteString("\t\trespond @cf_acl_geo \"Zugriff aus diesem Land nicht erlaubt\" 403\n")
	}
	if len(a.Users) > 0 {
		b.WriteString("\t\tbasic_auth {\n")
		for _, u := range a.Users {
			fmt.Fprintf(&b, "\t\t\t%s %s\n", u.Username, u.Hash)
		}
		b.WriteString("\t\t}\n")
	}
	return b.String()
}

// geoDB is the list's own database or, without one, the DB-IP database
// caddyEvolved downloads. Empty means country rules cannot run yet.
func (a AccessList) geoDB(opt Options) string {
	if a.GeoDB != "" {
		return a.GeoDB
	}
	if opt.Caps.Geo {
		return opt.GeoDB
	}
	return ""
}
