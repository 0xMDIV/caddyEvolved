package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"

	"caddyevolved/internal/buildinfo"
)

// MCP (Model Context Protocol) endpoint for AI clients.
//
// The server is dual-era: modern clients (revision 2026-07-28) send
// stateless requests with per-request _meta and may call server/discover;
// legacy clients open with initialize. Both are answered on POST /mcp.
// Every tool is a thin wrapper around the REST API, executed in-process with
// the caller's own credential, so validation, the token scope and the audit
// log apply exactly as for any other client.

const mcpModern = "2026-07-28"

var mcpLegacy = []string{"2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05"}

type rpcRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    any    `json:"data,omitempty"`
}

type rpcResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  any             `json:"result,omitempty"`
	Error   *rpcError       `json:"error,omitempty"`
}

const mcpInstructions = `caddyEvolved manages a Caddy reverse proxy on a Linux host.
Sites are virtual hosts (domains -> upstreams) stored as one Caddyfile snippet each; every change is validated by caddy and rolled back if rejected.
Typical flow: list_sites, then create_site/update_site with the full site object. Use get_site_preview to see the generated Caddyfile before writing.
Plugins are compiled into the caddy binary: list_plugins shows what is built in; start_build + activate_build change the binary (caddy restarts briefly).
Security per site: accessList (IP/basic-auth lists), waf (Coraza, plugin coraza), defender (bot ranges), rateLimit. Read analytics with get_analytics before suggesting rate limits.
Host-wide: get_firewall/firewall_ip block or allow single IPs on every site; query_access_log and get_firewall_log show who did what; get_global_options holds the trusted proxies.
Prefer read tools first; ask the user before destructive actions (delete_site, activate_build, rollback_build, service_action stop).`

func (s *Server) handleMCP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		writeErr(w, http.StatusMethodNotAllowed, "method", "MCP: nur POST")
		return
	}
	if !sameOrigin(r) {
		writeErr(w, http.StatusForbidden, "cross_origin", "Fremde Herkunft verweigert")
		return
	}
	sess, ok := s.resolveSession(r)
	if !ok || !sess.Bearer {
		w.Header().Set("WWW-Authenticate", `Bearer realm="caddyEvolved"`)
		writeErr(w, http.StatusUnauthorized, "unauthenticated", "MCP braucht Authorization: Bearer <API-Token> (Einstellungen → API-Tokens)")
		return
	}
	var req rpcRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, maxBody)).Decode(&req); err != nil || req.Method == "" {
		writeJSON(w, http.StatusBadRequest, rpcResponse{JSONRPC: "2.0", ID: json.RawMessage("null"), Error: &rpcError{Code: -32700, Message: "parse error"}})
		return
	}

	var params struct {
		Meta map[string]json.RawMessage `json:"_meta"`
	}
	json.Unmarshal(req.Params, &params)
	version := ""
	if raw, ok := params.Meta["io.modelcontextprotocol/protocolVersion"]; ok {
		json.Unmarshal(raw, &version)
	}
	modern := version != ""
	if modern && version != mcpModern {
		s.mcpReply(w, http.StatusOK, req.ID, nil, &rpcError{Code: -32022, Message: "Unsupported protocol version",
			Data: map[string]any{"supported": append([]string{mcpModern}, mcpLegacy...), "requested": version}})
		return
	}
	// The method header must agree with the body when the client sends it.
	if h := r.Header.Get("Mcp-Method"); h != "" && h != req.Method {
		s.mcpReply(w, http.StatusBadRequest, req.ID, nil, &rpcError{Code: -32020, Message: "Mcp-Method header does not match body"})
		return
	}

	if len(req.ID) == 0 || string(req.ID) == "null" {
		// A notification (initialized, cancelled): nothing to answer.
		w.WriteHeader(http.StatusAccepted)
		return
	}

	complete := func(m map[string]any) map[string]any {
		if modern {
			m["resultType"] = "complete"
		}
		return m
	}
	info := map[string]any{"name": "caddyEvolved", "version": buildinfo.Version}

	switch req.Method {
	case "initialize":
		var p struct {
			ProtocolVersion string `json:"protocolVersion"`
		}
		json.Unmarshal(req.Params, &p)
		chosen := mcpLegacy[0]
		for _, v := range mcpLegacy {
			if v == p.ProtocolVersion {
				chosen = v
			}
		}
		s.mcpReply(w, http.StatusOK, req.ID, map[string]any{
			"protocolVersion": chosen,
			"capabilities":    map[string]any{"tools": map[string]any{"listChanged": false}},
			"serverInfo":      info,
			"instructions":    mcpInstructions,
		}, nil)
	case "server/discover":
		s.mcpReply(w, http.StatusOK, req.ID, complete(map[string]any{
			"supportedVersions": append([]string{mcpModern}, mcpLegacy...),
			"capabilities":      map[string]any{"tools": map[string]any{}},
			"_meta":             map[string]any{"io.modelcontextprotocol/serverInfo": info},
			"instructions":      mcpInstructions,
		}), nil)
	case "ping":
		s.mcpReply(w, http.StatusOK, req.ID, complete(map[string]any{}), nil)
	case "tools/list":
		list := make([]map[string]any, 0, len(mcpTools))
		for _, t := range mcpTools {
			if sess.Scope == "read" && !t.ReadOnly {
				continue // a read token sees only what it may call
			}
			list = append(list, t.describe())
		}
		s.mcpReply(w, http.StatusOK, req.ID, complete(map[string]any{"tools": list}), nil)
	case "tools/call":
		var p struct {
			Name      string         `json:"name"`
			Arguments map[string]any `json:"arguments"`
		}
		if err := json.Unmarshal(req.Params, &p); err != nil {
			s.mcpReply(w, http.StatusOK, req.ID, nil, &rpcError{Code: -32602, Message: "invalid params"})
			return
		}
		tool, ok := mcpToolByName(p.Name)
		if !ok {
			s.mcpReply(w, http.StatusOK, req.ID, nil, &rpcError{Code: -32602, Message: "unknown tool " + p.Name})
			return
		}
		text, isErr := s.runTool(r, tool, p.Arguments)
		s.mcpReply(w, http.StatusOK, req.ID, complete(map[string]any{
			"content": []map[string]any{{"type": "text", "text": text}},
			"isError": isErr,
		}), nil)
	default:
		status := http.StatusOK
		if modern {
			status = http.StatusNotFound
		}
		s.mcpReply(w, status, req.ID, nil, &rpcError{Code: -32601, Message: "method not found: " + req.Method})
	}
}

func (s *Server) mcpReply(w http.ResponseWriter, status int, id json.RawMessage, result any, rerr *rpcError) {
	if len(id) == 0 {
		id = json.RawMessage("null")
	}
	writeJSON(w, status, rpcResponse{JSONRPC: "2.0", ID: id, Result: result, Error: rerr})
}

// runTool maps arguments onto one REST call and returns the body as text.
func (s *Server) runTool(r *http.Request, t mcpTool, args map[string]any) (string, bool) {
	if args == nil {
		args = map[string]any{}
	}
	text, isErr, _, _, _ := s.callTool(r.Context(), r, t, args, "mcp", "")
	return text, isErr
}

// callTool runs one tool in-process as the caller of r. via names the
// client in the audit log ("mcp", "ai"); chat is the AI chat it came from.
func (s *Server) callTool(ctx context.Context, r *http.Request, t mcpTool, args map[string]any, via, chat string) (text string, isErr bool, method, path string, status int) {
	method, path, body, err := t.Request(args)
	if err != nil {
		return "Argumentfehler: " + err.Error(), true, method, path, 0
	}
	status, data := s.internalCall(ctx, r, method, path, body, via, chat)
	text = string(bytes.TrimSpace(data))
	if t.Shape != nil && status < 400 {
		var v any
		if json.Unmarshal(data, &v) == nil {
			if out, err := json.Marshal(t.Shape(v)); err == nil {
				text = string(out)
			}
		}
	}
	if status >= 400 {
		return fmt.Sprintf("HTTP %d: %s", status, text), true, method, path, status
	}
	return text, false, method, path, status
}

// internalCall runs a REST request in-process with the caller's own
// credential: the bearer token of an MCP client, or the browser session of
// the user who approved an AI proposal. Validation, scope and the audit
// log apply exactly as for any other client.
func (s *Server) internalCall(ctx context.Context, r *http.Request, method, path string, body any, via, chat string) (int, []byte) {
	var rd io.Reader
	if body != nil {
		data, _ := json.Marshal(body)
		rd = bytes.NewReader(data)
	}
	req, err := http.NewRequestWithContext(ctx, method, path, rd)
	if err != nil {
		return http.StatusBadRequest, []byte(err.Error())
	}
	req.Host = r.Host
	req.RemoteAddr = r.RemoteAddr
	if a := r.Header.Get("Authorization"); a != "" {
		req.Header.Set("Authorization", a)
	}
	if c := r.Header.Get("Cookie"); c != "" && via == "ai" {
		req.Header.Set("Cookie", c)
		// The user's click on "Ausführen" passed the CSRF gate already.
		req.Header.Set(HeaderGate, "1")
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-CaddyEvolved-Via", via)
	if chat != "" {
		req.Header.Set("X-CaddyEvolved-Chat", chat)
	}
	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, req)
	return rec.Code, rec.Body.Bytes()
}

// mcpTool describes one tool and how it maps to the REST API.
type mcpTool struct {
	Name        string
	Description string
	ReadOnly    bool
	Destructive bool
	Schema      map[string]any
	Request     func(args map[string]any) (method, path string, body any, err error)
	// Shape trims a large response to what a model needs.
	Shape func(v any) any
}

func (t mcpTool) describe() map[string]any {
	schema := t.Schema
	if schema == nil {
		schema = obj(nil)
	}
	return map[string]any{
		"name":        t.Name,
		"description": t.Description,
		"inputSchema": schema,
		"annotations": map[string]any{"readOnlyHint": t.ReadOnly, "destructiveHint": t.Destructive},
	}
}

func mcpToolByName(name string) (mcpTool, bool) {
	for _, t := range mcpTools {
		if t.Name == name {
			return t, true
		}
	}
	return mcpTool{}, false
}

// --- schema helpers ---

func obj(props map[string]any, required ...string) map[string]any {
	if props == nil {
		props = map[string]any{}
	}
	m := map[string]any{"type": "object", "properties": props}
	if len(required) > 0 {
		m["required"] = required
	}
	return m
}

func str(desc string) map[string]any { return map[string]any{"type": "string", "description": desc} }
func boolean(desc string) map[string]any {
	return map[string]any{"type": "boolean", "description": desc}
}
func integer(desc string) map[string]any {
	return map[string]any{"type": "integer", "description": desc}
}
func enum(desc string, vals ...string) map[string]any {
	return map[string]any{"type": "string", "enum": vals, "description": desc}
}
func strList(desc string) map[string]any {
	return map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": desc}
}

var siteSchema = obj(map[string]any{
	"id":               str("site id (a-z0-9-); derived from the first domain when empty on create"),
	"domains":          strList("host names, e.g. app.example.com, or :8080"),
	"mode":             enum("what the site does", "proxy", "redirect", "static", "raw"),
	"upstreams":        strList("proxy targets host:port or https://host:port"),
	"upstreamTls":      boolean("talk TLS to the upstream"),
	"upstreamInsecure": boolean("skip upstream certificate verification"),
	"lbPolicy":         str("load balancing policy, e.g. round_robin, least_conn"),
	"healthUri":        str("active health check path, e.g. /health"),
	"tls":              enum("certificate", "auto", "internal", "dns", "off"),
	"dnsProvider":      str("DNS plugin id for tls=dns, e.g. cloudflare"),
	"compress":         boolean("zstd/gzip compression"),
	"redirectTo":       str("target URL for mode=redirect"),
	"root":             str("directory for mode=static"),
	"extra":            str("extra Caddyfile directives inside the site block"),
	"raw":              str("full block body for mode=raw"),
	"accessList":       str("access list id"),
	"cloudflare":       obj(map[string]any{"proxied": boolean("route visitors through Cloudflare (orange cloud)")}),
	"enabled":          boolean("site is active"),
	"waf":              obj(map[string]any{"enabled": boolean(""), "mode": enum("", "block", "detect")}),
	"defender":         obj(map[string]any{"enabled": boolean(""), "responder": enum("", "block", "tarpit", "garbage", "drop"), "ranges": strList("openai, aws, deepseek, githubcopilot, … or CIDRs")}),
	"rateLimit":        obj(map[string]any{"enabled": boolean(""), "events": integer("requests per window and client IP"), "window": str("e.g. 1m")}),
}, "domains")

var aclSchema = obj(map[string]any{
	"name":           str("display name"),
	"allow":          strList("only these IPs/CIDRs (or private_ranges) may connect"),
	"deny":           strList("blocked IPs/CIDRs"),
	"allowCountries": strList("ISO country codes allowed (needs plugin maxmind-geolocation)"),
	"denyCountries":  strList("ISO country codes blocked"),
	"geoDb":          str("path to GeoLite2-Country.mmdb"),
	"users":          map[string]any{"type": "array", "items": obj(map[string]any{"username": str(""), "password": str("new password; empty keeps the old one")})},
}, "name")

func argString(args map[string]any, key string) string {
	if v, ok := args[key].(string); ok {
		return strings.TrimSpace(v)
	}
	return ""
}

func needID(args map[string]any) (string, error) {
	id := argString(args, "id")
	if id == "" {
		return "", fmt.Errorf("id fehlt")
	}
	return url.PathEscape(id), nil
}

func withQuery(path string, args map[string]any, keys ...string) string {
	q := url.Values{}
	for _, k := range keys {
		switch v := args[k].(type) {
		case string:
			if v != "" {
				q.Set(k, v)
			}
		case float64:
			q.Set(k, fmt.Sprint(int(v)))
		}
	}
	if len(q) == 0 {
		return path
	}
	return path + "?" + q.Encode()
}

func get(path string) func(map[string]any) (string, string, any, error) {
	return func(map[string]any) (string, string, any, error) { return http.MethodGet, path, nil, nil }
}

var mcpTools = []mcpTool{
	{Name: "get_status", ReadOnly: true, Description: "Health of caddy and caddyEvolved: service state, caddy version, admin API, ports, warnings.",
		Request: get("/api/status"),
		Shape: func(v any) any {
			m, _ := v.(map[string]any)
			delete(m, "enabledPlugins")
			return m
		}},
	{Name: "list_sites", ReadOnly: true, Description: "All sites with domains, mode, upstreams, TLS and security settings.",
		Request: get("/api/sites")},
	{Name: "get_site_preview", ReadOnly: true, Description: "Render a site to its Caddyfile snippet without saving; returns problems if invalid.",
		Schema: siteSchema,
		Request: func(a map[string]any) (string, string, any, error) {
			return http.MethodPost, "/api/sites/preview", a, nil
		}},
	{Name: "create_site", Description: "Create a site. caddy validates and reloads; on rejection nothing changes and the error is returned.",
		Schema: siteSchema,
		Request: func(a map[string]any) (string, string, any, error) {
			if _, ok := a["enabled"]; !ok {
				a["enabled"] = true
			}
			return http.MethodPost, "/api/sites", a, nil
		}},
	{Name: "update_site", Description: "Replace a site (send the complete site object; read it with list_sites first).",
		Schema: siteSchema,
		Request: func(a map[string]any) (string, string, any, error) {
			id, err := needID(a)
			return http.MethodPut, "/api/sites/" + id, a, err
		}},
	{Name: "set_site_enabled", Description: "Switch a site on or off.",
		Schema: obj(map[string]any{"id": str("site id"), "enabled": boolean("")}, "id", "enabled"),
		Request: func(a map[string]any) (string, string, any, error) {
			id, err := needID(a)
			return http.MethodPost, "/api/sites/" + id + "/enabled", map[string]any{"enabled": a["enabled"]}, err
		}},
	{Name: "delete_site", Destructive: true, Description: "Delete a site.",
		Schema: obj(map[string]any{"id": str("site id")}, "id"),
		Request: func(a map[string]any) (string, string, any, error) {
			id, err := needID(a)
			return http.MethodDelete, "/api/sites/" + id, nil, err
		}},
	{Name: "list_access_lists", ReadOnly: true, Description: "Access lists (IP allow/deny, countries, basic-auth users) and which sites use them.",
		Request: get("/api/access-lists")},
	{Name: "create_access_list", Description: "Create an access list; assign it to a site via update_site accessList.",
		Schema: aclSchema,
		Request: func(a map[string]any) (string, string, any, error) {
			return http.MethodPost, "/api/access-lists", a, nil
		}},
	{Name: "update_access_list", Description: "Replace an access list (users without password keep theirs).",
		Schema: func() map[string]any {
			s := obj(nil, "id", "name")
			props := map[string]any{"id": str("access list id")}
			for k, v := range aclSchema["properties"].(map[string]any) {
				props[k] = v
			}
			s["properties"] = props
			return s
		}(),
		Request: func(a map[string]any) (string, string, any, error) {
			id, err := needID(a)
			return http.MethodPut, "/api/access-lists/" + id, a, err
		}},
	{Name: "delete_access_list", Destructive: true, Description: "Delete an access list that no site uses.",
		Schema: obj(map[string]any{"id": str("access list id")}, "id"),
		Request: func(a map[string]any) (string, string, any, error) {
			id, err := needID(a)
			return http.MethodDelete, "/api/access-lists/" + id, nil, err
		}},
	{Name: "list_certificates", ReadOnly: true, Description: "TLS certificates caddy holds, with issuer, expiry and the sites they serve.",
		Request: get("/api/certificates")},
	{Name: "get_analytics", ReadOnly: true, Description: "Traffic statistics: totals, time series, top paths/IPs/agents/status codes, blocked requests.",
		Schema: obj(map[string]any{"range": enum("time range", "15m", "1h", "6h", "24h", "7d", "30d"), "site": str("site id (optional)")}),
		Request: func(a map[string]any) (string, string, any, error) {
			return http.MethodGet, withQuery("/api/analytics", a, "range", "site"), nil, nil
		},
		Shape: func(v any) any {
			// The full series is long; models need totals and top lists.
			m, _ := v.(map[string]any)
			if rep, ok := m["report"].(map[string]any); ok {
				delete(rep, "series")
			}
			return m
		}},
	{Name: "recent_requests", ReadOnly: true, Description: "The newest requests (host, path, status, duration, client IP, user agent).",
		Schema: obj(map[string]any{"limit": integer("max 300, default 50"), "site": str("site id (optional)")}),
		Request: func(a map[string]any) (string, string, any, error) {
			if _, ok := a["limit"]; !ok {
				a["limit"] = float64(50)
			}
			return http.MethodGet, withQuery("/api/analytics/recent", a, "limit", "site"), nil, nil
		}},
	{Name: "get_logs", ReadOnly: true, Description: "Process log lines of caddy or caddyevolved.",
		Schema: obj(map[string]any{"unit": enum("", "caddy", "caddyevolved"), "lines": integer("default 100"), "grep": str("case-insensitive filter")}),
		Request: func(a map[string]any) (string, string, any, error) {
			return http.MethodGet, withQuery("/api/logs", a, "unit", "lines", "grep"), nil, nil
		}},
	{Name: "get_caddyfile", ReadOnly: true, Description: "The main Caddyfile (global options and the import of the site snippets).",
		Request: get("/api/caddyfile")},
	{Name: "validate_caddyfile", ReadOnly: true, Description: "Check Caddyfile text with the installed caddy without saving.",
		Schema: obj(map[string]any{"content": str("Caddyfile text")}, "content"),
		Request: func(a map[string]any) (string, string, any, error) {
			return http.MethodPost, "/api/caddyfile/validate", map[string]any{"content": a["content"]}, nil
		}},
	{Name: "list_plugins", ReadOnly: true, Description: "Plugin catalog: id, name, category, whether it is compiled into the running caddy.",
		Request: get("/api/plugins"),
		Shape: func(v any) any {
			m, _ := v.(map[string]any)
			list, _ := m["plugins"].([]any)
			out := make([]map[string]any, 0, len(list))
			for _, x := range list {
				p, _ := x.(map[string]any)
				out = append(out, map[string]any{"id": p["id"], "name": p["name"], "category": p["category"], "detected": p["detected"], "note": p["note"]})
			}
			return map[string]any{"caddyVersion": m["caddyVersion"], "plugins": out}
		}},
	{Name: "list_builds", ReadOnly: true, Description: "Custom caddy builds, which one is active, whether a build is running.",
		Request: get("/api/builds")},
	{Name: "get_build", ReadOnly: true, Description: "One build with the last log lines.",
		Schema: obj(map[string]any{"id": str("build id")}, "id"),
		Request: func(a map[string]any) (string, string, any, error) {
			id, err := needID(a)
			return http.MethodGet, "/api/builds/" + id, nil, err
		},
		Shape: func(v any) any {
			m, _ := v.(map[string]any)
			if log, ok := m["log"].([]any); ok && len(log) > 40 {
				m["log"] = log[len(log)-40:]
			}
			return m
		}},
	{Name: "start_build", Description: "Compile caddy with plugins on the server (takes 1-3 minutes; poll get_build). Does not change the running binary.",
		Schema: obj(map[string]any{"caddyVersion": str("e.g. v2.11.7 or latest"), "plugins": strList("catalog ids or go module paths")}, "plugins"),
		Request: func(a map[string]any) (string, string, any, error) {
			return http.MethodPost, "/api/builds", a, nil
		}},
	{Name: "activate_build", Destructive: true, Description: "Install a finished build as the live caddy (restart with automatic rollback if unhealthy). Ask the user first.",
		Schema: obj(map[string]any{"id": str("build id")}, "id"),
		Request: func(a map[string]any) (string, string, any, error) {
			id, err := needID(a)
			return http.MethodPost, "/api/builds/" + id + "/activate", nil, err
		}},
	{Name: "rollback_build", Destructive: true, Description: "Swap back to the previous caddy binary.",
		Request: func(map[string]any) (string, string, any, error) {
			return http.MethodPost, "/api/builds/rollback", nil, nil
		}},
	{Name: "service_action", Destructive: true, Description: "reload (validate + zero-downtime), restart, start or stop caddy.",
		Schema: obj(map[string]any{"action": enum("", "reload", "restart", "start", "stop")}, "action"),
		Request: func(a map[string]any) (string, string, any, error) {
			act := argString(a, "action")
			switch act {
			case "reload", "restart", "start", "stop":
			default:
				return "", "", nil, fmt.Errorf("action: reload, restart, start oder stop")
			}
			return http.MethodPost, "/api/service/" + act + "?unit=caddy.service", nil, nil
		}},
	{Name: "get_audit_log", ReadOnly: true, Description: "Who changed what: mutating API calls and logins, newest first.",
		Schema: obj(map[string]any{"limit": integer("default 50")}),
		Request: func(a map[string]any) (string, string, any, error) {
			if _, ok := a["limit"]; !ok {
				a["limit"] = float64(50)
			}
			return http.MethodGet, withQuery("/api/audit", a, "limit"), nil, nil
		}},
	{Name: "get_firewall", ReadOnly: true, Description: "Firewall rules (allow/deny IPs, countries, ASNs, blocklists, auto-ban) and the current auto-bans.",
		Request: get("/api/firewall")},
	{Name: "get_firewall_log", ReadOnly: true, Description: "Recently blocked requests, WAF matches and the most blocked IPs of the last 24 hours.",
		Request: get("/api/firewall/log")},
	{Name: "firewall_ip", Description: "Block or allow one IP or CIDR on every site, or lift a block or auto-ban.",
		Schema: obj(map[string]any{"ip": str("IP or CIDR"), "action": enum("", "block", "allow", "unblock", "unban")}, "ip", "action"),
		Request: func(a map[string]any) (string, string, any, error) {
			switch argString(a, "action") {
			case "block", "allow", "unblock", "unban":
			default:
				return "", "", nil, fmt.Errorf("action: block, allow, unblock oder unban")
			}
			return http.MethodPost, "/api/firewall/quick", map[string]any{"ip": argString(a, "ip"), "action": argString(a, "action")}, nil
		}},
	{Name: "update_firewall", Description: "Replace the firewall rules (send the complete firewall object; read it with get_firewall first).",
		Schema: map[string]any{"type": "object", "description": "the firewall object from get_firewall"},
		Request: func(a map[string]any) (string, string, any, error) {
			if len(a) == 0 {
				return "", "", nil, fmt.Errorf("das vollständige Firewall-Objekt aus get_firewall fehlt")
			}
			return http.MethodPut, "/api/firewall", a, nil
		}},
	{Name: "query_access_log", ReadOnly: true, Description: "Search the access log (rotated files included), newest first.",
		Schema: obj(map[string]any{
			"ip": str("client IP or prefix"), "host": str("site domain"), "status": str("e.g. 404 or 5xx"), "path": str("path contains"),
			"q": str("free text"), "tag": str("e.g. scanner, crawler, blocked"), "since": str("e.g. 1h, 24h"), "limit": integer("default 50"),
		}),
		Request: func(a map[string]any) (string, string, any, error) {
			if _, ok := a["limit"]; !ok {
				a["limit"] = float64(50)
			}
			return http.MethodGet, withQuery("/api/logs/access", a, "ip", "host", "status", "path", "q", "tag", "since", "limit"), nil, nil
		}},
	{Name: "get_global_options", ReadOnly: true, Description: "Host-wide options: trusted proxies (real visitor IP), DynDNS, CrowdSec, Tailscale, cache.",
		Request: get("/api/global")},
	{Name: "update_global_options", Description: "Replace the host-wide options (send the complete global object from get_global_options; the firewall part is ignored).",
		Schema: map[string]any{"type": "object", "description": "the global object from get_global_options"},
		Request: func(a map[string]any) (string, string, any, error) {
			if len(a) == 0 {
				return "", "", nil, fmt.Errorf("das vollständige Objekt aus get_global_options fehlt")
			}
			return http.MethodPut, "/api/global", a, nil
		}},
}
