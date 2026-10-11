package api

import (
	"context"
	"net/http"
	"sync"
	"time"

	"caddyevolved/internal/toolbox"
)

// Network tools run on the server. Scans can be noisy and slow, so they are
// for logged-in users only (not API tokens) and run one at a time.
var scanMu sync.Mutex

func (s *Server) handleToolsInfo(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"networks": toolbox.LocalNetworks(), "commonPorts": toolbox.CommonPorts()})
}

func (s *Server) handleToolCIDR(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	if from, to := q.Get("from"), q.Get("to"); from != "" || to != "" {
		cidrs, err := toolbox.RangeToCIDRs(from, to)
		if err != nil {
			writeErr(w, http.StatusBadRequest, "bad_range", errText(err))
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"cidrs": cidrs})
		return
	}
	info, err := toolbox.ParseCIDR(q.Get("q"))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad_cidr", errText(err))
		return
	}
	writeJSON(w, http.StatusOK, info)
}

func (s *Server) handleToolDNS(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	recs, err := toolbox.LookupDNS(ctx, r.URL.Query().Get("name"))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "dns", errText(err))
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"records": recs})
}

// runNetTool decodes the request, takes the scan lock and answers with fn's
// result.
func (s *Server) runNetTool(w http.ResponseWriter, r *http.Request, limit time.Duration, req any, fn func(ctx context.Context) (any, error)) {
	if !tokenAdmin(w, r) {
		return
	}
	if err := decode(r, req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", errText(err))
		return
	}
	if !scanMu.TryLock() {
		writeErr(w, http.StatusConflict, "tool_busy", "Es läuft bereits ein Werkzeug – kurz warten")
		return
	}
	defer scanMu.Unlock()
	ctx, cancel := context.WithTimeout(r.Context(), limit)
	defer cancel()
	start := time.Now()
	out, err := fn(ctx)
	if err != nil && out == nil {
		writeErr(w, http.StatusBadRequest, "tool_failed", errText(err))
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"result": out, "error": errText(err), "seconds": time.Since(start).Seconds()})
}

func (s *Server) handleToolPing(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Host  string `json:"host"`
		Count int    `json:"count"`
	}
	s.runNetTool(w, r, 40*time.Second, &req, func(ctx context.Context) (any, error) {
		return toolbox.Ping(ctx, req.Host, req.Count, 2*time.Second)
	})
}

func (s *Server) handleToolTraceroute(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Host    string `json:"host"`
		MaxHops int    `json:"maxHops"`
	}
	s.runNetTool(w, r, 90*time.Second, &req, func(ctx context.Context) (any, error) {
		addr, hops, err := toolbox.Traceroute(ctx, req.Host, req.MaxHops, time.Second)
		if hops == nil && err != nil {
			return nil, err
		}
		return map[string]any{"addr": addr, "hops": hops}, err
	})
}

func (s *Server) handleToolPorts(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Host  string `json:"host"`
		Ports string `json:"ports"`
	}
	s.runNetTool(w, r, 60*time.Second, &req, func(ctx context.Context) (any, error) {
		ports, err := toolbox.ParsePorts(req.Ports)
		if err != nil {
			return nil, err
		}
		addr, open, err := toolbox.ScanPorts(ctx, req.Host, ports, 800*time.Millisecond)
		if addr == "" && err != nil {
			return nil, err
		}
		if open == nil {
			open = []toolbox.PortResult{}
		}
		return map[string]any{"addr": addr, "scanned": len(ports), "open": open}, err
	})
}

func (s *Server) handleToolHosts(w http.ResponseWriter, r *http.Request) {
	var req struct {
		CIDR string `json:"cidr"`
	}
	s.runNetTool(w, r, 60*time.Second, &req, func(ctx context.Context) (any, error) {
		hosts, err := toolbox.ScanHosts(ctx, req.CIDR, 1500*time.Millisecond)
		if hosts == nil && err != nil {
			return nil, err
		}
		if hosts == nil {
			hosts = []toolbox.HostResult{}
		}
		return map[string]any{"hosts": hosts}, err
	})
}

func (s *Server) handleToolMDNS(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Seconds int `json:"seconds"`
	}
	s.runNetTool(w, r, 30*time.Second, &req, func(ctx context.Context) (any, error) {
		wait := time.Duration(req.Seconds) * time.Second
		if wait < 2*time.Second || wait > 15*time.Second {
			wait = 4 * time.Second
		}
		svc, err := toolbox.BrowseMDNS(ctx, wait)
		if svc == nil {
			svc = []toolbox.MDNSService{}
		}
		return map[string]any{"services": svc}, err
	})
}
