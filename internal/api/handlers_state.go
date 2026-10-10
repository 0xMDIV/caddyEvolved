package api

import (
	"net/http"
	"os"
	"strings"
	"time"

	"caddyforge/internal/config"
	"caddyforge/internal/events"
	"caddyforge/internal/install"
)

// stateView is the install state as the UI sees it. It never carries secret
// values, only which key names exist.
type stateView struct {
	Installed    bool         `json:"installed"`
	CaddyVersion string       `json:"caddyVersion,omitempty"`
	BinarySource string       `json:"binarySource,omitempty"`
	Variant      string       `json:"variant,omitempty"`
	Enabled      []string     `json:"enabledPlugins,omitempty"`
	Email        string       `json:"email,omitempty"`
	AdminPort    int          `json:"adminPort"`
	HTTPPort     int          `json:"httpPort"`
	HTTPSPort    int          `json:"httpsPort"`
	UIPort       int          `json:"uiPort"`
	UIBind       string       `json:"uiBind,omitempty"`
	Managed      bool         `json:"managed"`
	SiteDomain   string       `json:"siteDomain,omitempty"`
	SiteTarget   string       `json:"siteTarget,omitempty"`
	EnvKeys      []string     `json:"envKeys,omitempty"`
	UpdatedAt    string       `json:"updatedAt,omitempty"`
	Paths        config.Paths `json:"paths"`
}

func loadStateView(path string) (stateView, error) {
	st, err := config.LoadState(path)
	if err != nil {
		if os.IsNotExist(err) {
			return stateView{}, nil
		}
		return stateView{}, err
	}
	return stateView{
		Installed:    st.Installed,
		CaddyVersion: st.CaddyVersion,
		BinarySource: st.BinarySource,
		Variant:      st.Variant,
		Enabled:      st.Enabled,
		Email:        st.Email,
		AdminPort:    st.AdminPort,
		HTTPPort:     st.HTTPPort,
		HTTPSPort:    st.HTTPSPort,
		UIPort:       st.UIPort,
		UIBind:       st.UIBind,
		Managed:      st.Managed,
		UpdatedAt:    st.UpdatedAt,
	}, nil
}

func (v stateView) toAnswers() install.Answers {
	return install.Answers{
		BinarySource: v.BinarySource,
		Plugins:      v.Enabled,
		Email:        v.Email,
		HTTPPort:     v.HTTPPort,
		HTTPSPort:    v.HTTPSPort,
		AdminPort:    v.AdminPort,
		UIPort:       v.UIPort,
		UIBind:       v.UIBind,
		Managed:      v.Managed,
	}
}

// handleState serves the persisted install plus env key names.
func (s *Server) handleState(w http.ResponseWriter, r *http.Request) {
	v, err := loadStateView(s.Paths.StateFile)
	if err != nil {
		s.fail(w, r, err, 0)
		return
	}
	v.Paths = s.Paths
	for k := range s.envKeys() {
		v.EnvKeys = append(v.EnvKeys, k)
	}
	writeJSON(w, http.StatusOK, v)
}

// handleApplyState is the write path for install changes. It validates, then
// starts a normal run, so nothing edits state.json behind the plan's back.
func (s *Server) handleApplyState(w http.ResponseWriter, r *http.Request) {
	answers, err := s.answersFromRequest(r)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad_answers", errText(err))
		return
	}
	rr, err := s.startRun(answers, false)
	if err != nil {
		status, code := http.StatusInternalServerError, "internal"
		msg := errText(err)
		switch {
		case strings.Contains(msg, "läuft bereits"):
			status, code = http.StatusConflict, "busy"
		case strings.Contains(msg, "answers"), strings.Contains(msg, "katalog"), strings.Contains(msg, "sinnlos"):
			status, code = http.StatusBadRequest, "invalid"
		}
		writeErr(w, status, code, msg)
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]any{
		"runId": rr.ID, "status": rr.Status, "steps": rr.snapshot(),
	})
}

// handleEvents returns recorded events, oldest first, with a cursor.
func (s *Server) handleEvents(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	limit := parseIntDefault(q.Get("limit"), 200, 1, 1000)
	all := s.Events.Since(q.Get("after"), limit)
	if kind := q.Get("kind"); kind != "" {
		filtered := make([]events.Event, 0, len(all))
		for _, e := range all {
			if string(e.Kind) == kind {
				filtered = append(filtered, e)
			}
		}
		all = filtered
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"events":     all,
		"cursor":     lastID(all),
		"count":      len(all),
		"serverTime": time.Now().UTC(),
	})
}

func lastID(v []events.Event) string {
	if len(v) == 0 {
		return ""
	}
	return v[len(v)-1].ID
}

func errContains(err error, needle string) bool {
	return err != nil && strings.Contains(err.Error(), needle)
}

func parseIntDefault(s string, def, min, max int) int {
	if s == "" {
		return def
	}
	n := 0
	for _, r := range s {
		if r < '0' || r > '9' {
			return def
		}
		n = n*10 + int(r-'0')
	}
	switch {
	case n < min:
		return min
	case n > max:
		return max
	default:
		return n
	}
}
