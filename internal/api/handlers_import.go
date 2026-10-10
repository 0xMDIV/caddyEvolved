package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"caddyevolved/internal/events"
	"caddyevolved/internal/importer"
	"caddyevolved/internal/sites"
)

// importBody allows archives: a Zoraxy backup zip is a few megabytes, and
// base64 adds a third.
const importBody = 48 << 20

type importPreviewRequest struct {
	Format string          `json:"format"`
	Files  []importer.File `json:"files"`
}

func (s *Server) handleImportPreview(w http.ResponseWriter, r *http.Request) {
	var req importPreviewRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, importBody)).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", "Anfrage nicht lesbar: "+errText(err))
		return
	}
	res, err := importer.Run(req.Format, req.Files)
	if err != nil {
		writeErr(w, http.StatusUnprocessableEntity, "import_failed", errText(err))
		return
	}
	// Flag what already exists, so the operator decides before anything is
	// written.
	existing, _ := s.Sites.List()
	owner := map[string]string{}
	ids := map[string]bool{}
	for _, st := range existing {
		ids[st.ID] = true
		for _, d := range st.Domains {
			owner[strings.ToLower(d)] = st.ID
		}
	}
	for i := range res.Sites {
		c := &res.Sites[i]
		if ids[c.Site.ID] {
			c.Problems = append(c.Problems, "Site-ID "+c.Site.ID+" existiert bereits – ID ändern oder bestehende Site löschen")
		}
		for _, d := range c.Site.Domains {
			if o, ok := owner[strings.ToLower(d)]; ok {
				c.Problems = append(c.Problems, "Domain "+d+" gehört schon zur Site "+o)
			}
		}
	}
	lists, _ := s.Sites.ListACL()
	for i := range res.AccessLists {
		for _, a := range lists {
			if a.ID == res.AccessLists[i].AccessList.ID {
				res.AccessLists[i].Warnings = append(res.AccessLists[i].Warnings, "Access List "+a.ID+" existiert bereits und wird nicht überschrieben")
			}
		}
	}
	writeJSON(w, http.StatusOK, res)
}

type importApplyRequest struct {
	AccessLists []sites.AccessList `json:"accessLists"`
	Sites       []sites.Site       `json:"sites"`
}

type importItemResult struct {
	Kind    string   `json:"kind"` // site | accessList
	ID      string   `json:"id"`
	OK      bool     `json:"ok"`
	Error   string   `json:"error,omitempty"`
	Details []string `json:"details,omitempty"`
}

// handleImportApply creates access lists first (sites reference them), then
// every site on its own, so one site caddy rejects does not block the rest.
func (s *Server) handleImportApply(w http.ResponseWriter, r *http.Request) {
	var req importApplyRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, importBody)).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", "Anfrage nicht lesbar: "+errText(err))
		return
	}
	ctx := r.Context()
	var results []importItemResult
	existing, _ := s.Sites.ListACL()
	have := map[string]bool{}
	for _, a := range existing {
		have[a.ID] = true
	}
	for _, a := range req.AccessLists {
		res := importItemResult{Kind: "accessList", ID: a.ID}
		if have[a.ID] {
			res.OK, res.Error = true, "existiert bereits – unverändert"
			results = append(results, res)
			continue
		}
		var reloaded bool
		saved, err := s.Sites.UpsertACL(ctx, a, true, s.siteCommit(&reloaded))
		res.ID, res.OK = firstNonEmptyStr(saved.ID, a.ID), err == nil
		res.Error, res.Details = importErr(err)
		results = append(results, res)
	}
	okCount := 0
	for _, st := range req.Sites {
		res := importItemResult{Kind: "site", ID: st.ID}
		var reloaded bool
		saved, err := s.Sites.Upsert(ctx, st, true, s.siteCommit(&reloaded))
		res.ID, res.OK = firstNonEmptyStr(saved.ID, st.ID), err == nil
		res.Error, res.Details = importErr(err)
		if err == nil {
			okCount++
		}
		results = append(results, res)
	}
	s.Events.Record(events.Event{
		Kind: events.KindProxy, Step: "import", OK: okCount == len(req.Sites),
		Summary: fmt.Sprintf("Import: %d von %d Sites übernommen", okCount, len(req.Sites)),
	})
	writeJSON(w, http.StatusOK, map[string]any{"results": results, "imported": okCount})
}

func importErr(err error) (string, []string) {
	if err == nil {
		return "", nil
	}
	var verr *sites.ValidationError
	var cerr *sites.ErrInvalid
	switch {
	case errors.As(err, &verr):
		return "Eingaben ungültig", verr.Problems
	case errors.As(err, &cerr):
		return "caddy lehnt die Site ab", outputLines(cerr.Output, cerr.Err)
	default:
		return errText(err), nil
	}
}

func firstNonEmptyStr(v ...string) string {
	for _, s := range v {
		if s != "" {
			return s
		}
	}
	return ""
}
