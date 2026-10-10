package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"caddyevolved/internal/events"
	"caddyevolved/internal/install"
)

// run is one install execution, tracked so the UI can poll or stream it.
type run struct {
	ID       string          `json:"id"`
	Started  time.Time       `json:"started"`
	Finished time.Time       `json:"finished,omitempty"`
	Status   string          `json:"status"`
	Error    string          `json:"error,omitempty"`
	Steps    []install.Step  `json:"steps,omitempty"`
	Answers  install.Answers `json:"answers,omitempty"`
	DryRun   bool            `json:"dryRun"`

	cancel context.CancelFunc
	mu     sync.Mutex
}

func (r *run) snapshot() []install.Step {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]install.Step, len(r.Steps))
	copy(out, r.Steps)
	return out
}

// runs keeps the last few executions in memory plus their event trail.
type runs struct {
	mu   sync.Mutex
	all  []*run
	byID map[string]*run
	lock installLock
}

func newRuns() *runs {
	return &runs{byID: map[string]*run{}}
}

func (rs *runs) add(r *run) {
	rs.mu.Lock()
	defer rs.mu.Unlock()
	rs.all = append(rs.all, r)
	if len(rs.all) > 25 {
		rs.all = rs.all[len(rs.all)-25:]
	}
	rs.byID[r.ID] = r
}

func (rs *runs) get(id string) (*run, bool) {
	rs.mu.Lock()
	defer rs.mu.Unlock()
	r, ok := rs.byID[id]
	return r, ok
}

func (rs *runs) list() []*run {
	rs.mu.Lock()
	defer rs.mu.Unlock()
	out := make([]*run, len(rs.all))
	copy(out, rs.all)
	return out
}

// handleInstallPlan returns the planned steps without changing anything.
// POST validates an explicit answer set; GET shows the current install's plan.
func (s *Server) handleInstallPlan(w http.ResponseWriter, r *http.Request) {
	answers, err := s.answersFromRequest(r)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad_answers", errText(err))
		return
	}
	opts := install.Options{Answers: answers, Root: s.Paths.Root, DryRun: true, Unattended: true}
	plan, err := install.NewPlan(r.Context(), opts)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "plan_failed", errText(err))
		return
	}
	// A dry run executes read-only steps only; it reports what *would* happen.
	runErr := plan.Run(r.Context())
	writeJSON(w, http.StatusOK, map[string]any{
		"answers":  answers,
		"steps":    plan.StepsCopy(),
		"dryRun":   true,
		"error":    errText(runErr),
		"warnings": plan.Warnings(),
	})
}

// handleInstallApply starts a plan in the background and returns immediately.
func (s *Server) handleInstallApply(w http.ResponseWriter, r *http.Request) {
	answers, err := s.answersFromRequest(r)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad_answers", errText(err))
		return
	}
	rr, err := s.startRun(answers, r.URL.Query().Get("dryRun") == "true")
	if err != nil {
		status, code := http.StatusInternalServerError, "internal"
		msg := errText(err)
		if strings.Contains(msg, "läuft bereits") {
			status, code = http.StatusConflict, "busy"
		} else if strings.Contains(msg, "answers") || strings.Contains(msg, "katalog") {
			status, code = http.StatusBadRequest, "invalid"
		}
		writeErr(w, status, code, msg)
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]any{"runId": rr.ID, "status": rr.Status, "steps": rr.snapshot()})
}

// startRun builds the plan, registers a run and executes it in the background.
// It returns once the run is scheduled, never waiting for the install itself.
func (s *Server) startRun(answers install.Answers, dryRun bool) (*run, error) {
	answers.Defaults()
	if err := answers.Validate(); err != nil {
		return nil, err
	}
	id := fmt.Sprintf("run-%s", time.Now().UTC().Format("20060102-150405"))
	runCtx, cancel := context.WithCancel(context.Background())

	if err := s.runs.lock.tryStart(id, cancel); err != nil {
		cancel()
		return nil, err
	}

	rr := &run{ID: id, Started: time.Now().UTC(), Status: "running", Answers: answers, DryRun: dryRun, cancel: cancel}
	opts := install.Options{
		Answers:    answers,
		Root:       s.Paths.Root,
		DryRun:     dryRun,
		Unattended: true,
		Runner:     s.Runner,
		Progress: func(st install.Step) {
			rr.mu.Lock()
			rr.Steps = upsertStep(rr.Steps, st)
			rr.mu.Unlock()
		},
		Logf: func(format string, args ...any) {
			s.Events.Record(events.Event{
				Kind: events.KindInstall, Step: id, OK: true,
				Summary: fmt.Sprintf(format, args...),
			})
		},
	}
	plan, err := install.NewPlan(runCtx, opts)
	if err != nil {
		s.runs.lock.finish()
		cancel()
		return nil, err
	}
	rr.mu.Lock()
	rr.Steps = plan.StepsCopy()
	rr.mu.Unlock()
	s.runs.add(rr)

	go func() {
		defer func() {
			cancel()
			s.runs.lock.finish()
		}()
		err := plan.Run(runCtx)
		rr.mu.Lock()
		rr.Finished = time.Now().UTC()
		rr.Steps = plan.StepsCopy()
		switch {
		case errors.Is(runCtx.Err(), context.Canceled):
			rr.Status = "aborted"
			rr.Error = "abgebrochen"
		case err != nil:
			rr.Status = "failed"
			rr.Error = errText(err)
		default:
			rr.Status = "done"
		}
		rr.mu.Unlock()

		s.Events.Record(events.Event{
			Kind:    events.KindInstall,
			Step:    id,
			OK:      rr.Status == "done",
			Error:   rr.Error,
			Summary: summaryOf(rr),
			Meta:    map[string]any{"variant": answers.BinarySource, "plugins": answers.Plugins},
		})
	}()
	return rr, nil
}

// handleRuns lists install executions, newest last.
func (s *Server) handleRuns(w http.ResponseWriter, r *http.Request) {
	out := make([]map[string]any, 0)
	for _, rr := range s.runs.list() {
		rr.mu.Lock()
		item := map[string]any{
			"id": rr.ID, "status": rr.Status, "started": rr.Started,
			"finished": rr.Finished, "dryRun": rr.DryRun, "error": rr.Error,
			"answers": rr.Answers,
		}
		rr.mu.Unlock()
		item["steps"] = rr.snapshot()
		out = append(out, item)
	}
	id, since, running := s.runs.lock.running()
	writeJSON(w, http.StatusOK, map[string]any{"runs": out, "running": running, "runningId": id, "since": since})
}

// handleRunAbort cancels the in-flight install.
func (s *Server) handleRunAbort(w http.ResponseWriter, r *http.Request) {
	if !s.runs.lock.abort() {
		writeErr(w, http.StatusNotFound, "not_running", "Keine laufende Installation")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"aborted": true})
}

// answersFromRequest builds the Answers for a plan: from the body when given,
// otherwise the current install. Both {"answers":{...}} and a bare object are
// accepted, because hand-driven curl should not need a wrapper.
func (s *Server) answersFromRequest(r *http.Request) (install.Answers, error) {
	st, err := loadStateView(s.Paths.StateFile)
	if err != nil {
		return install.Answers{}, err
	}
	if r.Method == http.MethodGet || r.ContentLength == 0 {
		return st.toAnswers(), nil
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, maxBody))
	if err != nil {
		return install.Answers{}, err
	}
	if len(bytes.TrimSpace(body)) == 0 {
		return st.toAnswers(), nil
	}
	var wrapper struct {
		Answers *install.Answers `json:"answers"`
	}
	if err := json.Unmarshal(body, &wrapper); err == nil && wrapper.Answers != nil {
		return merge(*wrapper.Answers, st), nil
	}
	var bare install.Answers
	if err := json.Unmarshal(body, &bare); err != nil {
		return install.Answers{}, fmt.Errorf("JSON: %w", err)
	}
	return merge(bare, st), nil
}

func merge(a install.Answers, st stateView) install.Answers {
	if a.BinarySource == "" {
		a.BinarySource = st.BinarySource
	}
	if a.Email == "" {
		a.Email = st.Email
	}
	if a.HTTPPort == 0 {
		a.HTTPPort = st.HTTPPort
	}
	if a.HTTPSPort == 0 {
		a.HTTPSPort = st.HTTPSPort
	}
	if a.AdminPort == 0 {
		a.AdminPort = st.AdminPort
	}
	if a.UIPort == 0 {
		a.UIPort = st.UIPort
	}
	if a.UIBind == "" {
		a.UIBind = st.UIBind
	}
	if a.Plugins == nil {
		a.Plugins = st.Enabled
	}
	if a.Credentials == nil && len(st.Enabled) > 0 {
		a.Credentials = map[string]string{}
	}
	return a
}

func upsertStep(steps []install.Step, st install.Step) []install.Step {
	for i, existing := range steps {
		if existing.Name == st.Name {
			steps[i] = st
			return steps
		}
	}
	return append(steps, st)
}

func summaryOf(rr *run) string {
	rr.mu.Lock()
	defer rr.mu.Unlock()
	var ok, skipped, failed int
	for _, st := range rr.Steps {
		switch st.Status {
		case install.StatusOK:
			ok++
		case install.StatusSkipped, install.StatusPlanned:
			skipped++
		case install.StatusFailed:
			failed++
		}
	}
	return fmt.Sprintf("%d Schritte ok, %d übersprungen, %d fehlgeschlagen (%s)", ok, skipped, failed, rr.Status)
}
