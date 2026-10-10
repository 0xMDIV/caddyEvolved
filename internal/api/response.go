package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
)

// maxBody caps request bodies; a Caddyfile is a few kilobytes, an exploit is
// usually much larger.
const maxBody = 2 << 20

type errorBody struct {
	Error string `json:"error"`
	// Code is a stable string for the UI to branch on, not the HTTP status.
	Code string `json:"code,omitempty"`
	// Details carries per-field problems for wizard validation.
	Details []string `json:"details,omitempty"`
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	if v == nil {
		return
	}
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		log.Printf("api: response encode: %v", err)
	}
}

func writeErr(w http.ResponseWriter, status int, code, msg string, details ...string) {
	writeJSON(w, status, errorBody{Error: msg, Code: code, Details: details})
}

// fail maps an error to a status code without leaking internals to the UI.
func (s *Server) fail(w http.ResponseWriter, r *http.Request, err error, fallback int) {
	switch {
	case errors.Is(err, os.ErrPermission):
		writeErr(w, http.StatusForbidden, "permission", "Keine Berechtigung – caddyEvolved braucht root für Diensteingriffe: "+errText(err))
	case errors.Is(err, os.ErrNotExist):
		writeErr(w, http.StatusNotFound, "not_found", "Nicht gefunden: "+errText(err))
	case errors.Is(err, context.DeadlineExceeded):
		writeErr(w, http.StatusGatewayTimeout, "timeout", "Zeitüberschreitung bei der Aktion")
	default:
		code := "internal"
		status := fallback
		if status == 0 {
			status = http.StatusInternalServerError
		}
		writeErr(w, status, code, errText(err))
	}
}

func errText(err error) string {
	if err == nil {
		return ""
	}
	return strings.TrimSpace(err.Error())
}

// decode reads a JSON body with a hard size limit.
func decode(r *http.Request, dst any) error {
	body, err := io.ReadAll(io.LimitReader(r.Body, maxBody))
	if err != nil {
		return fmt.Errorf("Body lesen: %w", err)
	}
	if len(strings.TrimSpace(string(body))) == 0 {
		return errors.New("leere Anfrage")
	}
	if err := json.Unmarshal(body, dst); err != nil {
		return fmt.Errorf("JSON: %w", err)
	}
	return nil
}
