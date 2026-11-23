package server

import (
	"net/http"
	"strings"
	"time"
)

// Accepting a risk is for findings that cannot be fixed (no vendor update, software that must stay as it is).
// An accepted finding is still listed, marked as accepted, but no longer lowers the score or raises alerts.
func (s *Server) handleAcceptRisk(w http.ResponseWriter, r *http.Request, sess *session) {
	var req struct {
		Key  string `json:"key"`
		Note string `json:"note"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	req.Key, req.Note = strings.TrimSpace(req.Key), strings.TrimSpace(req.Note)
	if req.Key == "" || len(req.Key) > 300 || len(req.Note) > 500 {
		writeErr(w, 400, "a finding key and a note up to 500 characters are required")
		return
	}
	s.db.update(func(x *dbData) {
		if x.Accepted == nil {
			x.Accepted = map[string]AcceptRec{}
		}
		x.Accepted[req.Key] = AcceptRec{Note: req.Note, At: time.Now().UTC()}
	})
	s.record(r, "risk_accepted", "", req.Key)
	writeJSON(w, 200, map[string]bool{"ok": true})
}

func (s *Server) handleUnacceptRisk(w http.ResponseWriter, r *http.Request, sess *session) {
	var req struct {
		Key string `json:"key"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	s.db.update(func(x *dbData) { delete(x.Accepted, req.Key) })
	s.record(r, "risk_unaccepted", "", req.Key)
	writeJSON(w, 200, map[string]bool{"ok": true})
}
