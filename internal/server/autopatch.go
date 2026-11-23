package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// PatchSettings describes the weekly maintenance window in the server's local time.
type PatchSettings struct {
	Enabled      bool  `json:"enabled"`
	Days         []int `json:"days"`         // 0 = Sunday ... 6 = Saturday
	StartHour    int   `json:"startHour"`    // 0-23
	Hours        int   `json:"hours"`        // length of the window, 1-12
	AllowReboot  bool  `json:"allowReboot"`  // let Windows restart when an update needs it
	SecurityOnly bool  `json:"securityOnly"` // only critical, important and security-category updates
}

// inWindow reports whether t falls inside the window, including a window that runs past midnight.
func (p PatchSettings) inWindow(t time.Time) bool {
	if !p.Enabled || len(p.Days) == 0 || p.Hours < 1 {
		return false
	}
	for back := 0; back <= 1; back++ {
		day := t.AddDate(0, 0, -back)
		start := time.Date(day.Year(), day.Month(), day.Day(), p.StartHour, 0, 0, 0, t.Location())
		end := start.Add(time.Duration(p.Hours) * time.Hour)
		if t.Before(start) || !t.Before(end) {
			continue
		}
		for _, d := range p.Days {
			if d == int(day.Weekday()) {
				return true
			}
		}
	}
	return false
}

func (p *PatchSettings) clean() string {
	if p.StartHour < 0 || p.StartHour > 23 {
		return "start hour must be 0 to 23"
	}
	if p.Hours < 1 || p.Hours > 12 {
		return "the window must be 1 to 12 hours long"
	}
	seen := map[int]bool{}
	var days []int
	for _, d := range p.Days {
		if d < 0 || d > 6 {
			return "days must be 0 (Sunday) to 6 (Saturday)"
		}
		if !seen[d] {
			seen[d] = true
			days = append(days, d)
		}
	}
	p.Days = days
	if p.Enabled && len(days) == 0 {
		return "pick at least one day"
	}
	return ""
}

func (s *Server) handlePatchGet(w http.ResponseWriter, r *http.Request, sess *session) {
	p := s.db.settings().Patch
	if p.Days == nil {
		p.Days = []int{}
	}
	writeJSON(w, 200, p)
}

func (s *Server) handlePatchPut(w http.ResponseWriter, r *http.Request, sess *session) {
	var p PatchSettings
	if !readJSON(w, r, &p) {
		return
	}
	if msg := p.clean(); msg != "" {
		writeErr(w, 400, msg)
		return
	}
	if !s.needStepUp(w, sess) {
		return
	}
	s.db.update(func(d *dbData) { d.Settings.Patch = p })
	s.record(r, "patch_window", "", fmt.Sprintf("enabled=%v days=%v start=%d hours=%d", p.Enabled, p.Days, p.StartHour, p.Hours))
	writeJSON(w, 200, p)
}

// autoPatch runs every couple of minutes. Inside the window, each online approved device is patched at most once
// per day, one device at a time so a bad update never hits the whole fleet at once.
func (s *Server) autoPatch() {
	set := s.db.settings().Patch
	now := time.Now()
	if !set.inWindow(now) {
		return
	}
	today := now.Format("2006-01-02")
	for _, d := range s.st.devices() {
		if !d.Approved || s.hub.online(d.ID) == nil {
			continue
		}
		var done string
		s.db.view(func(x *dbData) { done = x.Patched[d.ID] })
		if done == today {
			continue
		}
		s.db.update(func(x *dbData) {
			if x.Patched == nil {
				x.Patched = map[string]string{}
			}
			x.Patched[d.ID] = today
		})
		s.patchDevice(d.ID, d.Name, set)
		if !s.db.settings().Patch.inWindow(time.Now()) {
			return // the window closed while we worked
		}
	}
}

func (s *Server) patchDevice(id, name string, set PatchSettings) {
	raw, err := s.callCmd(id, "updates.check", nil, "patch-window")
	if err != nil {
		s.log.Printf("patch window: %s: check failed: %v", name, err)
		return
	}
	var res struct {
		Updates []Patch `json:"updates"`
	}
	if json.Unmarshal(raw, &res) != nil || len(res.Updates) == 0 {
		return
	}
	var ids []string
	for _, u := range res.Updates {
		if set.SecurityOnly && !isSecurityPatch(u) {
			continue
		}
		ids = append(ids, u.ID)
	}
	if len(ids) == 0 {
		return
	}
	args, _ := json.Marshal(map[string]any{"ids": ids, "reboot": set.AllowReboot})
	_, err = s.callCmd(id, "updates.install", args, "patch-window")
	detail := fmt.Sprintf("%s: %d update(s)", name, len(ids))
	if err != nil {
		detail += " failed: " + err.Error()
	}
	s.audit.add(AuditEntry{IP: "server", Action: "patch_window_run", Device: id, Detail: detail})
	_ = s.startScan(id, "patch-window") // refresh findings after patching
}

func isSecurityPatch(p Patch) bool {
	switch strings.ToLower(p.Severity) {
	case "critical", "important":
		return true
	}
	for _, c := range p.Cats {
		if strings.Contains(strings.ToLower(c), "security") {
			return true
		}
	}
	return false
}
