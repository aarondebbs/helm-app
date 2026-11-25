package server

import (
	"encoding/json"
	"net/http"
	"sort"
	"strings"
	"time"
)

// Antivirus intelligence. Helm does not carry its own signature database: the engine on each PC (Microsoft
// Defender, ClamAV, XProtect) is the scanner, and Helm makes sure its intelligence is fresh. Every PC with the
// Antivirus module is told to update at least once a day, its engine version is read back afterwards, and
// anything older than two days is reported as out of date.

const (
	avUpdateEvery = 24 * time.Hour
	avStatusEvery = 6 * time.Hour
	avStaleAfter  = 48 * time.Hour
)

// AVRec is what Helm last learned about the antivirus engine of one PC.
type AVRec struct {
	StatusAt     time.Time       `json:"statusAt"`
	Status       json.RawMessage `json:"status,omitempty"`
	UpdatedAt    time.Time       `json:"updatedAt"`              // last successful signature update that Helm started
	SetupPending []string        `json:"setupPending,omitempty"` // modules whose setup is still to do: the PC was offline, or it failed
	SetupFails   int             `json:"setupFails,omitempty"`
	SetupTriedAt time.Time       `json:"setupTriedAt,omitempty"`
	LastQuick    time.Time       `json:"lastQuick,omitempty"` // last scan Helm started by itself
	LastFull     time.Time       `json:"lastFull,omitempty"`
	LastErr      string          `json:"lastErr,omitempty"`
	LastErrAt    time.Time       `json:"lastErrAt,omitempty"`
}

func (s *Server) storeAV(j Job) {
	if j.Name == "module.install" {
		s.storeSetup(j)
		return
	}
	if j.Name != "av.status" && j.Name != "av.update" {
		return
	}
	s.db.update(func(d *dbData) {
		r := d.AV[j.DeviceID]
		if r == nil {
			r = &AVRec{}
			d.AV[j.DeviceID] = r
		}
		if j.Status != "ok" {
			r.LastErr, r.LastErrAt = j.Err, j.Finished
			return
		}
		r.LastErr = ""
		if j.Name == "av.status" && len(j.Data) > 0 && len(j.Data) < 64<<10 {
			r.StatusAt, r.Status = j.Finished, append(json.RawMessage(nil), j.Data...)
		}
		if j.Name == "av.update" {
			r.UpdatedAt = j.Finished
		}
	})
	if j.Name == "av.update" && j.Status == "ok" { // read the new version back
		_, _ = s.hub.dispatch(j.DeviceID, "av.status", json.RawMessage(`{}`), "auto-av")
	}
}

// kickAV installs whatever the chosen modules need on the PC (an antivirus engine, a firewall tool).
// When that finishes, storeAV starts the first definition update.
func (s *Server) kickAV(id string, mods []string) {
	if _, err := s.hub.dispatch(id, "module.install", s.setupArgs(id, mods), "auto-setup"); err != nil {
		// Offline: remember it and do it when the PC next connects.
		s.db.update(func(d *dbData) {
			if d.AV == nil {
				d.AV = map[string]*AVRec{}
			}
			r := d.AV[id]
			if r == nil {
				r = &AVRec{}
				d.AV[id] = r
			}
			r.SetupPending = append([]string(nil), mods...)
		})
	}
}

// runPendingSetup does the setup that was waiting for this PC to come online.
func (s *Server) runPendingSetup(id string) {
	var mods []string
	s.db.view(func(x *dbData) {
		if r := x.AV[id]; r != nil {
			mods = append(mods, r.SetupPending...)
		}
	})
	if len(mods) == 0 {
		return
	}
	time.Sleep(10 * time.Second) // let the connection settle
	_, _ = s.hub.dispatch(id, "module.install", s.setupArgs(id, mods), "auto-setup")
}

// setupArgs is what the agent is told to set up: the modules, plus this PC's switches.
func (s *Server) setupArgs(id string, mods []string) json.RawMessage {
	var o DeviceOpts
	if d, ok := s.st.device(id); ok {
		o = d.Opts
	}
	b, _ := json.Marshal(map[string]any{"modules": mods, "fastStartupOff": o.FastStartupOff, "linuxRealtime": o.LinuxRealtime})
	return b
}

const maxSetupTries = 5

// storeSetup records how a setup run went. A run that fails, or leaves a component not ready, is remembered and
// retried once a day, up to five times. An agent that does not know the command (older than 1.0.5) is not retried.
func (s *Server) storeSetup(j Job) {
	var a struct{ Modules []string }
	_ = json.Unmarshal(j.Args, &a)
	var res struct {
		Components []struct {
			Module string `json:"module"`
			OK     bool   `json:"ok"`
		} `json:"components"`
	}
	_ = json.Unmarshal(j.Data, &res)
	var failed []string
	switch {
	case j.Status != "ok" && strings.Contains(j.Err, "unknown command"):
		// nothing to retry
	case j.Status != "ok":
		failed = a.Modules
	default:
		for _, c := range res.Components {
			if !c.OK {
				failed = append(failed, c.Module)
			}
		}
	}
	s.db.update(func(d *dbData) {
		if d.AV == nil {
			d.AV = map[string]*AVRec{}
		}
		r := d.AV[j.DeviceID]
		if r == nil {
			r = &AVRec{}
			d.AV[j.DeviceID] = r
		}
		r.SetupTriedAt = time.Now()
		if len(failed) == 0 {
			r.SetupPending, r.SetupFails = nil, 0
		} else {
			r.SetupPending, r.SetupFails = failed, r.SetupFails+1
		}
	})
	// The antivirus engine is there (or this agent cannot install one): fetch definitions and read the state.
	for _, m := range a.Modules {
		if m == "av" && j.Status == "ok" || m == "av" && strings.Contains(j.Err, "unknown command") {
			_, _ = s.hub.dispatch(j.DeviceID, "av.update", json.RawMessage(`{}`), "auto-av")
			_, _ = s.hub.dispatch(j.DeviceID, "av.status", json.RawMessage(`{}`), "auto-av")
			break
		}
	}
}

// autoAV keeps the antivirus intelligence of every online PC with the module fresh.
func (s *Server) autoAV() {
	online := s.hub.onlineIDs()
	for _, d := range s.st.devices() {
		if !d.Approved || online[d.ID] == nil || !d.has("av") {
			continue
		}
		var rec AVRec
		s.db.view(func(x *dbData) {
			if r := x.AV[d.ID]; r != nil {
				rec = *r
			}
		})
		if time.Since(rec.UpdatedAt) > avUpdateEvery && time.Since(rec.LastErrAt) > 2*time.Hour {
			_, _ = s.hub.dispatch(d.ID, "av.update", json.RawMessage(`{}`), "auto-av")
		} else if time.Since(rec.StatusAt) > avStatusEvery {
			_, _ = s.hub.dispatch(d.ID, "av.status", json.RawMessage(`{}`), "auto-av")
		}
		if len(rec.SetupPending) > 0 && rec.SetupFails < maxSetupTries && time.Since(rec.SetupTriedAt) > 24*time.Hour {
			s.db.update(func(x *dbData) {
				if r := x.AV[d.ID]; r != nil {
					r.SetupTriedAt = time.Now() // counts as tried even if the PC does not answer
				}
			})
			_, _ = s.hub.dispatch(d.ID, "module.install", s.setupArgs(d.ID, rec.SetupPending), "auto-setup")
		}
		s.scheduledScan(d.ID, rec)
	}
}

// scheduledScan covers PCs that have no real-time protection: a quick scan every day and a full scan every week,
// started only in the quiet hours (01:00 to 06:00 server time) so a scan does not slow people down.
func (s *Server) scheduledScan(id string, rec AVRec) {
	if h := time.Now().Hour(); h < 1 || h >= 6 {
		return
	}
	s.runDueScan(id, rec, false)
}

// catchUpScan runs when a PC connects. If it has no real-time protection and its scan is overdue (it was off during
// the quiet hours, or has just booted), a quick scan starts two minutes later, once the PC has finished starting up.
// A weekly full scan that is overdue still waits for the quiet hours.
func (s *Server) catchUpScan(id string) {
	time.Sleep(2 * time.Minute)
	select {
	case <-s.stop:
		return
	default:
	}
	if s.hub.online(id) == nil {
		return
	}
	var rec AVRec
	s.db.view(func(x *dbData) {
		if r := x.AV[id]; r != nil {
			rec = *r
		}
	})
	if d, ok := s.st.device(id); ok && d.Approved && d.has("av") {
		s.runDueScan(id, rec, true)
	}
}

func (s *Server) runDueScan(id string, rec AVRec, onConnect bool) {
	if len(rec.Status) == 0 {
		return
	}
	var st struct {
		Enabled  bool `json:"enabled"`
		Realtime bool `json:"realtime"`
	}
	if json.Unmarshal(rec.Status, &st) != nil || !st.Enabled || st.Realtime {
		return
	}
	kind := ""
	switch {
	case time.Since(rec.LastFull) > 7*24*time.Hour && !onConnect:
		kind = "full"
	case onConnect && time.Since(rec.LastQuick) > 24*time.Hour && time.Since(rec.LastFull) > 24*time.Hour:
		kind = "quick"
	case time.Since(rec.LastQuick) > 24*time.Hour && time.Since(rec.LastFull) > 24*time.Hour:
		kind = "quick"
	default:
		return
	}
	args, _ := json.Marshal(map[string]any{"kind": kind})
	if _, err := s.hub.dispatch(id, "av.scan", args, "auto-scan"); err != nil {
		return
	}
	s.db.update(func(d *dbData) {
		if r := d.AV[id]; r != nil {
			r.LastQuick = time.Now()
			if kind == "full" {
				r.LastFull = time.Now()
			}
		}
	})
}

type avRow struct {
	ID         string          `json:"id"`
	Name       string          `json:"name"`
	Online     bool            `json:"online"`
	OS         string          `json:"os"`
	Engine     string          `json:"engine"`
	Enabled    bool            `json:"enabled"`
	Realtime   bool            `json:"realtime"`
	Signatures string          `json:"signatures"`
	SigDate    string          `json:"signaturesUpdated,omitempty"`
	UpdatedAt  time.Time       `json:"updatedAt,omitempty"`
	StatusAt   time.Time       `json:"statusAt,omitempty"`
	State      string          `json:"state"` // current, stale, missing, unknown, error
	Hint       string          `json:"hint,omitempty"`
	SetupFails int             `json:"setupFails,omitempty"`
	SetupLeft  []string        `json:"setupLeft,omitempty"`
	Err        string          `json:"err,omitempty"`
	Raw        json.RawMessage `json:"-"`
}

func (s *Server) avRows() []avRow {
	online := s.hub.onlineIDs()
	var rows []avRow
	for _, d := range s.st.devices() {
		if !d.Approved || !d.has("av") {
			continue
		}
		row := avRow{ID: d.ID, Name: d.Name, Online: online[d.ID] != nil, State: "unknown"}
		if d.Hello != nil {
			row.OS = d.Hello.OS
		}
		var rec AVRec
		s.db.view(func(x *dbData) {
			if r := x.AV[d.ID]; r != nil {
				rec = *r
			}
		})
		row.UpdatedAt, row.StatusAt, row.Err = rec.UpdatedAt, rec.StatusAt, rec.LastErr
		row.SetupFails, row.SetupLeft = rec.SetupFails, rec.SetupPending
		if len(rec.Status) > 0 {
			var st struct {
				Engine     string `json:"engine"`
				Enabled    bool   `json:"enabled"`
				Realtime   bool   `json:"realtime"`
				Signatures any    `json:"signatures"`
				SigUpdated any    `json:"signaturesUpdated"`
				Hint       string `json:"hint"`
			}
			if json.Unmarshal(rec.Status, &st) == nil {
				row.Engine, row.Enabled, row.Realtime, row.Hint = st.Engine, st.Enabled, st.Realtime, st.Hint
				if st.Signatures != nil {
					row.Signatures = strings.TrimSpace(strings.ReplaceAll(strings.TrimSpace(toStr(st.Signatures)), "\n", " "))
				}
				if st.SigUpdated != nil {
					row.SigDate = toStr(st.SigUpdated)
				}
			}
		}
		switch {
		case rec.StatusAt.IsZero() && rec.LastErr != "":
			row.State = "error"
		case rec.StatusAt.IsZero():
			row.State = "unknown"
		case row.Engine == "none" || row.Engine == "":
			row.State = "missing"
		case !rec.UpdatedAt.IsZero() && time.Since(rec.UpdatedAt) < avStaleAfter, row.Engine == "XProtect (built in)":
			row.State = "current"
		default:
			row.State = "stale"
		}
		rows = append(rows, row)
	}
	sort.Slice(rows, func(i, j int) bool { return strings.ToLower(rows[i].Name) < strings.ToLower(rows[j].Name) })
	return rows
}

func toStr(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	b, _ := json.Marshal(v)
	return strings.Trim(string(b), `"`)
}

func (s *Server) handleAV(w http.ResponseWriter, r *http.Request, sess *session) {
	rows := s.avRows()
	counts := map[string]int{}
	for _, x := range rows {
		counts[x.State]++
	}
	var last time.Time
	for _, x := range rows {
		if x.UpdatedAt.After(last) {
			last = x.UpdatedAt
		}
	}
	writeJSON(w, 200, map[string]any{"rows": rows, "counts": counts, "lastUpdate": last, "everyHours": int(avUpdateEvery / time.Hour),
		"engines": "Microsoft Defender on Windows, ClamAV on Linux, XProtect on macOS: each vendor publishes new threat definitions several times a day, and Helm tells every PC to fetch them at least once every 24 hours."})
}

func (s *Server) handleAVUpdateAll(w http.ResponseWriter, r *http.Request, sess *session) {
	n := 0
	online := s.hub.onlineIDs()
	for _, d := range s.st.devices() {
		if d.Approved && d.has("av") && online[d.ID] != nil {
			if _, err := s.hub.dispatch(d.ID, "av.update", json.RawMessage(`{}`), sess.User); err == nil {
				n++
			}
		}
	}
	s.record(r, "av_update_all", "", "")
	writeJSON(w, 200, map[string]int{"started": n})
}
