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
	StatusAt  time.Time       `json:"statusAt"`
	Status    json.RawMessage `json:"status,omitempty"`
	UpdatedAt time.Time       `json:"updatedAt"` // last successful signature update that Helm started
	LastErr   string          `json:"lastErr,omitempty"`
	LastErrAt time.Time       `json:"lastErrAt,omitempty"`
}

func (s *Server) storeAV(j Job) {
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

// kickAV starts the first update and status read for a PC that just got the Antivirus module.
func (s *Server) kickAV(id string, mods []string) {
	for _, m := range mods {
		if m == "av" {
			_, _ = s.hub.dispatch(id, "av.update", json.RawMessage(`{}`), "auto-av")
			_, _ = s.hub.dispatch(id, "av.status", json.RawMessage(`{}`), "auto-av")
			return
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
	}
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
