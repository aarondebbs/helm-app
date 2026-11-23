package server

import (
	"net/http"
	"strconv"
	"time"
)

// sessionStart records the start of a remote session and returns its id.
func (s *Server) sessionStart(r *http.Request, deviceID, kind string, viewOnly bool) string {
	name := deviceID
	if d, ok := s.st.device(deviceID); ok {
		name = d.Name
	}
	rec := &SessionRec{ID: randHex(6), DeviceID: deviceID, DeviceName: name, Kind: kind, Started: time.Now().UTC(),
		ViewOnly: viewOnly, IP: s.clientIP(r), Result: "active"}
	s.db.update(func(d *dbData) {
		d.Sessions = append(d.Sessions, rec)
		if len(d.Sessions) > maxSessions {
			d.Sessions = d.Sessions[len(d.Sessions)-maxSessions:]
		}
	})
	return rec.ID
}

// sessionEnd finalises a session record.
func (s *Server) sessionEnd(id, result, detail string) {
	s.db.update(func(d *dbData) {
		for i := len(d.Sessions) - 1; i >= 0; i-- {
			if d.Sessions[i].ID == id {
				d.Sessions[i].Ended, d.Sessions[i].Result, d.Sessions[i].Detail = time.Now().UTC(), result, detail
				return
			}
		}
	})
}

// sessionRefused records a session that never started.
func (s *Server) sessionRefused(r *http.Request, deviceID, kind, why string) {
	id := s.sessionStart(r, deviceID, kind, false)
	s.sessionEnd(id, "refused", why)
}

func (s *Server) handleSessions(w http.ResponseWriter, r *http.Request, sess *session) {
	limit := 300
	if n, err := strconv.Atoi(r.URL.Query().Get("limit")); err == nil && n > 0 && n < 2001 {
		limit = n
	}
	dev := r.URL.Query().Get("device")
	out := []SessionRec{}
	s.db.view(func(d *dbData) {
		for i := len(d.Sessions) - 1; i >= 0 && len(out) < limit; i-- {
			if dev == "" || d.Sessions[i].DeviceID == dev {
				out = append(out, *d.Sessions[i])
			}
		}
	})
	writeJSON(w, 200, out)
}
