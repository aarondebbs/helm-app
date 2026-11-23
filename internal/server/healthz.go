package server

import (
	"net/http"
	"os"
	"path/filepath"
)

// handleHealthz is for uptime monitors: no sign-in, no details beyond ok/not ok and the version.
// It answers 503 when the data directory cannot be written, which is the failure that matters on a Pi
// (full or read-only SD card).
func (s *Server) handleHealthz(w http.ResponseWriter, r *http.Request) {
	probe := filepath.Join(s.cfg.DataDir, ".healthz")
	if err := os.WriteFile(probe, []byte("ok"), 0o600); err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"status": "unhealthy", "version": s.cfg.Version})
		return
	}
	_ = os.Remove(probe)
	writeJSON(w, 200, map[string]any{"status": "ok", "version": s.cfg.Version})
}
