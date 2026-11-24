package agent

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"helm/internal/proto"
)

// TrayStatus is what the tray icon on the PC shows. The service writes it to a folder every user can read.
// It holds nothing secret: no token, no device secret.
type TrayStatus struct {
	proto.Config
	Computer string    `json:"computer"`
	Version  string    `json:"version"`
	State    string    `json:"state"` // starting | connecting | pending | connected | offline
	Server   string    `json:"server"`
	Control  string    `json:"control,omitempty"` // loopback address of the support-request endpoint
	Updated  time.Time `json:"updated"`
}

// PublicDir is the folder the tray reads. It is separate from the agent's private data folder.
func PublicDir() string {
	if d := publicDirOS(); d != "" {
		return d
	}
	return filepath.Join(os.TempDir(), "helm-public")
}

func statusPath() string { return filepath.Join(PublicDir(), "status.json") }

func (a *Agent) setState(state string) {
	a.stMu.Lock()
	a.tray.State = state
	a.stMu.Unlock()
	a.writeStatus()
}

func (a *Agent) setConfig(c proto.Config) {
	a.stMu.Lock()
	a.tray.Config = c
	a.stMu.Unlock()
	a.writeStatus()
}

func (a *Agent) writeStatus() {
	a.stMu.Lock()
	s := a.tray
	s.Updated = time.Now().UTC()
	s.Version, s.Server = a.cfg.Version, a.cfg.Server
	s.Computer, _ = os.Hostname()
	a.stMu.Unlock()
	dir := PublicDir()
	if os.MkdirAll(dir, 0o755) != nil {
		return
	}
	b, _ := json.Marshal(s)
	tmp := statusPath() + ".tmp"
	if os.WriteFile(tmp, b, 0o644) == nil {
		_ = os.Rename(tmp, statusPath())
	}
}

// statusLoop keeps the status fresh so the tray can tell a stopped agent from a quiet one.
func (a *Agent) statusLoop(ctx context.Context) {
	a.setState("starting")
	t := time.NewTicker(30 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			a.writeStatus()
		}
	}
}

// serveControl accepts "request support" from the tray on the loopback interface only.
func (a *Agent) serveControl(ctx context.Context) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return
	}
	a.stMu.Lock()
	a.tray.Control = ln.Addr().String()
	a.stMu.Unlock()
	a.writeStatus()
	var last time.Time
	mux := http.NewServeMux()
	mux.HandleFunc("POST /support", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Helm-Tray") != "1" {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		a.stMu.Lock()
		ok := a.tray.State == "connected" && a.tray.AllowSupport
		a.stMu.Unlock()
		if !ok {
			http.Error(w, "this PC is not connected to the portal right now", http.StatusServiceUnavailable)
			return
		}
		if time.Since(last) < time.Minute {
			http.Error(w, "a request was sent a moment ago", http.StatusTooManyRequests)
			return
		}
		last = time.Now()
		var req struct{ Msg string }
		_ = json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&req)
		if req.Msg == "" {
			req.Msg = "Someone at the PC asked for support."
		}
		a.sendFrame(proto.Frame{T: proto.TSupport, Msg: req.Msg})
		w.WriteHeader(http.StatusNoContent)
	})
	srv := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	go func() { <-ctx.Done(); _ = srv.Close() }()
	_ = srv.Serve(ln)
}
