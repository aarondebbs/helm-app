// Package server implements the Helm web server: admin API, agent hub and UI.
package server

import (
	"embed"
	"encoding/json"
	"io/fs"
	"log"
	"mime"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

//go:embed web
var webFS embed.FS

func init() { _ = mime.AddExtensionType(".woff2", "font/woff2") }

// Config controls the server.
type Config struct {
	DataDir    string
	Listen     string // e.g. 127.0.0.1:8787
	Dev        bool   // allow insecure cookies (plain HTTP on localhost)
	TrustProxy bool   // trust X-Forwarded-For from a loopback proxy (Tailscale Funnel)
	RDPBind    string // address the RDP tunnel listeners bind to (default 127.0.0.1)
	Version    string
	// UpdatePubKey is the hex ed25519 release key (compiled in); GitHubAPI overrides the API base in tests.
	UpdatePubKey string
	GitHubAPI    string
	// GoogleTokenURL overrides Google's token endpoint in tests.
	GoogleTokenURL string
}

// Server is the Helm server.
type Server struct {
	cfg       Config
	st        *Store
	db        *DB
	cve       *cveEngine
	hist      *histStore
	stop      chan struct{}
	wg        sync.WaitGroup
	sess      *sessions
	hub       *Hub
	oidc      oidcStore
	upd       *updater
	loginIP   *limiter
	loginAcct *limiter
	agentIP   *limiter
	audit     *auditLog
	tunnels   *tunnelMgr
	log       *log.Logger
	handler   http.Handler
}

// New creates a server.
func New(cfg Config) (*Server, error) {
	st, err := OpenStore(cfg.DataDir)
	if err != nil {
		return nil, err
	}
	if cfg.RDPBind == "" {
		cfg.RDPBind = "127.0.0.1"
	}
	db, err := OpenDB(cfg.DataDir)
	if err != nil {
		return nil, err
	}
	s := &Server{
		cfg:       cfg,
		st:        st,
		db:        db,
		hist:      newHistStore(),
		stop:      make(chan struct{}),
		sess:      newSessions(),
		hub:       newHub(),
		loginIP:   newLimiter(5, 15*time.Minute, 15*time.Minute),
		loginAcct: newLimiter(30, time.Hour, 15*time.Minute),
		agentIP:   newLimiter(30, 10*time.Minute, 10*time.Minute),
		audit:     newAudit(filepath.Join(cfg.DataDir, "audit.jsonl")),
		log:       log.New(os.Stderr, "helm: ", log.LstdFlags),
	}
	s.cve = newCVEEngine(cfg.DataDir, func() string { return s.db.settings().NVDKey })
	s.tunnels = newTunnelMgr(s)
	s.hub.onFinish = s.storeInventory
	s.upd = newUpdater(cfg)
	s.upd.exit = func() { s.Close(); os.Exit(0) }
	s.handler = s.routes()
	return s, nil
}

// Handler returns the HTTP handler (for tests and embedding).
func (s *Server) Handler() http.Handler { return s.handler }

// Store exposes the store for CLI commands.
func (s *Server) Store() *Store { return s.st }

// StartBackground launches the alert engine, scheduler and CVE downloader.
func (s *Server) StartBackground() {
	s.cve.start()
	s.wg.Add(7)
	go s.loop(time.Hour, s.autoBackup)
	go s.loop(6*time.Hour, s.autoUpdateCheck)
	go s.loop(10*time.Minute, s.autoInventory)
	go s.loop(30*time.Second, s.evalAlerts)
	go s.loop(15*time.Second, s.runDueSchedules)
	go s.loop(5*time.Minute, s.autoScan)
	go s.loop(2*time.Minute, s.autoPatch)
}

func (s *Server) loop(every time.Duration, fn func()) {
	defer s.wg.Done()
	t := time.NewTicker(every)
	defer t.Stop()
	time.AfterFunc(5*time.Second, func() {
		select {
		case <-s.stop:
		default:
			fn()
		}
	})
	for {
		select {
		case <-t.C:
			fn()
		case <-s.stop:
			return
		}
	}
}

// Close flushes state and stops background work.
func (s *Server) Close() {
	select {
	case <-s.stop:
		return
	default:
		close(s.stop)
	}
	s.wg.Wait()
	s.cve.close()
	s.db.Close()
	s.st.Close()
}

// Run serves until the listener fails.
func (s *Server) Run() error {
	srv := &http.Server{
		Addr:              s.cfg.Listen,
		Handler:           s.handler,
		ReadHeaderTimeout: 15 * time.Second,
		IdleTimeout:       2 * time.Minute,
		ErrorLog:          s.log,
	}
	s.StartBackground()
	s.log.Printf("listening on %s (version %s)", s.cfg.Listen, s.cfg.Version)
	return srv.ListenAndServe()
}

func (s *Server) routes() http.Handler {
	mux := http.NewServeMux()

	// public
	mux.HandleFunc("POST /api/login", s.handleLogin)
	mux.HandleFunc("GET /api/auth/google/start", s.handleGoogleStart)
	mux.HandleFunc("GET /api/auth/google/callback", s.handleGoogleCallback)
	mux.HandleFunc("GET /api/settings/google", s.authed(s.handleGoogleGet, false))
	mux.HandleFunc("PUT /api/settings/google", s.authed(s.handleGooglePut, true))
	mux.HandleFunc("POST /api/agent/enroll", s.handleEnroll)
	mux.HandleFunc("GET /api/agent/update", s.handleAgentUpdate)
	mux.HandleFunc("GET /ws/agent", s.handleAgentWS)
	mux.HandleFunc("GET /ws/agent/chan/{sid}", s.handleAgentChan)
	mux.HandleFunc("GET /dl/{file}", s.handleDownloadDist)
	mux.HandleFunc("GET /dl/releases/{dir}/{file}", s.handleDownloadRelease)

	// authenticated
	mux.HandleFunc("GET /api/me", s.authed(s.handleMe, false))
	mux.HandleFunc("POST /api/logout", s.authed(s.handleLogout, true))
	mux.HandleFunc("POST /api/account/2fa/begin", s.authed(s.handle2faBegin, true))
	mux.HandleFunc("POST /api/account/2fa/confirm", s.authed(s.handle2faConfirm, true))
	mux.HandleFunc("POST /api/account/2fa/disable", s.authed(s.handle2faDisable, true))
	mux.HandleFunc("GET /api/auth/config", s.handleAuthConfig)
	mux.HandleFunc("GET /api/update", s.authed(s.handleUpdateGet, false))
	mux.HandleFunc("POST /api/update/check", s.authed(s.handleUpdateCheck, false))
	mux.HandleFunc("GET /api/health", s.authed(s.handleHealth, false))
	mux.HandleFunc("GET /healthz", s.handleHealthz)
	mux.HandleFunc("POST /api/devices/{id}/update-software", s.authed(s.handleUpdateSoftware, true))
	mux.HandleFunc("GET /api/patch-window", s.authed(s.handlePatchGet, false))
	mux.HandleFunc("PUT /api/patch-window", s.authed(s.handlePatchPut, true))
	mux.HandleFunc("GET /api/backups", s.authed(s.handleBackupsList, false))
	mux.HandleFunc("POST /api/backups", s.authed(s.handleBackupCreate, true))
	mux.HandleFunc("POST /api/backups/upload", s.authed(s.handleBackupUpload, true))
	mux.HandleFunc("POST /api/backups/restore", s.authed(s.handleBackupRestore, true))
	mux.HandleFunc("GET /api/backups/{name}", s.authed(s.handleBackupDownload, false))
	mux.HandleFunc("DELETE /api/backups/{name}", s.authed(s.handleBackupDelete, true))
	mux.HandleFunc("POST /api/update/agents", s.authed(s.handleUpdateAgents, true))
	mux.HandleFunc("POST /api/update/server", s.authed(s.handleUpdateServer, true))
	mux.HandleFunc("GET /api/devices/{id}/inventory", s.authed(s.handleDeviceInventory, false))
	mux.HandleFunc("POST /api/account/password", s.authed(s.handleChangePassword, true))
	mux.HandleFunc("POST /api/account/username", s.authed(s.handleChangeUsername, true))
	mux.HandleFunc("POST /api/stepup", s.authed(s.handleStepUp, true))
	mux.HandleFunc("GET /api/info", s.authed(s.handleInfo, false))
	mux.HandleFunc("GET /api/devices", s.authed(s.handleDevices, false))
	mux.HandleFunc("GET /api/devices/{id}", s.authed(s.handleDevice, false))
	mux.HandleFunc("POST /api/devices/{id}/approve", s.authed(s.handleApprove, true))
	mux.HandleFunc("POST /api/devices/{id}/edit", s.authed(s.handleEdit, true))
	mux.HandleFunc("DELETE /api/devices/{id}", s.authed(s.handleDeleteDevice, true))
	mux.HandleFunc("POST /api/devices/{id}/cmd", s.authed(s.handleCmd, true))
	mux.HandleFunc("POST /api/devices/{id}/wake", s.authed(s.handleWake, true))
	mux.HandleFunc("GET /api/devices/{id}/jobs", s.authed(s.handleDeviceJobs, false))
	mux.HandleFunc("GET /api/jobs/{id}", s.authed(s.handleJob, false))
	mux.HandleFunc("GET /api/tokens", s.authed(s.handleTokens, false))
	mux.HandleFunc("POST /api/tokens", s.authed(s.handleCreateToken, true))
	mux.HandleFunc("POST /api/installer", s.authed(s.handleInstaller, true))
	mux.HandleFunc("DELETE /api/tokens/{id}", s.authed(s.handleRevokeToken, true))
	mux.HandleFunc("GET /api/audit", s.authed(s.handleAudit, false))
	mux.HandleFunc("POST /api/devices/{id}/rdp/open", s.authed(s.handleRDPOpen, true))
	mux.HandleFunc("GET /api/tunnels", s.authed(s.handleTunnels, false))
	mux.HandleFunc("DELETE /api/tunnels/{id}", s.authed(s.handleTunnelClose, true))
	mux.HandleFunc("GET /api/devices/{id}/download", s.authed(s.handleFileDownload, false))
	mux.HandleFunc("POST /api/devices/{id}/upload", s.authed(s.handleFileUpload, true))
	mux.HandleFunc("GET /api/agent/package/{id}", s.handleAgentPackage)
	mux.HandleFunc("GET /api/dashboard", s.authed(s.handleDashboard, false))
	mux.HandleFunc("GET /api/devices/{id}/scan", s.authed(s.handleDeviceScan, false))
	mux.HandleFunc("POST /api/devices/{id}/scan", s.authed(s.handleDeviceScanStart, true))
	mux.HandleFunc("GET /api/devices/{id}/history", s.authed(s.handleDeviceHistory, false))
	mux.HandleFunc("GET /api/software", s.authed(s.handleSoftware, false))
	mux.HandleFunc("GET /api/security", s.authed(s.handleFleetSecurity, false))
	mux.HandleFunc("GET /api/reports/{kind}", s.authed(s.handleReport, false))
	mux.HandleFunc("GET /api/sessions", s.authed(s.handleSessions, false))
	mux.HandleFunc("GET /api/alerts", s.authed(s.handleAlerts, false))
	mux.HandleFunc("POST /api/alerts/{id}/ack", s.authed(s.handleAlertAck, true))
	mux.HandleFunc("POST /api/alerts/clear", s.authed(s.handleAlertsClear, true))
	mux.HandleFunc("GET /api/settings", s.authed(s.handleSettingsGet, false))
	mux.HandleFunc("PUT /api/settings", s.authed(s.handleSettingsPut, true))
	mux.HandleFunc("POST /api/settings/telegram-test", s.authed(s.handleTelegramTest, true))
	mux.HandleFunc("GET /api/scripts", s.authed(s.handleScripts, false))
	mux.HandleFunc("POST /api/scripts", s.authed(s.handleScriptSave, true))
	mux.HandleFunc("PUT /api/scripts/{id}", s.authed(s.handleScriptSave, true))
	mux.HandleFunc("DELETE /api/scripts/{id}", s.authed(s.handleScriptDelete, true))
	mux.HandleFunc("POST /api/run/script", s.authed(s.handleRunScript, true))
	mux.HandleFunc("POST /api/run/scan", s.authed(s.handleRunScan, true))
	mux.HandleFunc("GET /api/runs", s.authed(s.handleRuns, false))
	mux.HandleFunc("GET /api/runs/{id}", s.authed(s.handleRun, false))
	mux.HandleFunc("GET /api/schedules", s.authed(s.handleSchedules, false))
	mux.HandleFunc("POST /api/schedules", s.authed(s.handleScheduleSave, true))
	mux.HandleFunc("PUT /api/schedules/{id}", s.authed(s.handleScheduleSave, true))
	mux.HandleFunc("DELETE /api/schedules/{id}", s.authed(s.handleScheduleDelete, true))
	mux.HandleFunc("POST /api/schedules/{id}/run", s.authed(s.handleScheduleRunNow, true))
	mux.HandleFunc("GET /api/packages", s.authed(s.handlePackages, false))
	mux.HandleFunc("POST /api/packages", s.authed(s.handlePackageAdd, true))
	mux.HandleFunc("POST /api/packages/upload", s.authed(s.handlePackageUpload, true))
	mux.HandleFunc("DELETE /api/packages/{id}", s.authed(s.handlePackageDelete, true))
	mux.HandleFunc("POST /api/deploy", s.authed(s.handleDeploy, true))
	mux.HandleFunc("GET /ws/ui", s.handleUIChannel)

	sub, _ := fs.Sub(webFS, "web")
	mux.Handle("GET /", http.FileServerFS(sub))

	return s.secure(mux)
}

// secure adds security headers to every response.
func (s *Server) secure(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Content-Security-Policy", "default-src 'self'; img-src 'self' blob: data:; style-src 'self' 'unsafe-inline'; "+
			"connect-src 'self' ws: wss:; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
		if !s.cfg.Dev {
			h.Set("Strict-Transport-Security", "max-age=31536000")
		}
		if strings.HasPrefix(r.URL.Path, "/api/") {
			h.Set("Cache-Control", "no-store")
		}
		next.ServeHTTP(w, r)
	})
}

// ---- helpers ----

func (s *Server) clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	if s.cfg.TrustProxy {
		if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
			if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
				parts := strings.Split(xff, ",")
				if last := strings.TrimSpace(parts[len(parts)-1]); net.ParseIP(last) != nil {
					return last
				}
			}
		}
	}
	return host
}

func (s *Server) cookieName() string {
	if s.cfg.Dev {
		return "helm_session"
	}
	return "__Host-helm"
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]string{"error": msg})
}

func readJSON(w http.ResponseWriter, r *http.Request, v any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	dec := json.NewDecoder(r.Body)
	if err := dec.Decode(v); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid request body")
		return false
	}
	return true
}

// sameOrigin reports whether the Origin header (if any) matches the Host.
func sameOrigin(r *http.Request) bool {
	o := r.Header.Get("Origin")
	if o == "" {
		return true
	}
	u, err := url.Parse(o)
	if err != nil {
		return false
	}
	return strings.EqualFold(u.Host, r.Host)
}

type authedFunc func(w http.ResponseWriter, r *http.Request, sess *session)

// authed wraps a handler with session authentication. When mutating is true the
// request must carry the CSRF token and a same-origin Origin header.
func (s *Server) authed(fn authedFunc, mutating bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sess := s.sessionFor(r)
		if sess == nil {
			writeErr(w, http.StatusUnauthorized, "not signed in")
			return
		}
		if mutating {
			if !sameOrigin(r) || !ctEq(r.Header.Get("X-CSRF-Token"), sess.CSRF) {
				writeErr(w, http.StatusForbidden, "bad CSRF token")
				return
			}
		}
		fn(w, r, sess)
	}
}

func (s *Server) sessionFor(r *http.Request) *session {
	c, err := r.Cookie(s.cookieName())
	if err != nil {
		return nil
	}
	return s.sess.get(c.Value)
}

// needStepUp writes a 428 and returns false when a recent 2FA check is missing.
func (s *Server) needStepUp(w http.ResponseWriter, sess *session) bool {
	if s.sess.stepUpValid(sess) {
		return true
	}
	writeErr(w, http.StatusPreconditionRequired, "stepup_required")
	return false
}
