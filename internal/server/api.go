package server

import (
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"helm/internal/proto"
	"helm/internal/ws"
)

// record writes an audit entry for a request.
func (s *Server) record(r *http.Request, action, device, detail string) {
	s.audit.add(AuditEntry{IP: s.clientIP(r), Action: action, Device: device, Detail: detail})
}

// ---- auth endpoints ----

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	ip := s.clientIP(r)
	if !sameOrigin(r) {
		writeErr(w, http.StatusForbidden, "bad origin")
		return
	}
	if !s.loginIP.allowed(ip) || !s.loginAcct.allowed("admin") {
		writeErr(w, http.StatusTooManyRequests, "too many attempts, try again later")
		return
	}
	var req struct{ User, Password, Code string }
	if !readJSON(w, r, &req) {
		return
	}
	adm := s.st.admin()
	if adm == nil {
		writeErr(w, http.StatusServiceUnavailable, "no administrator configured; run: helm-server init-admin")
		return
	}
	pwOK := checkPassword(adm, req.User, req.Password)
	step, codeOK := adm.checkCode(req.Code)
	if !pwOK || !codeOK {
		s.loginIP.fail(ip)
		s.loginAcct.fail("admin")
		s.audit.add(AuditEntry{IP: ip, Action: "login_failed"})
		time.Sleep(500 * time.Millisecond)
		writeErr(w, http.StatusUnauthorized, "invalid credentials")
		return
	}
	_ = s.st.update(func(d *data) error { d.Admin.LastStep = step; return nil })
	s.loginIP.reset(ip)
	token, sess := s.sess.create(ip, r.UserAgent())
	http.SetCookie(w, &http.Cookie{Name: s.cookieName(), Value: token, Path: "/", HttpOnly: true,
		Secure: !s.cfg.Dev, SameSite: http.SameSiteStrictMode})
	s.audit.add(AuditEntry{IP: ip, Action: "login"})
	writeJSON(w, 200, map[string]any{"user": adm.User, "csrf": sess.CSRF})
}

func (s *Server) handleMe(w http.ResponseWriter, r *http.Request, sess *session) {
	adm := s.st.admin()
	writeJSON(w, 200, map[string]any{"user": adm.User, "csrf": sess.CSRF, "totp": adm.TOTPSecret != "", "stepUp": s.sess.stepUpValid(sess),
		"stepUpUntil": sess.StepUpUntil})
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request, sess *session) {
	if c, err := r.Cookie(s.cookieName()); err == nil {
		s.sess.destroy(c.Value)
	}
	http.SetCookie(w, &http.Cookie{Name: s.cookieName(), Value: "", Path: "/", MaxAge: -1, HttpOnly: true,
		Secure: !s.cfg.Dev, SameSite: http.SameSiteStrictMode})
	s.record(r, "logout", "", "")
	writeJSON(w, 200, map[string]bool{"ok": true})
}

func (s *Server) handleStepUp(w http.ResponseWriter, r *http.Request, sess *session) {
	ip := s.clientIP(r)
	if !s.loginIP.allowed(ip) || !s.loginAcct.allowed("admin") {
		writeErr(w, http.StatusTooManyRequests, "too many attempts, try again later")
		return
	}
	var req struct{ Code, Password string }
	if !readJSON(w, r, &req) {
		return
	}
	adm := s.st.admin()
	step, ok := adm.checkCode(req.Code)
	if adm.TOTPSecret == "" { // two-step verification is off: confirm with the password instead
		ok = checkPassword(adm, adm.User, req.Password)
	}
	if !ok {
		s.loginIP.fail(ip)
		s.loginAcct.fail("admin")
		s.record(r, "stepup_failed", "", "")
		writeErr(w, http.StatusUnauthorized, "invalid or already used code (wait for the next one)")
		return
	}
	_ = s.st.update(func(d *data) error { d.Admin.LastStep = step; return nil })
	s.sess.grantStepUp(sess)
	s.record(r, "stepup", "", "")
	writeJSON(w, 200, map[string]any{"stepUpUntil": sess.StepUpUntil})
}

// handleChangePassword sets a new administrator password. It needs a step-up window and the current
// password, and signs out every other session.
func (s *Server) handleChangePassword(w http.ResponseWriter, r *http.Request, sess *session) {
	var req struct{ Current, New string }
	if !readJSON(w, r, &req) {
		return
	}
	if err := ValidatePasswordStrength(req.New); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	ip := s.clientIP(r)
	if !s.loginIP.allowed(ip) || !s.loginAcct.allowed("admin") {
		writeErr(w, http.StatusTooManyRequests, "too many attempts, try again later")
		return
	}
	adm := s.st.admin()
	if !checkPassword(adm, adm.User, req.Current) {
		s.loginIP.fail(ip)
		s.loginAcct.fail("admin")
		s.record(r, "password_change_failed", "", "")
		writeErr(w, http.StatusUnauthorized, "current password is wrong")
		return
	}
	if err := s.st.SetPassword(req.New); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.sess.destroyAllExcept(sess)
	s.record(r, "password_changed", "", "")
	writeJSON(w, 200, map[string]bool{"ok": true})
}

// handleChangeUsername renames the administrator. It needs a step-up window and the current password.
func (s *Server) handleChangeUsername(w http.ResponseWriter, r *http.Request, sess *session) {
	var req struct{ NewUser, Password string }
	if !readJSON(w, r, &req) {
		return
	}
	nu := strings.TrimSpace(req.NewUser)
	if l := len([]rune(nu)); l < 3 || l > 40 || strings.ContainsAny(nu, "\r\n\t") {
		writeErr(w, http.StatusBadRequest, "the username must be 3-40 characters")
		return
	}
	ip := s.clientIP(r)
	if !s.loginIP.allowed(ip) || !s.loginAcct.allowed("admin") {
		writeErr(w, http.StatusTooManyRequests, "too many attempts, try again later")
		return
	}
	adm := s.st.admin()
	if !checkPassword(adm, adm.User, req.Password) {
		s.loginIP.fail(ip)
		s.loginAcct.fail("admin")
		s.record(r, "username_change_failed", "", "")
		writeErr(w, http.StatusUnauthorized, "current password is wrong")
		return
	}
	_ = s.st.update(func(d *data) error { d.Admin.User = nu; return nil })
	s.record(r, "username_changed", "", nu)
	writeJSON(w, 200, map[string]any{"user": nu})
}

func (s *Server) baseURL(r *http.Request) string {
	scheme := "https"
	if s.cfg.Dev {
		scheme = "http"
	}
	return scheme + "://" + r.Host
}

func (s *Server) handleInfo(w http.ResponseWriter, r *http.Request, sess *session) {
	_, msiErr := os.Stat(filepath.Join(s.cfg.DataDir, "dist", "Helm-Agent.msi"))
	_, tplErr := os.Stat(filepath.Join(s.cfg.DataDir, "dist", "Helm-Agent.template.msi"))
	var dist []string
	if ents, err := os.ReadDir(filepath.Join(s.cfg.DataDir, "dist")); err == nil {
		for _, e := range ents {
			if !e.IsDir() && reFile.MatchString(e.Name()) && !strings.HasSuffix(e.Name(), ".version") {
				dist = append(dist, e.Name())
			}
		}
	}
	writeJSON(w, 200, map[string]any{"version": s.cfg.Version, "baseUrl": s.baseURL(r), "msi": msiErr == nil, "installer": tplErr == nil,
		"releases": s.listReleases(), "dist": dist})
}

// ---- devices ----

type deviceView struct {
	ID        string       `json:"id"`
	Name      string       `json:"name"`
	Notes     string       `json:"notes"`
	Group     string       `json:"group"`
	Tags      []string     `json:"tags"`
	Security  *secSummary  `json:"security,omitempty"`
	Approved  bool         `json:"approved"`
	Online    bool         `json:"online"`
	LastSeen  time.Time    `json:"lastSeen"`
	LastIP    string       `json:"lastIp"`
	Via       string       `json:"via"`
	CreatedAt time.Time    `json:"createdAt"`
	Hello     *proto.Hello `json:"hello,omitempty"`
	Stats     *proto.Stats `json:"stats,omitempty"`
	StatsAt   time.Time    `json:"statsAt,omitempty"`
}

func (s *Server) view(d Device, online map[string]*Agent) deviceView {
	v := deviceView{ID: d.ID, Name: d.Name, Notes: d.Notes, Group: d.Group, Tags: d.Tags, Approved: d.Approved, LastSeen: d.LastSeen,
		LastIP: d.LastIP, Via: d.Via, CreatedAt: d.CreatedAt, Hello: d.Hello}
	if v.Tags == nil {
		v.Tags = []string{}
	}
	if a := online[d.ID]; a != nil {
		v.Online = true
		v.Stats, v.StatsAt = a.stats()
	}
	if d.Approved {
		v.Security = s.secSummaryFor(d.ID)
	}
	return v
}

func (s *Server) handleDevices(w http.ResponseWriter, r *http.Request, sess *session) {
	online := s.hub.onlineIDs()
	out := []deviceView{}
	for _, d := range s.st.devices() {
		out = append(out, s.view(d, online))
	}
	writeJSON(w, 200, out)
}

func (s *Server) handleDevice(w http.ResponseWriter, r *http.Request, sess *session) {
	d, ok := s.st.device(r.PathValue("id"))
	if !ok {
		writeErr(w, 404, "no such device")
		return
	}
	writeJSON(w, 200, s.view(d, s.hub.onlineIDs()))
}

func (s *Server) handleApprove(w http.ResponseWriter, r *http.Request, sess *session) {
	id := r.PathValue("id")
	if !s.needStepUp(w, sess) {
		return
	}
	err := s.st.update(func(d *data) error {
		dev := d.Devices[id]
		if dev == nil {
			return errors.New("no such device")
		}
		dev.Approved = true
		return nil
	})
	if err != nil {
		writeErr(w, 404, err.Error())
		return
	}
	if a := s.hub.online(id); a != nil {
		a.approved.Store(true)
		_ = a.send(proto.Frame{T: proto.TApproved})
	}
	s.record(r, "device_approved", id, "")
	writeJSON(w, 200, map[string]bool{"ok": true})
}

func (s *Server) handleEdit(w http.ResponseWriter, r *http.Request, sess *session) {
	id := r.PathValue("id")
	var req struct {
		Name, Notes, Group string
		Tags               []string
	}
	if !readJSON(w, r, &req) {
		return
	}
	req.Name = strings.TrimSpace(req.Name)
	req.Group = strings.TrimSpace(req.Group)
	if req.Name == "" || len(req.Name) > 80 || len(req.Notes) > 2000 || len(req.Group) > 40 {
		writeErr(w, 400, "name must be 1-80 characters, notes up to 2000, group up to 40")
		return
	}
	tags := []string{}
	seen := map[string]bool{}
	for _, t := range req.Tags {
		t = strings.ToLower(strings.TrimSpace(t))
		if t == "" || seen[t] {
			continue
		}
		if len(t) > 30 || len(tags) >= 12 {
			writeErr(w, 400, "tags: up to 12, each up to 30 characters")
			return
		}
		seen[t] = true
		tags = append(tags, t)
	}
	err := s.st.update(func(d *data) error {
		dev := d.Devices[id]
		if dev == nil {
			return errors.New("no such device")
		}
		dev.Name, dev.Notes, dev.Group, dev.Tags = req.Name, req.Notes, req.Group, tags
		return nil
	})
	if err != nil {
		writeErr(w, 404, err.Error())
		return
	}
	s.record(r, "device_edited", id, req.Name)
	writeJSON(w, 200, map[string]bool{"ok": true})
}

func (s *Server) handleDeleteDevice(w http.ResponseWriter, r *http.Request, sess *session) {
	id := r.PathValue("id")
	if !s.needStepUp(w, sess) {
		return
	}
	err := s.st.update(func(d *data) error {
		if d.Devices[id] == nil {
			return errors.New("no such device")
		}
		delete(d.Devices, id)
		return nil
	})
	if err != nil {
		writeErr(w, 404, err.Error())
		return
	}
	if a := s.hub.online(id); a != nil {
		_ = a.send(proto.Frame{T: proto.TRevoked})
		a.conn.Close(ws.ClosePolicy, "revoked")
	}
	s.hist.drop(id)
	s.db.update(func(x *dbData) { delete(x.Scans, id) })
	s.record(r, "device_deleted", id, "")
	writeJSON(w, 200, map[string]bool{"ok": true})
}

func (s *Server) handleCmd(w http.ResponseWriter, r *http.Request, sess *session) {
	id := r.PathValue("id")
	var req struct {
		Name string          `json:"name"`
		Args json.RawMessage `json:"args"`
		Wait int             `json:"wait"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	spec, ok := commands[req.Name]
	if !ok || req.Name == "wol" {
		writeErr(w, 400, "unknown command")
		return
	}
	if spec.Danger && !s.needStepUp(w, sess) {
		return
	}
	if len(req.Args) > 0 && !json.Valid(req.Args) {
		writeErr(w, 400, "args must be JSON")
		return
	}
	job, err := s.hub.dispatch(id, req.Name, req.Args, "admin")
	if err != nil {
		code := 409
		if errors.Is(err, errUnknownC) {
			code = 400
		}
		writeErr(w, code, err.Error())
		return
	}
	detail := req.Name
	if len(req.Args) > 0 {
		detail += " " + string(req.Args)
	}
	s.record(r, "command", id, detail)
	if req.Wait > 0 {
		if req.Wait > 90 {
			req.Wait = 90
		}
		job = s.hub.wait(job.ID, time.Duration(req.Wait)*time.Second)
	}
	writeJSON(w, 200, job)
}

func (s *Server) handleJob(w http.ResponseWriter, r *http.Request, sess *session) {
	j := s.hub.snapshot(r.PathValue("id"))
	if j == nil {
		writeErr(w, 404, "no such job")
		return
	}
	writeJSON(w, 200, j)
}

func (s *Server) handleDeviceJobs(w http.ResponseWriter, r *http.Request, sess *session) {
	jobs := s.hub.jobsFor(r.PathValue("id"), 50)
	if jobs == nil {
		jobs = []*Job{}
	}
	writeJSON(w, 200, jobs)
}

// handleWake asks another online PC on the same network to send a magic packet.
func (s *Server) handleWake(w http.ResponseWriter, r *http.Request, sess *session) {
	id := r.PathValue("id")
	target, ok := s.st.device(id)
	if !ok || target.Hello == nil || len(target.Hello.MACs) == 0 {
		writeErr(w, 404, "device unknown or has no MAC address on record")
		return
	}
	if s.hub.online(id) != nil {
		writeErr(w, 409, "device is already online")
		return
	}
	var relay *Agent
	for rid, a := range s.hub.onlineIDs() {
		if rid == id || !a.approved.Load() {
			continue
		}
		rd, _ := s.st.device(rid)
		if rd.Hello != nil && sameLAN(rd, target) {
			relay = a
			break
		}
	}
	if relay == nil {
		writeErr(w, 409, "no other online PC on the same network can send the wake packet")
		return
	}
	args, _ := json.Marshal(map[string]any{"macs": target.Hello.MACs})
	job, err := s.hub.dispatch(relay.ID, "wol", args, "admin")
	if err != nil {
		writeErr(w, 409, err.Error())
		return
	}
	s.record(r, "wake", id, "via "+relay.ID)
	writeJSON(w, 200, s.hub.wait(job.ID, 15*time.Second))
}

// sameLAN is true when both devices share a /24 on a private address (or the
// same public IP when no private addresses are known).
func sameLAN(a, b Device) bool {
	for _, x := range a.Hello.IPs {
		for _, y := range b.Hello.IPs {
			if p1, p2 := net.ParseIP(x), net.ParseIP(y); p1 != nil && p2 != nil && p1.To4() != nil && p2.To4() != nil &&
				p1.IsPrivate() && p1.Mask(net.CIDRMask(24, 32)).Equal(p2.Mask(net.CIDRMask(24, 32))) {
				return true
			}
		}
	}
	return false
}

// ---- tokens, audit ----

func (s *Server) handleTokens(w http.ResponseWriter, r *http.Request, sess *session) {
	writeJSON(w, 200, s.st.tokens())
}

func (s *Server) handleCreateToken(w http.ResponseWriter, r *http.Request, sess *session) {
	if !s.needStepUp(w, sess) {
		return
	}
	var req struct {
		Label   string `json:"label"`
		Hours   int    `json:"hours"`
		MaxUses int    `json:"maxUses"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	if req.Hours <= 0 || req.Hours > 24*90 {
		req.Hours = 24
	}
	if req.MaxUses < 0 || req.MaxUses > 1000 {
		writeErr(w, 400, "maxUses out of range")
		return
	}
	if len(req.Label) > 80 {
		writeErr(w, 400, "label too long")
		return
	}
	plain, t, err := s.st.CreateToken(req.Label, time.Duration(req.Hours)*time.Hour, req.MaxUses)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	s.record(r, "token_created", "", req.Label)
	writeJSON(w, 200, map[string]any{"token": plain, "info": t})
}

func (s *Server) handleRevokeToken(w http.ResponseWriter, r *http.Request, sess *session) {
	id := r.PathValue("id")
	err := s.st.update(func(d *data) error {
		t := d.Tokens[id]
		if t == nil {
			return errors.New("no such token")
		}
		t.Revoked = true
		return nil
	})
	if err != nil {
		writeErr(w, 404, err.Error())
		return
	}
	s.record(r, "token_revoked", "", id)
	writeJSON(w, 200, map[string]bool{"ok": true})
}

func (s *Server) handleAudit(w http.ResponseWriter, r *http.Request, sess *session) {
	n, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if n <= 0 || n > 1000 {
		n = 200
	}
	writeJSON(w, 200, s.audit.tail(n))
}

// ---- agent endpoints ----

func (a *Agent) stats() (*proto.Stats, time.Time) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.Stats, a.StatsAt
}

func (s *Server) authAgent(w http.ResponseWriter, r *http.Request) (Device, bool) {
	ip := s.clientIP(r)
	if !s.agentIP.allowed(ip) {
		writeErr(w, http.StatusTooManyRequests, "too many failures")
		return Device{}, false
	}
	id := r.Header.Get("X-Helm-Device")
	secret := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	d, ok := s.st.AuthDevice(id, secret)
	if !ok {
		s.agentIP.fail(ip)
		writeErr(w, http.StatusUnauthorized, "unknown device or bad credentials")
		return Device{}, false
	}
	return d, true
}

func (s *Server) handleEnroll(w http.ResponseWriter, r *http.Request) {
	ip := s.clientIP(r)
	if !s.agentIP.allowed(ip) {
		writeErr(w, http.StatusTooManyRequests, "too many failures")
		return
	}
	var req proto.EnrollRequest
	if !readJSON(w, r, &req) {
		return
	}
	if len(req.Hello.Hostname) == 0 || len(req.Hello.Hostname) > 100 {
		writeErr(w, 400, "bad hostname")
		return
	}
	id, secret, err := s.st.Enroll(req.Token, req.Hello, ip)
	if err != nil {
		s.agentIP.fail(ip)
		s.audit.add(AuditEntry{IP: ip, Action: "enroll_rejected", Detail: req.Hello.Hostname})
		writeErr(w, http.StatusForbidden, err.Error())
		return
	}
	s.audit.add(AuditEntry{IP: ip, Action: "enroll", Device: id, Detail: req.Hello.Hostname})
	writeJSON(w, 200, proto.EnrollResponse{DeviceID: id, Secret: secret})
}

func (s *Server) handleAgentWS(w http.ResponseWriter, r *http.Request) {
	dev, ok := s.authAgent(w, r)
	if !ok {
		return
	}
	c, err := ws.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	c.SetReadLimit(4 << 20)
	c.SetIdleTimeout(90 * time.Second)
	c.KeepAlive(25 * time.Second)
	ip := s.clientIP(r)
	a := &Agent{ID: dev.ID, conn: c, Since: time.Now(), IP: ip}
	a.approved.Store(dev.Approved)
	s.hub.attach(a)
	s.st.touch(func(d *data) {
		if x := d.Devices[dev.ID]; x != nil {
			x.LastSeen, x.LastIP = time.Now().UTC(), ip
		}
	})
	defer func() {
		s.hub.detach(a)
		c.Close(ws.CloseNormal, "")
		s.st.touch(func(d *data) {
			if x := d.Devices[dev.ID]; x != nil {
				x.LastSeen = time.Now().UTC()
			}
		})
	}()
	if dev.Approved {
		_ = a.send(proto.Frame{T: proto.TApproved})
	}
	for {
		op, msg, err := c.ReadMessage()
		if err != nil {
			return
		}
		if op != ws.OpText {
			continue
		}
		var f proto.Frame
		if json.Unmarshal(msg, &f) != nil {
			continue
		}
		switch f.T {
		case proto.THello:
			var h proto.Hello
			if json.Unmarshal(f.Data, &h) == nil {
				s.st.touch(func(d *data) {
					if x := d.Devices[dev.ID]; x != nil {
						x.Hello = &h
					}
				})
			}
		case proto.TStats:
			var st proto.Stats
			if json.Unmarshal(f.Data, &st) == nil {
				a.mu.Lock()
				a.Stats, a.StatsAt = &st, time.Now()
				a.mu.Unlock()
				s.hist.add(a.ID, st.CPU, st.MemUsed, st.MemTotal)
			}
		case proto.TResult:
			if j := s.hub.snapshot(f.ID); j != nil && j.DeviceID == a.ID {
				s.hub.finish(f.ID, f.Err, f.Data)
			}
		case proto.TProgress:
			if j := s.hub.snapshot(f.ID); j != nil && j.DeviceID == a.ID {
				s.hub.progress(f.ID, f.Msg)
			}
		case proto.TOpenFail:
			s.hub.refuse(f.SID, f.Err)
		}
	}
}

func (s *Server) handleAgentChan(w http.ResponseWriter, r *http.Request) {
	dev, ok := s.authAgent(w, r)
	if !ok {
		return
	}
	ch, ok := s.hub.claimChannel(r.PathValue("sid"), dev.ID)
	if !ok {
		writeErr(w, 404, "no such channel")
		return
	}
	c, err := ws.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	c.SetReadLimit(16 << 20)
	c.SetIdleTimeout(5 * time.Minute)
	c.KeepAlive(25 * time.Second)
	ch <- c
}

var (
	reDir  = regexp.MustCompile(`^[a-z0-9_-]{1,40}$`)
	reFile = regexp.MustCompile(`^[A-Za-z0-9._-]{1,120}$`)
)

type releaseFile struct {
	Version string `json:"version"`
	File    string `json:"file"`
	SHA256  string `json:"sha256"`
	Sig     string `json:"sig"`
}

func (s *Server) readRelease(dir string) (releaseFile, bool) {
	var rf releaseFile
	b, err := os.ReadFile(filepath.Join(s.cfg.DataDir, "releases", dir, "latest.json"))
	if err != nil || json.Unmarshal(b, &rf) != nil || !reFile.MatchString(rf.File) {
		return rf, false
	}
	return rf, true
}

func (s *Server) listReleases() map[string]string {
	out := map[string]string{}
	ents, _ := os.ReadDir(filepath.Join(s.cfg.DataDir, "releases"))
	for _, e := range ents {
		if e.IsDir() && reDir.MatchString(e.Name()) {
			if rf, ok := s.readRelease(e.Name()); ok {
				out[e.Name()] = rf.Version
			}
		}
	}
	return out
}

func (s *Server) handleAgentUpdate(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.authAgent(w, r); !ok {
		return
	}
	goos, arch := r.URL.Query().Get("os"), r.URL.Query().Get("arch")
	dir := goos + "-" + arch
	if !reDir.MatchString(dir) {
		writeErr(w, 400, "bad platform")
		return
	}
	rf, ok := s.readRelease(dir)
	if !ok || !semverNewer(rf.Version, r.URL.Query().Get("cur")) {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	writeJSON(w, 200, proto.UpdateInfo{Version: rf.Version, URL: "/dl/releases/" + dir + "/" + rf.File,
		SHA256: rf.SHA256, Sig: rf.Sig})
}

func (s *Server) handleDownloadRelease(w http.ResponseWriter, r *http.Request) {
	dir, file := r.PathValue("dir"), r.PathValue("file")
	if !reDir.MatchString(dir) || !reFile.MatchString(file) || file == "latest.json" {
		http.NotFound(w, r)
		return
	}
	http.ServeFile(w, r, filepath.Join(s.cfg.DataDir, "releases", dir, file))
}

func (s *Server) handleDownloadDist(w http.ResponseWriter, r *http.Request) {
	file := r.PathValue("file")
	if !reFile.MatchString(file) {
		http.NotFound(w, r)
		return
	}
	http.ServeFile(w, r, filepath.Join(s.cfg.DataDir, "dist", file))
}

// semverNewer reports whether a is a strictly newer dotted version than b.
func semverNewer(a, b string) bool {
	pa, pb := parseVer(a), parseVer(b)
	for i := 0; i < 3; i++ {
		if pa[i] != pb[i] {
			return pa[i] > pb[i]
		}
	}
	return false
}

func parseVer(v string) [3]int {
	var out [3]int
	v = strings.TrimPrefix(strings.TrimSpace(v), "v")
	if i := strings.IndexAny(v, "-+"); i >= 0 {
		v = v[:i]
	}
	for i, p := range strings.SplitN(v, ".", 3) {
		out[i], _ = strconv.Atoi(p)
	}
	return out
}

// handleAuthConfig tells the login page whether to ask for an authenticator code.
func (s *Server) handleAuthConfig(w http.ResponseWriter, r *http.Request) {
	adm := s.st.admin()
	writeJSON(w, 200, map[string]bool{"totp": adm == nil || adm.TOTPSecret != ""})
}
