package server

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"helm/internal/proto"
)

// ---- target resolution ----

func (s *Server) resolveTarget(t Target) []Device {
	var out []Device
	want := map[string]bool{}
	for _, id := range t.Devices {
		want[id] = true
	}
	for _, d := range s.st.devices() {
		if !d.Approved {
			continue
		}
		switch {
		case t.All:
		case t.Group != "" && d.Group == t.Group:
		case t.Tag != "" && containsStr(d.Tags, strings.ToLower(t.Tag)):
		case want[d.ID]:
		default:
			continue
		}
		out = append(out, d)
	}
	sort.Slice(out, func(i, j int) bool { return strings.ToLower(out[i].Name) < strings.ToLower(out[j].Name) })
	return out
}

func containsStr(a []string, x string) bool {
	for _, v := range a {
		if v == x {
			return true
		}
	}
	return false
}

func validTarget(t Target) bool { return t.All || t.Group != "" || t.Tag != "" || len(t.Devices) > 0 }

// ---- runs ----

// runSpec describes what to do on each device.
type runSpec struct {
	Kind, Title, ScheduleID, Trigger string
	Cmd                              string
	Args                             json.RawMessage
	Scan                             bool // use the scan pipeline instead of a single command
}

func (s *Server) newRun(spec runSpec, devs []Device) *Run {
	run := &Run{ID: randHex(6), Kind: spec.Kind, Title: spec.Title, ScheduleID: spec.ScheduleID, Trigger: spec.Trigger,
		Started: time.Now().UTC(), Status: "running", Results: []RunResult{}}
	for _, d := range devs {
		run.Results = append(run.Results, RunResult{DeviceID: d.ID, Name: d.Name, Status: "running"})
	}
	// The stored Run is mutated by worker goroutines; hand callers an independent snapshot.
	snap := run.clone()
	s.db.addRun(run)
	return &snap
}

func (s *Server) setResult(runID string, idx int, rr RunResult) {
	s.db.update(func(d *dbData) {
		for _, r := range d.Runs {
			if r.ID != runID || idx >= len(r.Results) {
				continue
			}
			r.Results[idx] = rr
			done := true
			for _, x := range r.Results {
				if x.Status == "running" {
					done = false
				}
			}
			if done {
				r.Status, r.Finished = "done", time.Now().UTC()
			}
		}
	})
}

// execRun runs the spec on every device with limited parallelism.
func (s *Server) execRun(run *Run, devs []Device, spec runSpec, actor string) {
	if len(devs) == 0 {
		s.db.update(func(d *dbData) {
			for _, r := range d.Runs {
				if r.ID == run.ID {
					r.Status, r.Finished = "done", time.Now().UTC()
				}
			}
		})
		return
	}
	sem := make(chan struct{}, 8)
	var wg sync.WaitGroup
	for i, d := range devs {
		wg.Add(1)
		sem <- struct{}{}
		go func(i int, d Device) {
			defer wg.Done()
			defer func() { <-sem }()
			rr := RunResult{DeviceID: d.ID, Name: d.Name, Status: "ok"}
			if s.hub.online(d.ID) == nil {
				rr.Status, rr.Err = "skipped", "PC was offline"
				s.setResult(run.ID, i, rr)
				return
			}
			if spec.Scan {
				if err := s.startScan(d.ID, actor); err != nil {
					rr.Status, rr.Err = "error", err.Error()
				} else {
					rr.Output = "scan started"
				}
				s.setResult(run.ID, i, rr)
				return
			}
			raw, err := s.callCmd(d.ID, spec.Cmd, spec.Args, actor)
			if err != nil {
				rr.Status, rr.Err = "error", err.Error()
			} else {
				rr.Output, rr.ExitCode = summarize(spec.Cmd, raw)
				if rr.ExitCode != nil && *rr.ExitCode != 0 {
					rr.Status = "error"
					rr.Err = fmt.Sprintf("exit code %d", *rr.ExitCode)
				}
			}
			s.setResult(run.ID, i, rr)
		}(i, d)
	}
	wg.Wait()
}

func summarize(cmd string, raw json.RawMessage) (string, *int) {
	if cmd == "exec" {
		var r proto.ExecResult
		if json.Unmarshal(raw, &r) == nil {
			out := r.Stdout
			if r.Stderr != "" {
				out += "\n" + r.Stderr
			}
			if len(out) > 8000 {
				out = out[:8000] + "\n… (truncated)"
			}
			if r.TimedOut {
				out += "\n(timed out)"
			}
			code := r.ExitCode
			return strings.TrimSpace(out), &code
		}
	}
	t := string(raw)
	if len(t) > 4000 {
		t = t[:4000] + "…"
	}
	return t, nil
}

// ---- scripts ----

func (s *Server) handleScripts(w http.ResponseWriter, r *http.Request, sess *session) {
	out := []Script{}
	s.db.view(func(d *dbData) {
		for _, x := range d.Scripts {
			out = append(out, *x)
		}
	})
	sort.Slice(out, func(i, j int) bool { return strings.ToLower(out[i].Name) < strings.ToLower(out[j].Name) })
	writeJSON(w, 200, out)
}

func (s *Server) handleScriptSave(w http.ResponseWriter, r *http.Request, sess *session) {
	var req Script
	if !readJSON(w, r, &req) {
		return
	}
	req.Name = strings.TrimSpace(req.Name)
	if req.Name == "" || len(req.Name) > 80 || len(req.Desc) > 300 || strings.TrimSpace(req.Body) == "" || len(req.Body) > 200000 {
		writeErr(w, 400, "a name (up to 80 characters) and a script body are required")
		return
	}
	if req.Shell != "cmd" {
		req.Shell = "powershell"
	}
	if req.Timeout < 5 || req.Timeout > 10800 {
		req.Timeout = 120
	}
	id := r.PathValue("id")
	var saved Script
	s.db.update(func(d *dbData) {
		now := time.Now().UTC()
		x := d.Scripts[id]
		if id == "" || x == nil {
			x = &Script{ID: randHex(6), CreatedAt: now}
			d.Scripts[x.ID] = x
		}
		x.Name, x.Desc, x.Shell, x.Body, x.Timeout, x.UpdatedAt = req.Name, req.Desc, req.Shell, req.Body, req.Timeout, now
		saved = *x
	})
	s.record(r, "script_saved", "", saved.Name)
	writeJSON(w, 200, saved)
}

func (s *Server) handleScriptDelete(w http.ResponseWriter, r *http.Request, sess *session) {
	id := r.PathValue("id")
	s.db.update(func(d *dbData) {
		delete(d.Scripts, id)
		for sid, sc := range d.Schedules { // a schedule without its script would only fail
			if sc.ScriptID == id {
				delete(d.Schedules, sid)
			}
		}
	})
	writeJSON(w, 200, map[string]bool{"ok": true})
}

func (s *Server) scriptByID(id string) (Script, bool) {
	var sc Script
	ok := false
	s.db.view(func(d *dbData) {
		if x := d.Scripts[id]; x != nil {
			sc, ok = *x, true
		}
	})
	return sc, ok
}

// ---- running things on targets ----

func (s *Server) handleRunScript(w http.ResponseWriter, r *http.Request, sess *session) {
	if !s.needStepUp(w, sess) {
		return
	}
	var req struct {
		ScriptID string `json:"scriptId"`
		Body     string `json:"body"`
		Shell    string `json:"shell"`
		Timeout  int    `json:"timeout"`
		Target   Target `json:"target"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	title := "Ad-hoc script"
	if req.ScriptID != "" {
		sc, ok := s.scriptByID(req.ScriptID)
		if !ok {
			writeErr(w, 404, "no such script")
			return
		}
		req.Body, req.Shell, req.Timeout, title = sc.Body, sc.Shell, sc.Timeout, sc.Name
	}
	if strings.TrimSpace(req.Body) == "" || len(req.Body) > 200000 || !validTarget(req.Target) {
		writeErr(w, 400, "a script and a target are required")
		return
	}
	if req.Shell != "cmd" {
		req.Shell = "powershell"
	}
	if req.Timeout < 5 || req.Timeout > 10800 {
		req.Timeout = 120
	}
	devs := s.resolveTarget(req.Target)
	if len(devs) == 0 {
		writeErr(w, 400, "no approved PCs match that target")
		return
	}
	args, _ := json.Marshal(proto.ExecArgs{Script: req.Body, Shell: req.Shell, Timeout: req.Timeout})
	spec := runSpec{Kind: "script", Title: title, Trigger: "manual", Cmd: "exec", Args: args}
	run := s.newRun(spec, devs)
	s.record(r, "script_run", "", fmt.Sprintf("%s on %d PC(s)", title, len(devs)))
	go s.execRun(run, devs, spec, "admin")
	writeJSON(w, 200, run)
}

func (s *Server) handleRunScan(w http.ResponseWriter, r *http.Request, sess *session) {
	var req struct {
		Target Target `json:"target"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	if !validTarget(req.Target) {
		writeErr(w, 400, "choose what to scan")
		return
	}
	devs := s.resolveTarget(req.Target)
	if len(devs) == 0 {
		writeErr(w, 400, "no approved PCs match that target")
		return
	}
	spec := runSpec{Kind: "scan", Title: "Security scan", Trigger: "manual", Scan: true}
	run := s.newRun(spec, devs)
	s.record(r, "scan_run", "", fmt.Sprintf("%d PC(s)", len(devs)))
	go s.execRun(run, devs, spec, "admin")
	writeJSON(w, 200, run)
}

func (s *Server) handleRuns(w http.ResponseWriter, r *http.Request, sess *session) {
	out := []Run{}
	s.db.view(func(d *dbData) {
		for i := len(d.Runs) - 1; i >= 0 && len(out) < 100; i-- {
			out = append(out, d.Runs[i].clone())
		}
	})
	writeJSON(w, 200, out)
}

func (s *Server) handleRun(w http.ResponseWriter, r *http.Request, sess *session) {
	id := r.PathValue("id")
	var out *Run
	s.db.view(func(d *dbData) {
		for _, x := range d.Runs {
			if x.ID == id {
				cp := x.clone()
				out = &cp
			}
		}
	})
	if out == nil {
		writeErr(w, 404, "no such run")
		return
	}
	writeJSON(w, 200, out)
}

// ---- schedules ----

var reHHMM = regexp.MustCompile(`^([01]\d|2[0-3]):[0-5]\d$`)

func nextRun(sc *Schedule, from time.Time) time.Time {
	switch sc.Kind {
	case "interval":
		if sc.Every < 5 {
			sc.Every = 5
		}
		return from.Add(time.Duration(sc.Every) * time.Minute)
	case "daily", "weekly":
		var h, m int
		fmt.Sscanf(sc.At, "%d:%d", &h, &m)
		loc := from.Location()
		for add := 0; add < 8; add++ {
			c := time.Date(from.Year(), from.Month(), from.Day()+add, h, m, 0, 0, loc)
			if !c.After(from) {
				continue
			}
			if sc.Kind == "weekly" && !containsInt(sc.Days, int(c.Weekday())) {
				continue
			}
			return c
		}
	}
	return from.Add(24 * time.Hour)
}

func containsInt(a []int, x int) bool {
	for _, v := range a {
		if v == x {
			return true
		}
	}
	return false
}

func (s *Server) handleSchedules(w http.ResponseWriter, r *http.Request, sess *session) {
	out := []Schedule{}
	s.db.view(func(d *dbData) {
		for _, x := range d.Schedules {
			out = append(out, *x)
		}
	})
	sort.Slice(out, func(i, j int) bool { return out[i].Created.Before(out[j].Created) })
	writeJSON(w, 200, out)
}

func (s *Server) handleScheduleSave(w http.ResponseWriter, r *http.Request, sess *session) {
	if !s.needStepUp(w, sess) {
		return
	}
	var req Schedule
	if !readJSON(w, r, &req) {
		return
	}
	req.Name = strings.TrimSpace(req.Name)
	if req.Name == "" || len(req.Name) > 80 || !validTarget(req.Target) {
		writeErr(w, 400, "a name and a target are required")
		return
	}
	switch req.Action {
	case "script":
		if _, ok := s.scriptByID(req.ScriptID); !ok {
			writeErr(w, 400, "choose a script from the library")
			return
		}
	case "scan", "updates.install", "winget.upgrade_all", "restart":
	default:
		writeErr(w, 400, "unknown action")
		return
	}
	switch req.Kind {
	case "interval":
		if req.Every < 5 || req.Every > 60*24*30 {
			writeErr(w, 400, "interval must be between 5 minutes and 30 days")
			return
		}
	case "daily", "weekly":
		if !reHHMM.MatchString(req.At) {
			writeErr(w, 400, "time must look like 03:30")
			return
		}
		if req.Kind == "weekly" && len(req.Days) == 0 {
			writeErr(w, 400, "pick at least one weekday")
			return
		}
	default:
		writeErr(w, 400, "unknown schedule type")
		return
	}
	id := r.PathValue("id")
	var saved Schedule
	s.db.update(func(d *dbData) {
		x := d.Schedules[id]
		if id == "" || x == nil {
			x = &Schedule{ID: randHex(6), Created: time.Now().UTC()}
			d.Schedules[x.ID] = x
		}
		x.Name, x.Action, x.ScriptID, x.Target, x.Kind, x.Every, x.At, x.Days, x.Enabled = req.Name, req.Action, req.ScriptID, req.Target, req.Kind, req.Every, req.At, req.Days, req.Enabled
		x.NextRun = nextRun(x, time.Now())
		saved = *x
	})
	s.record(r, "schedule_saved", "", saved.Name)
	writeJSON(w, 200, saved)
}

func (s *Server) handleScheduleDelete(w http.ResponseWriter, r *http.Request, sess *session) {
	s.db.update(func(d *dbData) { delete(d.Schedules, r.PathValue("id")) })
	writeJSON(w, 200, map[string]bool{"ok": true})
}

func (s *Server) handleScheduleRunNow(w http.ResponseWriter, r *http.Request, sess *session) {
	if !s.needStepUp(w, sess) {
		return
	}
	var sc Schedule
	found := false
	s.db.view(func(d *dbData) {
		if x := d.Schedules[r.PathValue("id")]; x != nil {
			sc, found = *x, true
		}
	})
	if !found {
		writeErr(w, 404, "no such schedule")
		return
	}
	run, err := s.fireSchedule(&sc, "manual")
	if err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	writeJSON(w, 200, run)
}

func (s *Server) fireSchedule(sc *Schedule, trigger string) (*Run, error) {
	devs := s.resolveTarget(sc.Target)
	spec := runSpec{Title: sc.Name, ScheduleID: sc.ID, Trigger: trigger}
	switch sc.Action {
	case "script":
		scr, ok := s.scriptByID(sc.ScriptID)
		if !ok {
			return nil, errors.New("the script was deleted")
		}
		args, _ := json.Marshal(proto.ExecArgs{Script: scr.Body, Shell: scr.Shell, Timeout: scr.Timeout})
		spec.Kind, spec.Cmd, spec.Args = "script", "exec", args
	case "scan":
		spec.Kind, spec.Scan = "scan", true
	case "updates.install":
		spec.Kind, spec.Cmd, spec.Args = "update", "updates.install", json.RawMessage(`{"ids":[],"reboot":false}`)
	case "winget.upgrade_all":
		spec.Kind, spec.Cmd, spec.Args = "update", "winget.upgrade", json.RawMessage(`{"all":true}`)
	case "restart":
		spec.Kind, spec.Cmd, spec.Args = "power", "power", json.RawMessage(`{"action":"restart","delay":60,"message":"Scheduled restart by your administrator","force":false}`)
	}
	run := s.newRun(spec, devs)
	go s.execRun(run, devs, spec, "schedule:"+sc.Name)
	return run, nil
}

func (s *Server) runDueSchedules() {
	now := time.Now()
	var due []Schedule
	s.db.update(func(d *dbData) {
		for _, sc := range d.Schedules {
			if sc.Enabled && !sc.NextRun.IsZero() && !sc.NextRun.After(now) {
				// If the server was down for a long time, run once and move on instead of catching up.
				sc.LastRun = now.UTC()
				sc.NextRun = nextRun(sc, now)
				due = append(due, *sc)
			}
		}
	})
	for i := range due {
		if _, err := s.fireSchedule(&due[i], "schedule"); err != nil {
			s.log.Printf("schedule %q: %v", due[i].Name, err)
		}
	}
}

func (s *Server) autoScan() {
	set := s.db.settings()
	if !set.AutoScan {
		return
	}
	every := time.Duration(set.ScanEveryHours) * time.Hour
	online := s.hub.onlineIDs()
	for _, d := range s.st.devices() {
		if !d.Approved || online[d.ID] == nil {
			continue
		}
		var at time.Time
		s.db.view(func(x *dbData) {
			if sc := x.Scans[d.ID]; sc != nil {
				at = sc.At
			}
		})
		if time.Since(at) > every {
			_ = s.startScan(d.ID, "auto-scan")
		}
	}
}

// ---- software packages and deployment ----

var reWinget = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+-]{0,100}$`)
var reArgs = regexp.MustCompile(`^[A-Za-z0-9 /\-_=.,:"]{0,200}$`)

func (s *Server) pkgDir() string { return filepath.Join(s.cfg.DataDir, "packages") }

func (s *Server) handlePackages(w http.ResponseWriter, r *http.Request, sess *session) {
	out := []Package{}
	s.db.view(func(d *dbData) {
		for _, p := range d.Packages {
			out = append(out, *p)
		}
	})
	sort.Slice(out, func(i, j int) bool { return strings.ToLower(out[i].Name) < strings.ToLower(out[j].Name) })
	writeJSON(w, 200, out)
}

func (s *Server) handlePackageAdd(w http.ResponseWriter, r *http.Request, sess *session) {
	var req Package
	if !readJSON(w, r, &req) {
		return
	}
	req.Name, req.WingetID = strings.TrimSpace(req.Name), strings.TrimSpace(req.WingetID)
	if req.OS == "linux" {
		if req.Name == "" || len(req.Name) > 80 || !reAptName.MatchString(req.WingetID) {
			writeErr(w, 400, "a name and a valid apt package name (like htop) are required")
			return
		}
		p := &Package{ID: randHex(6), Name: req.Name, Type: "apt", OS: "linux", WingetID: req.WingetID, CreatedAt: time.Now().UTC()}
		s.db.update(func(d *dbData) { d.Packages[p.ID] = p })
		s.record(r, "package_added", "", p.Name)
		writeJSON(w, 200, p)
		return
	}
	if req.Name == "" || len(req.Name) > 80 || !reWinget.MatchString(req.WingetID) {
		writeErr(w, 400, "a name and a valid winget package id (like Mozilla.Firefox) are required")
		return
	}
	p := &Package{ID: randHex(6), Name: req.Name, Type: "winget", WingetID: req.WingetID, Version: strings.TrimSpace(req.Version), CreatedAt: time.Now().UTC()}
	if len(p.Version) > 40 || strings.ContainsAny(p.Version, " \"'`$;&|<>") {
		writeErr(w, 400, "bad version")
		return
	}
	s.db.update(func(d *dbData) { d.Packages[p.ID] = p })
	s.record(r, "package_added", "", p.Name)
	writeJSON(w, 200, p)
}

func (s *Server) handlePackageUpload(w http.ResponseWriter, r *http.Request, sess *session) {
	if !s.needStepUp(w, sess) {
		return
	}
	q := r.URL.Query()
	name, fn, args := strings.TrimSpace(q.Get("name")), q.Get("filename"), q.Get("args")
	ext := strings.ToLower(filepath.Ext(fn))
	if name == "" || len(name) > 80 || (ext != ".msi" && ext != ".exe" && ext != ".deb" && ext != ".pkg") || !regexp.MustCompile(`^[A-Za-z0-9._ -]{1,100}$`).MatchString(fn) || !reArgs.MatchString(args) {
		writeErr(w, 400, "a name, an .msi, .exe, .deb or .pkg filename, and simple silent-install arguments are required")
		return
	}
	if r.ContentLength > 1<<30 {
		writeErr(w, 413, "installer too large (max 1 GB)")
		return
	}
	if err := os.MkdirAll(s.pkgDir(), 0o700); err != nil {
		writeErr(w, 500, "cannot create package folder")
		return
	}
	id := randHex(6)
	path := filepath.Join(s.pkgDir(), id)
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0o600)
	if err != nil {
		writeErr(w, 500, "cannot store file")
		return
	}
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(f, h), http.MaxBytesReader(w, r.Body, 1<<30))
	f.Close()
	if err != nil || n == 0 {
		os.Remove(path)
		writeErr(w, 400, "upload failed")
		return
	}
	p := &Package{ID: id, Name: name, Type: "upload", Filename: fn, Kind: strings.TrimPrefix(ext, "."), OS: map[string]string{".deb": "linux", ".pkg": "darwin"}[ext], SHA256: hex.EncodeToString(h.Sum(nil)),
		Size: n, Args: args, CreatedAt: time.Now().UTC()}
	s.db.update(func(d *dbData) { d.Packages[id] = p })
	s.record(r, "package_uploaded", "", fmt.Sprintf("%s (%s, %d bytes)", name, fn, n))
	writeJSON(w, 200, p)
}

func (s *Server) handlePackageDelete(w http.ResponseWriter, r *http.Request, sess *session) {
	id := r.PathValue("id")
	if !regexp.MustCompile(`^[0-9a-f]{12}$`).MatchString(id) {
		writeErr(w, 400, "bad id")
		return
	}
	s.db.update(func(d *dbData) { delete(d.Packages, id) })
	os.Remove(filepath.Join(s.pkgDir(), id))
	writeJSON(w, 200, map[string]bool{"ok": true})
}

// handleAgentPackage serves an uploaded installer to an authenticated agent.
func (s *Server) handleAgentPackage(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.authAgent(w, r); !ok {
		return
	}
	id := r.PathValue("id")
	known := false
	s.db.view(func(d *dbData) { _, known = d.Packages[id] })
	if !known || !regexp.MustCompile(`^[0-9a-f]{12}$`).MatchString(id) {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	http.ServeFile(w, r, filepath.Join(s.pkgDir(), id))
}

func (s *Server) handleDeploy(w http.ResponseWriter, r *http.Request, sess *session) {
	var req struct {
		PackageID string `json:"packageId"`
		Action    string `json:"action"` // install | uninstall
		Target    Target `json:"target"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	var p Package
	found := false
	s.db.view(func(d *dbData) {
		if x := d.Packages[req.PackageID]; x != nil {
			p, found = *x, true
		}
	})
	if !found || !validTarget(req.Target) {
		writeErr(w, 400, "choose a package and a target")
		return
	}
	spec := runSpec{Kind: "deploy", Trigger: "manual"}
	switch {
	case p.Type == "apt" && req.Action == "uninstall":
		spec.Title, spec.Cmd = "Remove "+p.Name, "winget.uninstall"
		spec.Args, _ = json.Marshal(map[string]string{"id": p.WingetID})
	case p.Type == "apt":
		spec.Title, spec.Cmd = "Install "+p.Name, "winget.install"
		spec.Args, _ = json.Marshal(map[string]string{"id": p.WingetID})
	case p.Type == "winget" && req.Action == "uninstall":
		spec.Title, spec.Cmd = "Uninstall "+p.Name, "winget.uninstall"
		spec.Args, _ = json.Marshal(map[string]string{"id": p.WingetID})
	case p.Type == "winget":
		spec.Title, spec.Cmd = "Install "+p.Name, "winget.install"
		spec.Args, _ = json.Marshal(map[string]string{"id": p.WingetID, "version": p.Version})
	case req.Action == "uninstall":
		writeErr(w, 400, "uploaded installers can only be installed; use a winget package to uninstall")
		return
	default:
		spec.Title, spec.Cmd = "Install "+p.Name, "pkg.install"
		spec.Args, _ = json.Marshal(map[string]string{"path": "/api/agent/package/" + p.ID, "sha256": p.SHA256, "filename": p.Filename, "kind": p.Kind, "args": p.Args})
	}
	devs := filterOS(s.resolveTarget(req.Target), p.OS)
	if len(devs) == 0 {
		writeErr(w, 400, "no approved "+map[string]string{"linux": "Linux machines", "darwin": "Macs", "": "Windows PCs"}[p.OS]+" match that target")
		return
	}
	run := s.newRun(spec, devs)
	s.record(r, "deploy", "", fmt.Sprintf("%s on %d PC(s)", spec.Title, len(devs)))
	go s.execRun(run, devs, spec, "admin")
	writeJSON(w, 200, run)
}

var reAptName = regexp.MustCompile(`^[a-z0-9][a-z0-9+.:-]{0,100}$`)

// filterOS keeps only the machines of one platform: "linux", "darwin", or "" for Windows. A device that has
// not reported its OS yet is treated as Windows, the original platform.
func filterOS(devs []Device, os string) []Device {
	var out []Device
	for _, d := range devs {
		have := ""
		if d.Hello != nil && (d.Hello.OS == "linux" || d.Hello.OS == "darwin") {
			have = d.Hello.OS
		}
		if have == os {
			out = append(out, d)
		}
	}
	return out
}

// clone returns a copy that shares no slices with the stored run, which worker goroutines keep updating.
func (r *Run) clone() Run {
	c := *r
	c.Results = append([]RunResult(nil), r.Results...)
	return c
}
