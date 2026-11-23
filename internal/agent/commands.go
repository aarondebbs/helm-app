package agent

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"

	"helm/internal/proto"
)

type cmdCtx struct {
	a        *Agent
	id       string
	args     json.RawMessage
	progress func(string)
	pct      func(int, string) // progress with a percentage (0-100)
}

type handlerFn func(ctx context.Context, c *cmdCtx) (any, error)

func decode(args json.RawMessage, v any) error {
	if len(args) == 0 {
		return nil
	}
	if err := json.Unmarshal(args, v); err != nil {
		return errors.New("bad arguments: " + err.Error())
	}
	return nil
}

func (a *Agent) handlers() map[string]handlerFn {
	m := a.baseHandlers()
	defer func() {}()
	for k, v := range a.scanHandlers() {
		m[k] = v
	}
	for k, v := range a.deployHandlers() {
		m[k] = v
	}
	if realLinux() {
		a.linuxHandlers(m)
	}
	if realMac() {
		a.macHandlers(m)
	}
	return m
}

func (a *Agent) baseHandlers() map[string]handlerFn {
	return map[string]handlerFn{
		"ping": func(ctx context.Context, c *cmdCtx) (any, error) {
			return map[string]string{"pong": "ok", "version": a.cfg.Version}, nil
		},
		"inventory": func(ctx context.Context, c *cmdCtx) (any, error) {
			return a.psJSON(ctx, scriptInventory, nil, 2*time.Minute)
		},
		"software.list": func(ctx context.Context, c *cmdCtx) (any, error) {
			return a.psJSON(ctx, scriptSoftware, nil, 2*time.Minute)
		},
		"process.list": func(ctx context.Context, c *cmdCtx) (any, error) {
			return a.psJSON(ctx, scriptProcesses, nil, time.Minute)
		},
		"service.list": func(ctx context.Context, c *cmdCtx) (any, error) {
			return a.psJSON(ctx, scriptServices, nil, time.Minute)
		},
		"process.kill":    a.cmdProcessKill,
		"service.control": a.cmdServiceControl,
		"eventlog":        a.cmdEventLog,
		"file.list":       a.cmdFileList,
		"file.mkdir":      a.cmdFileMkdir,
		"file.delete":     a.cmdFileDelete,
		"file.rename":     a.cmdFileRename,
		"drives.list": func(ctx context.Context, c *cmdCtx) (any, error) {
			return listDrives(), nil
		},
		"updates.check":   a.cmdUpdatesCheck,
		"updates.install": a.cmdUpdatesInstall,
		"fix.apply":       a.cmdFixApply,
		"winget.list":     a.cmdWingetList,
		"winget.upgrade":  a.cmdWingetUpgrade,
		"power":           a.cmdPower,
		"msg":             a.cmdMsg,
		"wol":             a.cmdWOL,
		"exec":            a.cmdExec,
		"rdp.status": func(ctx context.Context, c *cmdCtx) (any, error) {
			return a.psJSON(ctx, scriptRDPStatus, nil, time.Minute)
		},
		"rdp.enable":      func(ctx context.Context, c *cmdCtx) (any, error) { return a.rdpSet(ctx, true) },
		"rdp.disable":     func(ctx context.Context, c *cmdCtx) (any, error) { return a.rdpSet(ctx, false) },
		"agent.update":    a.cmdAgentUpdate,
		"agent.uninstall": a.cmdAgentUninstall,
	}
}

// runCommand executes a server command asynchronously and reports the result.
func (a *Agent) runCommand(ctx context.Context, f proto.Frame) {
	h := a.handlers()[f.Name]
	reply := func(data any, err error) {
		r := proto.Frame{T: proto.TResult, ID: f.ID}
		if err != nil {
			r.Err = err.Error()
		} else if data != nil {
			if raw, ok := data.(json.RawMessage); ok {
				r.Data = raw
			} else {
				r.Data = mustJSON(data)
			}
		}
		a.sendFrame(r)
	}
	if h == nil {
		reply(nil, fmt.Errorf("unknown command %q", f.Name))
		return
	}
	select {
	case a.cmdSem <- struct{}{}:
	default:
		reply(nil, errors.New("agent is busy with too many commands"))
		return
	}
	go func() {
		defer func() { <-a.cmdSem }()
		defer func() {
			if r := recover(); r != nil {
				a.log.Printf("panic in command %s: %v", f.Name, r)
				reply(nil, fmt.Errorf("internal error: %v", r))
			}
		}()
		c := &cmdCtx{a: a, id: f.ID, args: f.Args, progress: func(m string) {
			a.sendFrame(proto.Frame{T: proto.TProgress, ID: f.ID, Msg: m})
		}, pct: func(p int, m string) {
			a.sendFrame(proto.Frame{T: proto.TProgress, ID: f.ID, Msg: m, Pct: p})
		}}
		data, err := h(ctx, c)
		reply(data, err)
	}()
}

// ---- script running ----

type scriptOpts struct {
	shell    string // powershell | cmd
	script   string
	env      map[string]string
	timeout  time.Duration
	onLine   func(string)
	internal bool // one of the built-in scripts (may use development fixtures)
}

type scriptResult struct {
	Stdout   string
	Stderr   string
	ExitCode int
	TimedOut bool
}

const (
	maxStdout = 1 << 20
	maxStderr = 256 << 10
)

type capBuf struct {
	b   bytes.Buffer
	max int
}

func (c *capBuf) Write(p []byte) (int, error) {
	if room := c.max - c.b.Len(); room > 0 {
		if len(p) > room {
			c.b.Write(p[:room])
		} else {
			c.b.Write(p)
		}
	}
	return len(p), nil
}

func (a *Agent) tmpDir() (string, error) {
	d := filepath.Join(a.cfg.DataDir, "tmp")
	if err := os.MkdirAll(d, 0o700); err != nil {
		return "", err
	}
	securePath(a.cfg.DataDir)
	return d, nil
}

func (a *Agent) runScript(ctx context.Context, o scriptOpts) (scriptResult, error) {
	if o.internal {
		if out, ok := fixtureFor(o.script); ok {
			if o.onLine != nil {
				for _, ln := range strings.Split(out, "\n") {
					o.onLine(ln)
				}
			}
			return scriptResult{Stdout: out}, nil
		}
	}
	if o.timeout <= 0 {
		o.timeout = time.Minute
	}
	dir, err := a.tmpDir()
	if err != nil {
		return scriptResult{}, err
	}
	var content []byte
	ext := ".ps1"
	switch o.shell {
	case "cmd":
		ext = ".cmd"
		content = []byte("@echo off\r\nchcp 65001 >nul\r\n" + strings.ReplaceAll(strings.ReplaceAll(o.script, "\r\n", "\n"), "\n", "\r\n") + "\r\n")
	default:
		if runtime.GOOS == "windows" {
			content = append([]byte{0xEF, 0xBB, 0xBF}, []byte(psHeader+o.script)...) // BOM so PowerShell 5.1 reads UTF-8
		} else {
			content = []byte(o.script) // development stand-in: run through sh
		}
	}
	path := filepath.Join(dir, "s-"+strconv.FormatInt(time.Now().UnixNano(), 36)+ext)
	if err := os.WriteFile(path, content, 0o600); err != nil {
		return scriptResult{}, err
	}
	defer os.Remove(path)

	cctx, cancel := context.WithTimeout(ctx, o.timeout)
	defer cancel()
	cmd := shellCommand(cctx, o.shell, path)
	cmd.Env = os.Environ()
	for k, v := range o.env {
		cmd.Env = append(cmd.Env, k+"="+v)
	}
	hideWindow(cmd)
	cmd.Cancel = func() error { killTree(cmd.Process.Pid); return nil }
	cmd.WaitDelay = 5 * time.Second
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return scriptResult{}, err
	}
	stderr := &capBuf{max: maxStderr}
	cmd.Stderr = stderr
	if err := cmd.Start(); err != nil {
		return scriptResult{}, err
	}
	var out capBuf
	out.max = maxStdout
	sc := bufio.NewScanner(stdout)
	sc.Buffer(make([]byte, 64<<10), maxStdout)
	for sc.Scan() {
		ln := sc.Text()
		out.Write([]byte(ln + "\n"))
		if o.onLine != nil {
			o.onLine(ln)
		}
	}
	_, _ = io.Copy(io.Discard, stdout)
	werr := cmd.Wait()
	res := scriptResult{Stdout: out.b.String(), Stderr: stderr.b.String()}
	if cctx.Err() == context.DeadlineExceeded {
		res.TimedOut = true
		res.ExitCode = -1
		return res, nil
	}
	if werr != nil {
		var ee *exec.ExitError
		if errors.As(werr, &ee) {
			res.ExitCode = ee.ExitCode()
			return res, nil
		}
		return res, werr
	}
	return res, nil
}

func firstLines(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) > n {
		s = s[:n] + "…"
	}
	return s
}

// psJSON runs a built-in PowerShell script that prints one JSON document.
func (a *Agent) psJSON(ctx context.Context, script string, env map[string]string, timeout time.Duration) (json.RawMessage, error) {
	res, err := a.runScript(ctx, scriptOpts{shell: "powershell", script: script, env: env, timeout: timeout, internal: true})
	if err != nil {
		return nil, err
	}
	if res.TimedOut {
		return nil, errors.New("timed out")
	}
	if res.ExitCode != 0 {
		return nil, errors.New(firstLines(res.Stderr+res.Stdout, 600))
	}
	out := bytes.TrimSpace(bytes.TrimPrefix([]byte(res.Stdout), []byte{0xEF, 0xBB, 0xBF}))
	if len(out) == 0 {
		return json.RawMessage("[]"), nil
	}
	if !json.Valid(out) {
		return nil, errors.New("unexpected output: " + firstLines(string(out), 300))
	}
	return json.RawMessage(out), nil
}

// ---- process / service / event log ----

func (a *Agent) cmdProcessKill(ctx context.Context, c *cmdCtx) (any, error) {
	var args struct {
		PID int `json:"pid"`
	}
	if err := decode(c.args, &args); err != nil {
		return nil, err
	}
	if args.PID <= 4 || args.PID == os.Getpid() {
		return nil, errors.New("refusing to kill that process")
	}
	p, err := os.FindProcess(args.PID)
	if err != nil {
		return nil, err
	}
	if err := p.Kill(); err != nil {
		return nil, err
	}
	return map[string]any{"killed": args.PID}, nil
}

var reServiceName = regexp.MustCompile(`^[A-Za-z0-9_.$ -]{1,256}$`)

func (a *Agent) cmdServiceControl(ctx context.Context, c *cmdCtx) (any, error) {
	var args struct{ Name, Action string }
	if err := decode(c.args, &args); err != nil {
		return nil, err
	}
	if !reServiceName.MatchString(args.Name) {
		return nil, errors.New("bad service name")
	}
	switch args.Action {
	case "start", "stop", "restart", "auto", "manual", "disable":
	default:
		return nil, errors.New("bad action")
	}
	return a.psJSON(ctx, scriptServiceControl, map[string]string{"HELM_A_NAME": args.Name, "HELM_A_ACTION": args.Action}, 2*time.Minute)
}

func (a *Agent) cmdEventLog(ctx context.Context, c *cmdCtx) (any, error) {
	args := struct {
		Log   string `json:"log"`
		Level string `json:"level"`
		Count int    `json:"count"`
	}{Log: "System", Level: "warnings", Count: 50}
	if err := decode(c.args, &args); err != nil {
		return nil, err
	}
	switch args.Log {
	case "System", "Application", "Security", "Setup":
	default:
		return nil, errors.New("log must be System, Application, Security or Setup")
	}
	switch args.Level {
	case "errors", "warnings", "all":
	default:
		return nil, errors.New("level must be errors, warnings or all")
	}
	if args.Count < 1 || args.Count > 300 {
		args.Count = 50
	}
	return a.psJSON(ctx, scriptEventLog, map[string]string{"HELM_A_LOG": args.Log, "HELM_A_LEVEL": args.Level,
		"HELM_A_COUNT": strconv.Itoa(args.Count)}, 90*time.Second)
}

// ---- updates ----

func (a *Agent) cmdUpdatesCheck(ctx context.Context, c *cmdCtx) (any, error) {
	return a.psJSON(ctx, scriptUpdatesCheck, nil, 15*time.Minute)
}

func (a *Agent) cmdUpdatesInstall(ctx context.Context, c *cmdCtx) (any, error) {
	var args struct {
		IDs    []string `json:"ids"`
		Reboot bool     `json:"reboot"`
	}
	if err := decode(c.args, &args); err != nil {
		return nil, err
	}
	reGUID := regexp.MustCompile(`^[0-9A-Fa-f-]{36}$`)
	for _, id := range args.IDs {
		if !reGUID.MatchString(id) {
			return nil, errors.New("bad update id")
		}
	}
	if !a.updMu.TryLock() {
		return nil, errors.New("another update operation is already running on this PC")
	}
	defer a.updMu.Unlock()
	var result json.RawMessage
	res, err := a.runScript(ctx, scriptOpts{shell: "powershell", script: scriptUpdatesInstall, internal: true,
		env: map[string]string{"HELM_A_IDS": strings.Join(args.IDs, ",")}, timeout: 3*time.Hour + 30*time.Minute,
		onLine: func(ln string) {
			switch {
			case strings.HasPrefix(ln, "PROGRESS:"):
				m := strings.TrimPrefix(ln, "PROGRESS:")
				if p, rest, ok := strings.Cut(m, ":"); ok {
					if n, err := strconv.Atoi(p); err == nil && n >= 0 && n <= 100 {
						c.pct(n, rest)
						return
					}
				}
				c.progress(m)
			case strings.HasPrefix(ln, "RESULT:"):
				result = json.RawMessage(strings.TrimPrefix(ln, "RESULT:"))
			}
		}})
	if err != nil {
		return nil, err
	}
	if res.TimedOut {
		return nil, errors.New("timed out while installing updates")
	}
	if res.ExitCode != 0 || result == nil || !json.Valid(result) {
		return nil, errors.New("update install failed: " + firstLines(res.Stderr+res.Stdout, 600))
	}
	var parsed struct {
		RebootRequired bool `json:"rebootRequired"`
	}
	_ = json.Unmarshal(result, &parsed)
	if args.Reboot && parsed.RebootRequired {
		c.progress("Restart required; restarting in 60 seconds")
		if err := powerAction(proto.PowerArgs{Action: "restart", Delay: 60, Message: "Helm: restarting to finish installing updates"}); err != nil {
			return nil, fmt.Errorf("updates installed but restart failed: %w", err)
		}
	}
	return result, nil
}

func (a *Agent) wingetPath() (string, error) {
	p := findWinget()
	if p == "" {
		if fx := wingetFixtureAvailable(); fx != "" {
			return fx, nil
		}
		return "", errors.New("winget is not installed on this PC (needs App Installer from the Microsoft Store)")
	}
	return p, nil
}

// runWinget runs winget.exe with args and returns the combined output.
func (a *Agent) runWinget(ctx context.Context, exe string, args []string, timeout time.Duration, onLine func(string)) (string, int, error) {
	if out, ok := wingetFixture(args); ok {
		return out, 0, nil
	}
	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	cmd := exec.CommandContext(cctx, exe, args...)
	hideWindow(cmd)
	cmd.Cancel = func() error { killTree(cmd.Process.Pid); return nil }
	cmd.WaitDelay = 5 * time.Second
	var out capBuf
	out.max = maxStdout
	if onLine != nil {
		pr, pw := io.Pipe()
		cmd.Stdout, cmd.Stderr = io.MultiWriter(&out, pw), io.MultiWriter(&out, pw)
		go func() {
			sc := bufio.NewScanner(pr)
			sc.Buffer(make([]byte, 64<<10), 1<<20)
			sc.Split(scanLinesOrCR)
			for sc.Scan() {
				if t := strings.TrimSpace(sc.Text()); t != "" {
					onLine(t)
				}
			}
			_, _ = io.Copy(io.Discard, pr)
		}()
		err := cmd.Run()
		_ = pw.Close()
		return out.b.String(), exitCode(err), nonExitErr(err)
	}
	cmd.Stdout, cmd.Stderr = &out, &out
	err := cmd.Run()
	return out.b.String(), exitCode(err), nonExitErr(err)
}

func scanLinesOrCR(data []byte, atEOF bool) (int, []byte, error) {
	if atEOF && len(data) == 0 {
		return 0, nil, nil
	}
	if i := bytes.IndexAny(data, "\r\n"); i >= 0 {
		return i + 1, data[:i], nil
	}
	if atEOF {
		return len(data), data, nil
	}
	return 0, nil, nil
}

func exitCode(err error) int {
	if err == nil {
		return 0
	}
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return ee.ExitCode()
	}
	return -1
}

func nonExitErr(err error) error {
	var ee *exec.ExitError
	if err != nil && !errors.As(err, &ee) {
		return err
	}
	return nil
}

func (a *Agent) cmdWingetList(ctx context.Context, c *cmdCtx) (any, error) {
	exe, err := a.wingetPath()
	if err != nil {
		return nil, err
	}
	if !a.updMu.TryLock() {
		return nil, errors.New("another update operation is already running on this PC")
	}
	defer a.updMu.Unlock()
	_, _, _ = a.runWinget(ctx, exe, []string{"source", "update", "--disable-interactivity"}, 2*time.Minute, nil)
	out, code, err := a.runWinget(ctx, exe, []string{"upgrade", "--accept-source-agreements", "--disable-interactivity"}, 4*time.Minute, nil)
	if err != nil {
		return nil, err
	}
	raw := firstLines(strings.Join(cleanWingetOutput(out), "\n"), 20000)
	pk := parseWingetUpgrade(out)
	if pk == nil {
		pk = []WingetPkg{}
	}
	return map[string]any{"packages": pk, "exitCode": code, "raw": raw}, nil
}

func (a *Agent) cmdWingetUpgrade(ctx context.Context, c *cmdCtx) (any, error) {
	var args struct {
		IDs []string `json:"ids"`
		All bool     `json:"all"`
	}
	if err := decode(c.args, &args); err != nil {
		return nil, err
	}
	if !args.All && len(args.IDs) == 0 {
		return nil, errors.New("nothing selected")
	}
	for _, id := range args.IDs {
		if !reWingetID.MatchString(id) {
			return nil, fmt.Errorf("bad package id %q", id)
		}
	}
	exe, err := a.wingetPath()
	if err != nil {
		return nil, err
	}
	if !a.updMu.TryLock() {
		return nil, errors.New("another update operation is already running on this PC")
	}
	defer a.updMu.Unlock()
	common := []string{"--silent", "--accept-source-agreements", "--accept-package-agreements", "--disable-interactivity"}
	type item struct {
		ID       string `json:"id"`
		ExitCode int    `json:"exitCode"`
		Tail     string `json:"tail"`
	}
	var results []item
	run := func(id string, argv []string) {
		c.progress("Upgrading " + id + "…")
		var last string
		out, code, _ := a.runWinget(ctx, exe, argv, 90*time.Minute, func(l string) { last = l })
		_ = last
		results = append(results, item{ID: id, ExitCode: code, Tail: firstLines(lastLines(strings.Join(cleanWingetOutput(out), "\n"), 6), 600)})
	}
	if args.All {
		run("(all)", append([]string{"upgrade", "--all"}, common...))
	} else {
		for _, id := range args.IDs {
			run(id, append([]string{"upgrade", "--id", id, "--exact"}, common...))
		}
	}
	return map[string]any{"results": results}, nil
}

func lastLines(s string, n int) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, "\n")
}

// ---- power, messages, WOL, exec, RDP ----

func (a *Agent) cmdPower(ctx context.Context, c *cmdCtx) (any, error) {
	var p proto.PowerArgs
	if err := decode(c.args, &p); err != nil {
		return nil, err
	}
	switch p.Action {
	case "shutdown", "restart", "sleep", "hibernate", "lock", "logoff", "cancel":
	default:
		return nil, errors.New("unknown power action")
	}
	if p.Delay < 0 || p.Delay > 86400 {
		return nil, errors.New("delay must be between 0 and 86400 seconds")
	}
	if len(p.Message) > 200 {
		p.Message = p.Message[:200]
	}
	if err := powerAction(p); err != nil {
		return nil, err
	}
	return map[string]any{"action": p.Action, "delay": p.Delay}, nil
}

func (a *Agent) cmdMsg(ctx context.Context, c *cmdCtx) (any, error) {
	var args struct{ Title, Text string }
	if err := decode(c.args, &args); err != nil {
		return nil, err
	}
	if strings.TrimSpace(args.Text) == "" || len(args.Text) > 500 || len(args.Title) > 80 {
		return nil, errors.New("text required (max 500 characters), title max 80")
	}
	if args.Title == "" {
		args.Title = "Message from your administrator"
	}
	if err := sendUserMessage(args.Title, args.Text); err != nil {
		return nil, err
	}
	return map[string]bool{"shown": true}, nil
}

func (a *Agent) cmdWOL(ctx context.Context, c *cmdCtx) (any, error) {
	var args struct {
		MACs []string `json:"macs"`
	}
	if err := decode(c.args, &args); err != nil {
		return nil, err
	}
	n := 0
	for _, m := range args.MACs {
		hw, err := net.ParseMAC(m)
		if err != nil || len(hw) != 6 {
			continue
		}
		if err := sendMagicPacket(hw); err != nil {
			return nil, err
		}
		n++
	}
	if n == 0 {
		return nil, errors.New("no valid MAC addresses")
	}
	return map[string]int{"sent": n}, nil
}

func sendMagicPacket(hw net.HardwareAddr) error {
	pkt := bytes.Repeat([]byte{0xff}, 6)
	for i := 0; i < 16; i++ {
		pkt = append(pkt, hw...)
	}
	targets := map[string]bool{"255.255.255.255:9": true}
	ifs, _ := net.Interfaces()
	for _, ifc := range ifs {
		addrs, _ := ifc.Addrs()
		for _, ad := range addrs {
			if ipn, ok := ad.(*net.IPNet); ok && ipn.IP.To4() != nil && !ipn.IP.IsLoopback() {
				ip := ipn.IP.To4()
				m := ipn.Mask
				if len(m) == 16 {
					m = m[12:]
				}
				if len(m) == 4 {
					b := net.IP{ip[0] | ^m[0], ip[1] | ^m[1], ip[2] | ^m[2], ip[3] | ^m[3]}
					targets[net.JoinHostPort(b.String(), "9")] = true
				}
			}
		}
	}
	var lastErr error
	sent := 0
	for t := range targets {
		conn, err := net.Dial("udp4", t)
		if err != nil {
			lastErr = err
			continue
		}
		if _, err := conn.Write(pkt); err != nil {
			lastErr = err
		} else {
			sent++
		}
		conn.Close()
	}
	if sent == 0 {
		return lastErr
	}
	return nil
}

func (a *Agent) cmdExec(ctx context.Context, c *cmdCtx) (any, error) {
	var args proto.ExecArgs
	if err := decode(c.args, &args); err != nil {
		return nil, err
	}
	if strings.TrimSpace(args.Script) == "" || len(args.Script) > 200000 {
		return nil, errors.New("script required (max 200000 characters)")
	}
	if args.Shell == "" || realUnix() {
		args.Shell = "powershell" // on Linux every script runs in bash/sh whatever shell was asked for
	}
	if args.Shell != "powershell" && args.Shell != "cmd" {
		return nil, errors.New("shell must be powershell or cmd")
	}
	if args.Timeout <= 0 {
		args.Timeout = 60
	}
	if args.Timeout > 10800 {
		args.Timeout = 10800
	}
	res, err := a.runScript(ctx, scriptOpts{shell: args.Shell, script: args.Script, timeout: time.Duration(args.Timeout) * time.Second})
	if err != nil {
		return nil, err
	}
	return proto.ExecResult{Stdout: res.Stdout, Stderr: res.Stderr, ExitCode: res.ExitCode, TimedOut: res.TimedOut}, nil
}

func (a *Agent) rdpSet(ctx context.Context, enable bool) (any, error) {
	v := "0"
	if enable {
		v = "1"
	}
	res, err := a.runScript(ctx, scriptOpts{shell: "powershell", script: scriptRDPSet, internal: true,
		env: map[string]string{"HELM_A_ENABLE": v}, timeout: time.Minute})
	if err != nil {
		return nil, err
	}
	if res.ExitCode != 0 || res.TimedOut {
		return nil, errors.New(firstLines(res.Stderr+res.Stdout, 600))
	}
	return map[string]string{"message": strings.TrimSpace(res.Stdout)}, nil
}

func canHostRDP(edition string) bool { return !realUnix() && !strings.HasPrefix(edition, "Core") }
