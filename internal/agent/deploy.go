package agent

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

var (
	reSafeFile = regexp.MustCompile(`^[A-Za-z0-9._-]{1,100}$`)
	reSHA256   = regexp.MustCompile(`^[0-9a-f]{64}$`)
	rePkgPath  = regexp.MustCompile(`^/api/agent/package/[0-9a-f]{8,32}$`)
	reVersion  = regexp.MustCompile(`^[A-Za-z0-9._+-]{1,60}$`)
)

func (a *Agent) deployHandlers() map[string]handlerFn {
	return map[string]handlerFn{
		"winget.install":   a.cmdWingetInstall,
		"winget.uninstall": a.cmdWingetUninstall,
		"pkg.install":      a.cmdPkgInstall,
	}
}

func (a *Agent) cmdWingetInstall(ctx context.Context, c *cmdCtx) (any, error) {
	var args struct {
		ID      string `json:"id"`
		Version string `json:"version"`
	}
	if err := decode(c.args, &args); err != nil {
		return nil, err
	}
	if !reWingetID.MatchString(args.ID) {
		return nil, fmt.Errorf("bad package id %q", args.ID)
	}
	if args.Version != "" && !reVersion.MatchString(args.Version) {
		return nil, errors.New("bad version")
	}
	argv := []string{"install", "--id", args.ID, "--exact", "--silent", "--scope", "machine",
		"--accept-source-agreements", "--accept-package-agreements", "--disable-interactivity"}
	if args.Version != "" {
		argv = append(argv, "--version", args.Version)
	}
	return a.wingetRun(ctx, c, "Installing "+args.ID+"…", argv)
}

func (a *Agent) cmdWingetUninstall(ctx context.Context, c *cmdCtx) (any, error) {
	var args struct {
		ID string `json:"id"`
	}
	if err := decode(c.args, &args); err != nil {
		return nil, err
	}
	if !reWingetID.MatchString(args.ID) {
		return nil, fmt.Errorf("bad package id %q", args.ID)
	}
	argv := []string{"uninstall", "--id", args.ID, "--exact", "--silent", "--accept-source-agreements", "--disable-interactivity"}
	return a.wingetRun(ctx, c, "Removing "+args.ID+"…", argv)
}

// wingetRun runs one winget command under the shared update lock and reports exit code + tail.
func (a *Agent) wingetRun(ctx context.Context, c *cmdCtx, msg string, argv []string) (any, error) {
	exe, err := a.wingetPath()
	if err != nil {
		return nil, err
	}
	if !a.updMu.TryLock() {
		return nil, errors.New("another update operation is already running on this PC")
	}
	defer a.updMu.Unlock()
	c.progress(msg)
	out, code, _ := a.runWinget(ctx, exe, argv, 60*time.Minute, func(string) {})
	tail := firstLines(lastLines(strings.Join(cleanWingetOutput(out), "\n"), 8), 800)
	// 0 = success; 0x8A150101 "no applicable upgrade"/"already installed" are benign
	if code != 0 && uint32(code) != 0x8A15002B && uint32(code) != 0x8A150061 {
		return nil, fmt.Errorf("winget exited with code %d: %s", code, tail)
	}
	return map[string]any{"exitCode": code, "tail": tail}, nil
}

// cmdPkgInstall downloads an installer from the Helm server (authenticated as this device),
// verifies its SHA-256 and runs it silently.
func (a *Agent) cmdPkgInstall(ctx context.Context, c *cmdCtx) (any, error) {
	var args struct {
		Path     string `json:"path"` // /api/agent/package/<id>
		SHA256   string `json:"sha256"`
		Filename string `json:"filename"`
		Kind     string `json:"kind"` // msi | exe
		Args     string `json:"args"`
	}
	if err := decode(c.args, &args); err != nil {
		return nil, err
	}
	if !rePkgPath.MatchString(args.Path) || !reSHA256.MatchString(args.SHA256) || !reSafeFile.MatchString(args.Filename) {
		return nil, errors.New("bad package description")
	}
	if realLinux() {
		if args.Kind != "deb" {
			return nil, errors.New("only .deb packages can be installed on Linux")
		}
	} else if realMac() {
		if args.Kind != "pkg" {
			return nil, errors.New("only .pkg installers can be installed on macOS")
		}
	} else if args.Kind != "msi" && args.Kind != "exe" {
		return nil, errors.New("kind must be msi or exe")
	}
	if len(args.Args) > 500 || strings.ContainsAny(args.Args, "\r\n\x00") {
		return nil, errors.New("bad installer arguments")
	}
	if !a.updMu.TryLock() {
		return nil, errors.New("another update operation is already running on this PC")
	}
	defer a.updMu.Unlock()

	dir := filepath.Join(a.cfg.DataDir, "pkg")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	dst := filepath.Join(dir, args.Filename)
	defer os.Remove(dst)
	c.progress("Downloading " + args.Filename + "…")
	dctx := context.WithValue(ctx, progKey{}, func(p int) { c.pct(p*8/10, "Downloading "+args.Filename+"…") })
	got, err := a.downloadAuth(dctx, a.cfg.Server+args.Path, dst)
	if err != nil {
		return nil, err
	}
	if got != args.SHA256 {
		return nil, errors.New("downloaded file does not match the expected SHA-256; not running it")
	}
	c.pct(85, "Running installer…")
	if realLinux() {
		return a.linuxDebInstall(ctx, dst)
	}
	if realMac() {
		return a.macPkgInstall(ctx, dst)
	}
	var script string
	if args.Kind == "msi" {
		script = fmt.Sprintf("msiexec /i \"%s\" /qn /norestart %s", dst, args.Args)
	} else {
		script = fmt.Sprintf("\"%s\" %s", dst, args.Args)
	}
	res, err := a.runScript(ctx, scriptOpts{shell: "cmd", script: script, timeout: 60 * time.Minute})
	if err != nil {
		return nil, err
	}
	if res.TimedOut {
		return nil, errors.New("installer timed out after 60 minutes")
	}
	reboot := res.ExitCode == 3010 || res.ExitCode == 1641
	if res.ExitCode != 0 && !reboot {
		return nil, fmt.Errorf("installer exited with code %d: %s", res.ExitCode, firstLines(res.Stderr+res.Stdout, 400))
	}
	return map[string]any{"exitCode": res.ExitCode, "rebootRequired": reboot}, nil
}

// downloadAuth is like download but authenticates as this device and caps the size.
func (a *Agent) downloadAuth(ctx context.Context, rawURL, dst string) (string, error) {
	req, _ := http.NewRequestWithContext(ctx, "GET", rawURL, nil)
	req.Header = a.authHeader()
	cl := a.httpClient()
	cl.Timeout = 60 * time.Minute
	resp, err := cl.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("download failed: HTTP %d", resp.StatusCode)
	}
	f, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o700)
	if err != nil {
		return "", err
	}
	h := sha256.New()
	var dst2 io.Writer = io.MultiWriter(f, h)
	if pf := progressFrom(ctx); pf != nil && resp.ContentLength > 0 {
		dst2 = &pctWriter{w: dst2, total: resp.ContentLength, report: pf}
	}
	n, err := io.Copy(dst2, io.LimitReader(resp.Body, 1<<30+1))
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil && n > 1<<30 {
		err = errors.New("package is larger than 1 GB")
	}
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

type progKey struct{}

func progressFrom(ctx context.Context) func(int) {
	f, _ := ctx.Value(progKey{}).(func(int))
	return f
}

// pctWriter reports download progress at most once per percent point.
type pctWriter struct {
	w        io.Writer
	total, n int64
	last     int
	report   func(int)
}

func (p *pctWriter) Write(b []byte) (int, error) {
	n, err := p.w.Write(b)
	p.n += int64(n)
	if pc := int(p.n * 100 / p.total); pc != p.last {
		p.last = pc
		p.report(pc)
	}
	return n, err
}
