//go:build !windows

package agent

// Homebrew on macOS. It plays the role winget has on Windows: it lists apps and command line tools that have a newer
// version and upgrades them. Helm's agent runs as root, but Homebrew refuses to run as root, so every brew call is made
// as the user who owns the Homebrew folder.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"
)

var reBrewID = regexp.MustCompile(`^(cask:)?[A-Za-z0-9][A-Za-z0-9@+._-]{0,80}(/[A-Za-z0-9][A-Za-z0-9@+._-]{0,80}){0,2}$`)

// brewBin finds Homebrew (Apple Silicon first, then Intel).
func brewBin() (string, error) {
	for _, p := range []string{"/opt/homebrew/bin/brew", "/usr/local/bin/brew"} {
		if st, err := os.Stat(p); err == nil && !st.IsDir() {
			return p, nil
		}
	}
	return "", errors.New("Homebrew is not installed on this Mac. Helm updates Apple software with System updates; other apps update through their own updater")
}

// brewRun runs brew as the owner of its folder (or as the current user when the agent is not root).
func brewRun(ctx context.Context, timeout time.Duration, args ...string) (string, error) {
	bin, err := brewBin()
	if err != nil {
		return "", err
	}
	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	cmd := exec.CommandContext(cctx, bin, args...)
	home := os.Getenv("HOME")
	if os.Geteuid() == 0 {
		st, err := os.Stat(filepath.Dir(filepath.Dir(bin)))
		if err != nil {
			return "", err
		}
		sys, ok := st.Sys().(*syscall.Stat_t)
		if !ok || sys.Uid == 0 {
			return "", errors.New("Homebrew is owned by root, which Homebrew does not support")
		}
		u, err := user.LookupId(strconv.Itoa(int(sys.Uid)))
		if err != nil {
			return "", err
		}
		gid, _ := strconv.Atoi(u.Gid)
		cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: sys.Uid, Gid: uint32(gid)}}
		home = u.HomeDir
	}
	cmd.Env = []string{"PATH=/opt/homebrew/bin:/opt/homebrew/sbin:/usr/local/bin:/usr/local/sbin:/usr/bin:/bin:/usr/sbin:/sbin", "HOME=" + home,
		"HOMEBREW_NO_ANALYTICS=1", "HOMEBREW_NO_AUTO_UPDATE=1", "HOMEBREW_NO_INSTALL_CLEANUP=1", "NONINTERACTIVE=1", "LC_ALL=C"}
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	err = cmd.Run()
	text := strings.TrimSpace(out.String())
	if err != nil {
		return text, fmt.Errorf("brew %s: %v %s", firstWord(args), err, firstLines(lastLines(errb.String(), 4), 400))
	}
	return text, nil
}

func firstWord(a []string) string {
	if len(a) == 0 {
		return ""
	}
	return a[0]
}

// parseBrewOutdated reads `brew outdated --json=v2`.
func parseBrewOutdated(js string) ([]WingetPkg, error) {
	var d struct {
		Formulae []struct {
			Name      string   `json:"name"`
			Installed []string `json:"installed_versions"`
			Current   string   `json:"current_version"`
		} `json:"formulae"`
		Casks []struct {
			Name      string `json:"name"`
			Installed any    `json:"installed_versions"` // a string on current brew, a list on older ones
			Current   string `json:"current_version"`
		} `json:"casks"`
	}
	if err := json.Unmarshal([]byte(js), &d); err != nil {
		return nil, err
	}
	out := []WingetPkg{}
	for _, f := range d.Formulae {
		out = append(out, WingetPkg{Name: f.Name, ID: f.Name, Version: strings.Join(f.Installed, ", "), Available: f.Current, Source: "brew"})
	}
	for _, c := range d.Casks {
		inst := ""
		switch v := c.Installed.(type) {
		case string:
			inst = v
		case []any:
			for _, x := range v {
				if s, ok := x.(string); ok {
					inst += s + " "
				}
			}
			inst = strings.TrimSpace(inst)
		}
		out = append(out, WingetPkg{Name: c.Name, ID: "cask:" + c.Name, Version: inst, Available: c.Current, Source: "brew cask"})
	}
	return out, nil
}

func (a *Agent) macBrewList(ctx context.Context, c *cmdCtx) (any, error) {
	if _, err := brewBin(); err != nil {
		return nil, err
	}
	if !a.updMu.TryLock() {
		return nil, errors.New("another update operation is already running on this Mac")
	}
	defer a.updMu.Unlock()
	c.progress("Refreshing Homebrew…")
	_, _ = brewRun(ctx, 5*time.Minute, "update", "--quiet")
	out, err := brewRun(ctx, 5*time.Minute, "outdated", "--json=v2", "--greedy")
	if err != nil && out == "" {
		return nil, err
	}
	pk, perr := parseBrewOutdated(out)
	if perr != nil {
		return nil, errors.New("Homebrew gave an answer Helm could not read")
	}
	return map[string]any{"packages": pk, "exitCode": 0}, nil
}

func (a *Agent) macBrewUpgrade(ctx context.Context, c *cmdCtx) (any, error) {
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
	var formulae, casks []string
	for _, id := range args.IDs {
		if !reBrewID.MatchString(id) || strings.Contains(id, "..") {
			return nil, fmt.Errorf("bad package id %q", id)
		}
		if n, ok := strings.CutPrefix(id, "cask:"); ok {
			casks = append(casks, n)
		} else {
			formulae = append(formulae, id)
		}
	}
	if !a.updMu.TryLock() {
		return nil, errors.New("another update operation is already running on this Mac")
	}
	defer a.updMu.Unlock()
	type item struct {
		ID       string `json:"id"`
		ExitCode int    `json:"exitCode"`
		Tail     string `json:"tail"`
	}
	var results []item
	step := func(label string, argv ...string) {
		c.progress("Updating " + label + "…")
		out, err := brewRun(ctx, 90*time.Minute, argv...)
		code := 0
		if err != nil {
			code = 1
			out += " " + err.Error()
		}
		results = append(results, item{ID: label, ExitCode: code, Tail: firstLines(lastLines(out, 6), 600)})
	}
	if args.All {
		step("all Homebrew formulae", "upgrade", "--formula")
		step("all Homebrew apps", "upgrade", "--cask", "--greedy")
	} else {
		if len(formulae) > 0 {
			step(strings.Join(formulae, ", "), append([]string{"upgrade", "--formula"}, formulae...)...)
		}
		if len(casks) > 0 {
			step(strings.Join(casks, ", "), append([]string{"upgrade", "--cask", "--greedy"}, casks...)...)
		}
	}
	return map[string]any{"results": results}, nil
}
