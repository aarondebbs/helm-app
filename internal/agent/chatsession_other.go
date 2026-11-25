//go:build !windows

package agent

import (
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"
)

// On Linux and macOS the agent is a system service, so it has no desktop of its own. When the administrator writes, it
// finds the user who is signed in at the screen, shows a desktop notification and opens the chat page as a small
// app-style window in that user's session. Closing the window is fine: the next message opens it again, and
// `helm-agent chat` opens it by hand.

// A desktopUser is the person at the screen and what is needed to run a command in their session.
type desktopUser struct {
	name, uid string
	env       []string // Linux: DISPLAY, XDG_RUNTIME_DIR and so on
}

var (
	chatProcMu sync.Mutex
	chatProc   *exec.Cmd
)

func which(names ...string) string {
	for _, n := range names {
		if p, err := exec.LookPath(n); err == nil {
			return p
		}
	}
	return ""
}

func cmdOut(name string, args ...string) string {
	out, err := exec.Command(name, args...).Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

// activeDesktopUser returns the user who is signed in at the screen, or false when nobody is.
func activeDesktopUser() (desktopUser, bool) {
	if runtime.GOOS == "darwin" {
		name := cmdOut("stat", "-f", "%Su", "/dev/console")
		if name == "" || name == "root" {
			return desktopUser{}, false
		}
		u, err := user.Lookup(name)
		if err != nil {
			return desktopUser{}, false
		}
		return desktopUser{name: name, uid: u.Uid}, true
	}
	if which("loginctl") == "" {
		return desktopUser{}, false
	}
	for _, line := range strings.Split(cmdOut("loginctl", "list-sessions", "--no-legend"), "\n") {
		f := strings.Fields(line)
		if len(f) < 1 {
			continue
		}
		props := map[string]string{}
		for _, kv := range strings.Split(cmdOut("loginctl", "show-session", f[0], "-p", "Active", "-p", "Type", "-p", "Name", "-p", "User", "-p", "Display", "-p", "Remote"), "\n") {
			if i := strings.Index(kv, "="); i > 0 {
				props[kv[:i]] = kv[i+1:]
			}
		}
		t := props["Type"]
		if props["Active"] != "yes" || props["Remote"] == "yes" || (t != "x11" && t != "wayland") || props["Name"] == "" || props["User"] == "" {
			continue
		}
		rt := "/run/user/" + props["User"]
		env := []string{"XDG_RUNTIME_DIR=" + rt, "DBUS_SESSION_BUS_ADDRESS=unix:path=" + rt + "/bus"}
		if t == "x11" {
			d := props["Display"]
			if d == "" {
				d = ":0"
			}
			env = append(env, "DISPLAY="+d)
		} else {
			env = append(env, "WAYLAND_DISPLAY=wayland-0", "DISPLAY=:0")
		}
		return desktopUser{name: props["Name"], uid: props["User"], env: env}, true
	}
	return desktopUser{}, false
}

// inSession builds a command that runs as the desktop user inside their session.
func (u desktopUser) inSession(args ...string) *exec.Cmd {
	if os.Geteuid() != 0 { // started by the user themselves: no switching needed
		return exec.Command(args[0], args[1:]...)
	}
	if runtime.GOOS == "darwin" {
		return exec.Command("launchctl", append([]string{"asuser", u.uid, "sudo", "-u", u.name}, args...)...)
	}
	sw := []string{"-u", u.name, "--", "env"}
	if p := which("runuser"); p != "" {
		return exec.Command(p, append(append(sw, u.env...), args...)...)
	}
	return exec.Command("sudo", append(append([]string{"-u", u.name, "env"}, u.env...), args...)...)
}

func cleanForShell(s string) string {
	s = strings.Map(func(r rune) rune {
		if r == '"' || r == '\\' || r < 32 {
			return ' '
		}
		return r
	}, s)
	if r := []rune(s); len(r) > 140 {
		s = string(r[:140]) + "…"
	}
	return s
}

// notify shows a desktop notification, if the system has a way to.
func (u desktopUser) notify(text string) {
	text = cleanForShell(text)
	if runtime.GOOS == "darwin" {
		_ = u.inSession("osascript", "-e", `display notification "`+text+`" with title "Message from support"`).Run()
		return
	}
	if which("notify-send") != "" {
		_ = u.inSession("notify-send", "-a", "Helm", "Message from support", text).Run()
	}
}

// openWindow starts the chat as an app-style window, using Chrome, Chromium, Edge or Brave when installed, and the
// default browser otherwise.
func (u desktopUser) openWindow(url string) {
	chatProcMu.Lock()
	defer chatProcMu.Unlock()
	if chatProc != nil && chatProc.ProcessState == nil && chatProc.Process != nil && chatProc.Process.Signal(syscall.Signal(0)) == nil {
		return // a chat window from earlier is still open
	}
	var c *exec.Cmd
	profile := filepath.Join(os.TempDir(), "helm-chat-"+u.uid)
	flags := []string{"--app=" + url, "--window-size=400,560", "--user-data-dir=" + profile, "--no-first-run", "--disable-extensions"}
	if runtime.GOOS == "darwin" {
		for _, app := range []string{"Google Chrome", "Microsoft Edge", "Chromium", "Brave Browser"} {
			if _, err := os.Stat("/Applications/" + app + ".app"); err == nil {
				c = u.inSession(append([]string{"open", "-n", "-W", "-a", app, "--args"}, flags...)...)
				break
			}
		}
		if c == nil {
			c = u.inSession("open", url)
		}
	} else if b := which("google-chrome", "google-chrome-stable", "chromium", "chromium-browser", "microsoft-edge", "brave-browser"); b != "" {
		c = u.inSession(append([]string{b}, flags...)...)
	} else if which("xdg-open") != "" {
		c = u.inSession("xdg-open", url)
	} else {
		return
	}
	if c.Start() != nil {
		return
	}
	chatProc = c
	go func() { _ = c.Wait() }()
}

// chatNotifyUser runs when the administrator writes (see chatIncoming).
func (a *Agent) chatNotifyUser(text string) {
	u, ok := activeDesktopUser()
	if !ok {
		return
	}
	a.stMu.Lock()
	s := a.tray
	a.stMu.Unlock()
	u.notify(text)
	time.Sleep(300 * time.Millisecond)
	if url := chatURL(s); url != "" && s.AllowSupport {
		u.openWindow(url)
	}
}

// RunChat is `helm-agent chat`: open the chat window by hand.
func RunChat(args []string) int {
	s, err := readTrayStatus()
	if err != nil || chatURL(s) == "" {
		os.Stderr.WriteString("The Helm agent is not running on this computer.\n")
		return 1
	}
	u := desktopUser{uid: "0"}
	if cu, err := user.Current(); err == nil {
		u = desktopUser{name: cu.Username, uid: cu.Uid}
		if os.Geteuid() == 0 {
			if d, ok := activeDesktopUser(); ok {
				u = d
			}
		}
	}
	chatProcMu.Lock()
	chatProc = nil
	chatProcMu.Unlock()
	u.openWindow(chatURL(s))
	chatProcMu.Lock()
	p := chatProc
	chatProcMu.Unlock()
	if p != nil { // keep running while the window is open
		_ = p.Wait()
	}
	return 0
}
