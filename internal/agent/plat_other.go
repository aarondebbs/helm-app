//go:build !windows

package agent

// Development stand-ins so the agent can run on Linux/macOS against a test
// server. None of this is used on Windows, the supported target platform.

import (
	"bytes"
	"context"
	"errors"
	"image"
	"image/color"
	"image/jpeg"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"helm/internal/proto"
	"helm/internal/ws"
)

func securePath(dir string) { _ = os.Chmod(dir, 0o700) }

func consumeEnrollToken() {
	if realUnix() {
		linuxConsumeToken()
	}
}

func sysStats() proto.Stats {
	if realMac() {
		return macStats()
	}
	if realLinux() {
		return linuxStats()
	}
	st := proto.Stats{CPU: 3.5, MemTotal: 8 << 30, MemUsed: 3 << 30, UptimeSec: 12345}
	var fs syscall.Statfs_t
	if syscall.Statfs("/", &fs) == nil {
		st.Disks = []proto.Disk{{Name: "/", Total: fs.Blocks * uint64(fs.Bsize), Free: fs.Bavail * uint64(fs.Bsize)}}
	}
	st.User, st.UserPresent = loggedOnUser()
	return st
}

func osInfo() (string, string) {
	if realMac() {
		return macOSInfo()
	}
	if realLinux() {
		return linuxOSInfo()
	}
	return "dev", "DevEdition"
}

func loggedOnUser() (string, bool) {
	if realMac() {
		return macLoggedOnUser()
	}
	if realLinux() {
		return linuxLoggedOnUser()
	}
	u := os.Getenv("USER")
	return u, u != ""
}

func shellCommand(ctx context.Context, shell, path string) *exec.Cmd {
	if realUnix() {
		return exec.CommandContext(ctx, linuxShell(), path)
	}
	return exec.CommandContext(ctx, "sh", path)
}

func terminalCommand(ctx context.Context, shell string) *exec.Cmd {
	if realUnix() {
		return exec.CommandContext(ctx, linuxShell())
	}
	return exec.CommandContext(ctx, "sh")
}

func hideWindow(cmd *exec.Cmd) {}

func killTree(pid int) {
	if p, err := os.FindProcess(pid); err == nil {
		_ = p.Kill()
	}
}

func powerAction(p proto.PowerArgs) error {
	if realMac() {
		return macPower(p)
	}
	if realLinux() {
		return linuxPower(p)
	}
	if os.Getenv("HELM_FAKE_POWER_FAIL") != "" {
		return errors.New("simulated failure")
	}
	return nil // simulated
}

func sendUserMessage(title, text string) error {
	if realMac() {
		return macMessage(title, text)
	}
	if realLinux() {
		return linuxMessage(title, text)
	}
	return nil
}

func rdpPort() int {
	if v, err := strconv.Atoi(os.Getenv("HELM_FAKE_RDP_PORT")); err == nil {
		return v
	}
	return 3389
}

func applyUpdate(newExe string) error {
	if realUnix() {
		return linuxApplyUpdate(newExe)
	}
	return errors.New("self-update is only supported on Windows, Linux and macOS")
}

func uninstallSelf() error {
	if realMac() {
		return macUninstall()
	}
	if realLinux() {
		return linuxUninstall()
	}
	return errors.New("uninstall is only supported on Windows, Linux and macOS")
}

func listDrives() []string {
	if realMac() {
		return macMounts()
	}
	if realLinux() {
		return linuxMounts()
	}
	return []string{"/"}
}

func wingetFixtureAvailable() string {
	if realUnix() {
		return ""
	}
	return "winget-fixture"
}

func wingetFixture(args []string) (string, bool) {
	if len(args) > 0 && args[0] == "source" {
		return "", true
	}
	if len(args) > 0 && args[0] == "upgrade" {
		for _, a := range args {
			if a == "--id" || a == "--all" {
				return "Successfully installed\r\n", true
			}
		}
		return "Name                 Id                      Version   Available Source\r\n" +
			"-----------------------------------------------------------------------\r\n" +
			"Git                  Git.Git                 2.43.0    2.44.0    winget\r\n" +
			"1 upgrades available.\r\n", true
	}
	return "", false
}

var fixtures = map[string]string{
	"inventory":      `{"computerName":"DEV","osCaption":"Dev OS","cpu":"Test CPU","cores":4,"ramBytes":8589934592}`,
	"software":       `[{"name":"Demo App","version":"1.0","publisher":"Acme","installDate":"20240101"}]`,
	"processes":      `[{"pid":100,"name":"demo","cpu":1.5,"memMB":10.2,"user":"dev","path":"/bin/demo"}]`,
	"services":       `[{"name":"DemoSvc","display":"Demo Service","state":"Running","start":"Auto","account":"LocalSystem"}]`,
	"servicecontrol": `{"name":"DemoSvc","status":"Running","startType":"Automatic"}`,
	"eventlog":       `[{"time":"2024-01-01T00:00:00Z","id":1,"provider":"Demo","level":"Warning","message":"hello"}]`,
	"updatescheck":   `{"updates":[{"id":"11111111-1111-1111-1111-111111111111","title":"Demo Update (KB1)","kb":["1"],"sizeMB":10,"severity":"Important","needsReboot":false,"downloaded":false,"categories":["Security"]}],"rebootPending":false}`,
	"updatesinstall": "PROGRESS:Downloading 1 update(s)...\nPROGRESS:Installing...\n" +
		`RESULT:{"installed":1,"resultCode":2,"rebootRequired":false,"items":[{"title":"Demo Update (KB1)","resultCode":2}]}`,
	"rdpstatus": `{"enabled":true,"port":3389,"nla":true,"edition":"Pro","supported":true,"service":"Running"}`,
	"rdpset":    "Remote Desktop enabled.",
	"scansoftware": `[{"name":"7-Zip 22.01 (x64)","version":"22.01","publisher":"Igor Pavlov","installDate":"20230101","scope":"machine"},` +
		`{"name":"Mozilla Firefox (x64 en-US)","version":"120.0","publisher":"Mozilla","installDate":"20231201","scope":"machine"},` +
		`{"name":"Demo App","version":"1.0","publisher":"Acme","installDate":"20240101","scope":"machine"}]`,
	"scanports": `[{"proto":"tcp","address":"0.0.0.0","port":135,"pid":900,"process":"svchost"},` +
		`{"proto":"tcp","address":"0.0.0.0","port":445,"pid":4,"process":"System"},` +
		`{"proto":"tcp","address":"127.0.0.1","port":5432,"pid":1200,"process":"postgres"},` +
		`{"proto":"tcp","address":"0.0.0.0","port":3389,"pid":1100,"process":"svchost"}]`,
	"scanconfig": `{"build":19045,"edition":"Professional","checks":[` +
		`{"id":"av_realtime","title":"Real-time antivirus protection","category":"Malware protection","severity":"high","status":"pass","detail":"Microsoft Defender real-time protection is on.","fix":""},` +
		`{"id":"firewall","title":"Windows Firewall enabled","category":"Network","severity":"high","status":"fail","detail":"Off for: Public","fix":"Turn the firewall on for every profile."},` +
		`{"id":"smb1","title":"SMBv1 disabled","category":"Network","severity":"high","status":"pass","detail":"SMBv1 is disabled.","fix":""},` +
		`{"id":"bitlocker","title":"System drive encrypted (BitLocker)","category":"Data protection","severity":"medium","status":"fail","detail":"The system drive is not protected by BitLocker.","fix":"Enable BitLocker."},` +
		`{"id":"reboot","title":"No restart pending","category":"Patching","severity":"low","status":"warn","detail":"A restart is pending.","fix":"Restart the PC."}]}`,
}

func fixtureFor(script string) (string, bool) {
	if realUnix() {
		return "", false
	}
	if !strings.HasPrefix(script, "# helm:") {
		return "", false
	}
	name := strings.TrimSpace(strings.SplitN(strings.TrimPrefix(script, "# helm:"), "\n", 2)[0])
	out, ok := fixtures[name]
	return out, ok
}

// launchHelper starts an in-process fake helper (stand-in for the Windows
// session helper) so the whole screen path can be exercised on Linux.
func launchHelper(ctx context.Context, hl helperLaunch) (func(), error) {
	if realUnix() {
		return nil, errors.New("remote screen is not supported on this platform; use the terminal and file tools")
	}
	hctx, cancel := context.WithCancel(ctx)
	go fakeHelper(hctx, hl)
	return cancel, nil
}

func fakeHelper(ctx context.Context, hl helperLaunch) {
	h := http.Header{}
	h.Set("X-Helm-Token", hl.Token)
	c, err := ws.Dial(ctx, "ws://"+hl.Addr+"/helper", ws.DialOptions{Header: h})
	if err != nil {
		return
	}
	defer c.Close(ws.CloseNormal, "")
	c.KeepAlive(10 * time.Second)
	go func() { <-ctx.Done(); c.Close(ws.CloseGoingAway, "") }()
	if os.Getenv("HELM_FAKE_CONSENT") == "deny" && hl.Consent != ConsentUnattended {
		_ = sendJSON(c, map[string]any{"t": "consent", "ok": false, "msg": "the person at the PC declined the request"})
		time.Sleep(200 * time.Millisecond)
		return
	}
	_ = sendJSON(c, map[string]any{"t": "consent", "ok": true})
	for {
		op, msg, err := c.ReadMessage()
		if err != nil {
			return
		}
		if op != ws.OpText {
			continue
		}
		if strings.Contains(string(msg), `"start"`) {
			_ = sendJSON(c, map[string]any{"t": "screen", "w": 256, "h": 128})
			img := image.NewRGBA(image.Rect(0, 0, 64, 64))
			for y := 0; y < 64; y++ {
				for x := 0; x < 64; x++ {
					img.Set(x, y, color.RGBA{uint8(x * 4), uint8(y * 4), 128, 255})
				}
			}
			var buf bytes.Buffer
			_ = jpeg.Encode(&buf, img, &jpeg.Options{Quality: 60})
			_ = c.WriteMessage(ws.OpBinary, EncodeTiles([]Tile{{X: 0, Y: 0, W: 64, H: 64, JPEG: buf.Bytes()}}))
			continue
		}
		_ = sendJSON(c, map[string]any{"t": "echo", "m": string(msg)})
	}
}

func sendSAS() error { return nil }

// LoadInstalledConfig reads settings from the environment (development only).
func LoadInstalledConfig() (server, token, consent string, allowInsecure bool) {
	if realUnix() {
		return linuxConfig()
	}
	return os.Getenv("HELM_SERVER"), os.Getenv("HELM_TOKEN"), os.Getenv("HELM_CONSENT"), os.Getenv("HELM_INSECURE") == "1"
}

// DefaultDataDir is the agent data directory (development only).
func DefaultDataDir() string {
	if realUnix() && os.Getenv("HELM_DATA") == "" {
		return linuxDataDir()
	}
	if d := os.Getenv("HELM_DATA"); d != "" {
		return d
	}
	h, _ := os.UserHomeDir()
	return h + "/.helm-agent"
}

// CleanupOldBinary is a no-op outside Windows.
func CleanupOldBinary() {}

// RunHelper is only meaningful on Windows.
func RunHelper(args []string) int { return 2 }

// ErrNotService is returned by RunService when not started by a service manager.
var ErrNotService = errors.New("services are only supported on Windows")

// RunService is only meaningful on Windows.
func RunService(name string, fn func(ctx context.Context)) error {
	if realUnix() { // systemd/launchd run the binary directly: run until SIGTERM/SIGINT
		ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, os.Interrupt)
		defer stop()
		fn(ctx)
		return nil
	}
	return ErrNotService
}

// ServiceName is the Windows service name registered by the MSI.
const ServiceName = "HelmAgent"

func linuxShell() string {
	if p, err := exec.LookPath("bash"); err == nil {
		return p
	}
	return "sh"
}
