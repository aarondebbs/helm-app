package agent

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// Security modules (Antivirus and EDR). The agent ships with the code; the server decides, per PC, which
// commands it will send. Antivirus drives the engine the OS already has (Microsoft Defender, ClamAV);
// Helm does not bring its own signature database.

func (a *Agent) secHandlers() map[string]handlerFn {
	return map[string]handlerFn{
		"av.status":      a.cmdAVStatus,
		"av.scan":        a.cmdAVScan,
		"av.update":      a.cmdAVUpdate,
		"av.threats":     a.cmdAVThreats,
		"edr.snapshot":   a.cmdEDRSnapshot,
		"edr.isolate":    a.cmdEDRIsolate,
		"edr.release":    a.cmdEDRRelease,
		"module.install": a.cmdModuleInstall,
		"wol.configure":  a.cmdWOLConfigure,
	}
}

func secRun(ctx context.Context, timeout time.Duration, name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	hideWindow(cmd)
	out, err := cmd.CombinedOutput()
	if ctx.Err() == context.DeadlineExceeded {
		return string(out), errors.New("timed out")
	}
	return string(out), err
}

func secPS(ctx context.Context, timeout time.Duration, script string) (string, error) {
	return secRun(ctx, timeout, powershellExe(), "-NoProfile", "-NonInteractive", "-Command", script)
}

func powershellExe() string {
	if runtime.GOOS == "windows" {
		if p, err := exec.LookPath("powershell.exe"); err == nil {
			return p
		}
		return "powershell.exe"
	}
	return "pwsh"
}

func haveBin(n string) bool { _, err := exec.LookPath(n); return err == nil }

// ---------------- antivirus ----------------

func (a *Agent) cmdAVStatus(ctx context.Context, c *cmdCtx) (any, error) {
	switch runtime.GOOS {
	case "windows":
		out, err := secPS(ctx, 60*time.Second, `$s=Get-MpComputerStatus; [pscustomobject]@{engine='Microsoft Defender';enabled=[bool]$s.AntivirusEnabled;realtime=[bool]$s.RealTimeProtectionEnabled;signatures=$s.AntivirusSignatureVersion;signaturesUpdated=$s.AntivirusSignatureLastUpdated;lastQuickScan=$s.QuickScanEndTime;lastFullScan=$s.FullScanEndTime;tamper=[bool]$s.IsTamperProtected} | ConvertTo-Json -Compress`)
		if err != nil {
			return nil, errors.New("Microsoft Defender is not available: " + firstLines(out, 200))
		}
		return json.RawMessage(strings.TrimSpace(out)), nil
	case "linux":
		if !haveBin("clamscan") {
			return map[string]any{"engine": "none", "enabled": false, "hint": "Install ClamAV (apt install clamav) to enable scanning on this machine"}, nil
		}
		v, _ := secRun(ctx, 20*time.Second, "clamscan", "--version")
		return map[string]any{"engine": "ClamAV", "enabled": true, "signatures": strings.TrimSpace(v), "realtime": haveBin("clamd")}, nil
	case "darwin":
		v, _ := secRun(ctx, 10*time.Second, "defaults", "read", "/Library/Apple/System/Library/CoreServices/XProtect.bundle/Contents/Info", "CFBundleShortVersionString")
		return map[string]any{"engine": "XProtect (built in)", "enabled": true, "signatures": strings.TrimSpace(v), "hint": "macOS keeps XProtect on and updates it itself; Helm reads its version."}, nil
	}
	return nil, errors.New("not supported on this system")
}

func (a *Agent) cmdAVScan(ctx context.Context, c *cmdCtx) (any, error) {
	var args struct {
		Kind string `json:"kind"` // quick, full, path
		Path string `json:"path"`
	}
	if err := decode(c.args, &args); err != nil {
		return nil, err
	}
	if args.Kind == "" {
		args.Kind = "quick"
	}
	switch runtime.GOOS {
	case "windows":
		kind := map[string]string{"quick": "QuickScan", "full": "FullScan"}[args.Kind]
		script := "Start-MpScan -ScanType " + kind
		if args.Kind == "path" {
			p, err := normPath(args.Path)
			if err != nil {
				return nil, err
			}
			script = "Start-MpScan -ScanType CustomScan -ScanPath '" + strings.ReplaceAll(p, "'", "''") + "'"
		} else if kind == "" {
			return nil, errors.New("unknown scan kind")
		}
		c.progress("Starting the Microsoft Defender " + args.Kind + " scan")
		// Defender does not report a percentage, so show how long the scan has run and what it is.
		started := time.Now()
		done := make(chan struct{})
		var out string
		var serr error
		go func() { out, serr = secPS(ctx, 4*time.Hour, script); close(done) }()
		tick := time.NewTicker(4 * time.Second)
		defer tick.Stop()
	wait:
		for {
			select {
			case <-done:
				break wait
			case <-tick.C:
				c.progress(fmt.Sprintf("Microsoft Defender is scanning (%s so far). It does not report a percentage.", time.Since(started).Round(time.Second)))
			}
		}
		if serr != nil {
			return nil, errors.New(firstLines(out, 300))
		}
		th, _ := secPS(ctx, 60*time.Second, `@(Get-MpThreatDetection | Sort-Object InitialDetectionTime -Descending | Select-Object -First 20 ThreatID,ProcessName,Resources,InitialDetectionTime,ActionSuccess) | ConvertTo-Json -Compress`)
		return map[string]any{"engine": "Microsoft Defender", "kind": args.Kind, "done": true, "recent": json.RawMessage(nonEmptyJSON(th))}, nil
	case "linux", "darwin":
		if !haveBin("clamscan") {
			return nil, errors.New("ClamAV is not installed on this machine (apt install clamav / brew install clamav)")
		}
		targets := []string{"/home", "/tmp", "/var/tmp", "/root"}
		cargs := []string{"-r", "--no-summary"}
		switch args.Kind {
		case "full":
			targets = []string{"/"}
			cargs = append(cargs, "--exclude-dir=^/proc", "--exclude-dir=^/sys", "--exclude-dir=^/dev", "--exclude-dir=^/run")
		case "path":
			p, err := normPath(args.Path)
			if err != nil {
				return nil, err
			}
			targets = []string{p}
		case "quick":
			if runtime.GOOS == "darwin" {
				targets = []string{"/Users", "/tmp"}
			}
		default:
			return nil, errors.New("unknown scan kind")
		}
		found, err := clamScan(ctx, c, cargs, targets, args.Kind == "full")
		if err != nil && len(found) == 0 {
			return nil, err
		}
		return map[string]any{"engine": "ClamAV", "kind": args.Kind, "done": true, "infected": found}, nil
	}
	return nil, errors.New("not supported on this system")
}

func nonEmptyJSON(s string) string {
	s = strings.TrimSpace(s)
	if s == "" || !json.Valid([]byte(s)) {
		return "[]"
	}
	return s
}

func (a *Agent) cmdAVUpdate(ctx context.Context, c *cmdCtx) (any, error) {
	switch runtime.GOOS {
	case "windows":
		rt, note := ensureDefenderRealtime(ctx)
		if out, err := secPS(ctx, 20*time.Minute, "Update-MpSignature"); err != nil {
			return nil, errors.New(firstLines(out, 300))
		}
		return map[string]any{"updated": true, "realtime": rt, "realtimeNote": note}, nil
	case "linux":
		if !haveBin("freshclam") {
			return nil, errors.New("freshclam (ClamAV) is not installed")
		}
		if out, err := runFreshclam(ctx); err != nil {
			return nil, errors.New(firstLines(out, 300))
		}
		return map[string]any{"updated": true}, nil
	}
	return nil, errors.New("signatures update by themselves on this system")
}

func (a *Agent) cmdAVThreats(ctx context.Context, c *cmdCtx) (any, error) {
	if runtime.GOOS == "windows" {
		out, err := secPS(ctx, 60*time.Second, `@(Get-MpThreatDetection | Sort-Object InitialDetectionTime -Descending | Select-Object -First 100 ThreatID,ProcessName,Resources,InitialDetectionTime,ActionSuccess) | ConvertTo-Json -Compress`)
		if err != nil {
			return nil, errors.New(firstLines(out, 300))
		}
		return json.RawMessage(nonEmptyJSON(out)), nil
	}
	return json.RawMessage("[]"), nil
}

// ---------------- EDR: telemetry ----------------

type edrProc struct {
	PID     int      `json:"pid"`
	PPID    int      `json:"ppid"`
	Name    string   `json:"name"`
	Path    string   `json:"path,omitempty"`
	User    string   `json:"user,omitempty"`
	Cmdline string   `json:"cmdline,omitempty"`
	Flags   []string `json:"flags,omitempty"`
}

type edrConn struct {
	PID    int    `json:"pid,omitempty"`
	Proc   string `json:"proc,omitempty"`
	Local  string `json:"local"`
	Remote string `json:"remote,omitempty"`
	State  string `json:"state"`
}

func (a *Agent) cmdEDRSnapshot(ctx context.Context, c *cmdCtx) (any, error) {
	var procs []edrProc
	var conns []edrConn
	var persist []string
	var err error
	switch runtime.GOOS {
	case "windows":
		procs, conns, persist, err = edrWindows(ctx)
	case "linux":
		procs, conns, persist, err = edrLinux()
	default:
		procs, conns, persist, err = edrDarwin(ctx)
	}
	if err != nil {
		return nil, err
	}
	flagged := 0
	for i := range procs {
		procs[i].Flags = edrFlags(procs[i])
		if len(procs[i].Flags) > 0 {
			flagged++
		}
	}
	// Only send what is useful: every flagged process plus the first 400 others.
	out := make([]edrProc, 0, len(procs))
	n := 0
	for _, p := range procs {
		if len(p.Flags) > 0 {
			out = append(out, p)
		} else if n < 400 {
			out = append(out, p)
			n++
		}
	}
	return map[string]any{"at": time.Now().Unix(), "processes": out, "total": len(procs), "flagged": flagged, "connections": conns, "persistence": persist, "isolated": isolationActive(a)}, nil
}

var suspiciousDirs = []string{`\appdata\local\temp\`, `\windows\temp\`, `\users\public\`, `\downloads\`, `\$recycle.bin\`, `\programdata\`, "/tmp/", "/var/tmp/", "/dev/shm/", "/run/user/"}

func edrFlags(p edrProc) []string {
	var f []string
	lp := strings.ToLower(strings.ReplaceAll(p.Path, "/", `/`))
	for _, d := range suspiciousDirs {
		if strings.Contains(lp, d) && !strings.Contains(lp, `\programdata\microsoft\windows defender`) && !strings.Contains(lp, `\programdata\microsoft\`) {
			f = append(f, "runs from "+strings.Trim(d, `\/`))
			break
		}
	}
	if strings.HasSuffix(p.Path, "(deleted)") {
		f = append(f, "program file was deleted while running")
	}
	n := strings.ToLower(p.Name)
	if runtime.GOOS == "windows" && p.Path != "" {
		sys32 := strings.ToLower(os.Getenv("SystemRoot")) + `\system32\`
		for _, sn := range []string{"svchost.exe", "lsass.exe", "csrss.exe", "winlogon.exe", "services.exe", "smss.exe"} {
			if n == sn && !strings.HasPrefix(lp, sys32) {
				f = append(f, "named like a Windows process but not in System32")
			}
		}
	}
	lc := strings.ToLower(p.Cmdline)
	if strings.Contains(lc, "-encodedcommand") || strings.Contains(lc, " -enc ") {
		f = append(f, "PowerShell with an encoded command")
	}
	if strings.Contains(lc, "/dev/tcp/") || strings.Contains(lc, "nc -e") || strings.Contains(lc, "bash -i") {
		f = append(f, "looks like a reverse shell")
	}
	return f
}

func edrWindows(ctx context.Context) ([]edrProc, []edrConn, []string, error) {
	script := `$ErrorActionPreference='SilentlyContinue'
$p=@(Get-CimInstance Win32_Process | ForEach-Object { [pscustomobject]@{pid=[int]$_.ProcessId;ppid=[int]$_.ParentProcessId;name=$_.Name;path=$_.ExecutablePath;cmdline=$_.CommandLine} })
$ct=@(Get-NetTCPConnection | Where-Object {$_.State -in 'Listen','Established'} | ForEach-Object { [pscustomobject]@{pid=[int]$_.OwningProcess;local=($_.LocalAddress+':'+$_.LocalPort);remote=($_.RemoteAddress+':'+$_.RemotePort);state=[string]$_.State} })
$run=@(); foreach($k in 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run','HKCU:\Software\Microsoft\Windows\CurrentVersion\Run','HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce'){ $r=Get-ItemProperty $k; if($r){ $r.PSObject.Properties | Where-Object {$_.Name -notlike 'PS*'} | ForEach-Object { $run+=($k.Split('\')[0]+' Run: '+$_.Name+' = '+$_.Value) } } }
$tasks=@(Get-ScheduledTask | Where-Object {$_.State -ne 'Disabled' -and $_.TaskPath -notlike '\Microsoft\*'} | ForEach-Object { 'Task: '+$_.TaskPath+$_.TaskName })
[pscustomobject]@{procs=$p;conns=$ct;persist=@($run+$tasks)} | ConvertTo-Json -Compress -Depth 4`
	out, err := secPS(ctx, 2*time.Minute, script)
	if err != nil {
		return nil, nil, nil, errors.New(firstLines(out, 300))
	}
	var raw struct {
		Procs []struct {
			PID     int
			PPID    int
			Name    string
			Path    string
			Cmdline string
		}
		Conns []struct {
			PID                  int
			Local, Remote, State string
		}
		Persist []string
	}
	if err := json.Unmarshal([]byte(strings.TrimSpace(out)), &raw); err != nil {
		return nil, nil, nil, errors.New("could not read the process list")
	}
	names := map[int]string{}
	var ps []edrProc
	for _, p := range raw.Procs {
		names[p.PID] = p.Name
		ps = append(ps, edrProc{PID: p.PID, PPID: p.PPID, Name: p.Name, Path: p.Path, Cmdline: clip(p.Cmdline, 300)})
	}
	var cs []edrConn
	for _, c := range raw.Conns {
		cs = append(cs, edrConn{PID: c.PID, Proc: names[c.PID], Local: c.Local, Remote: c.Remote, State: c.State})
	}
	return ps, cs, raw.Persist, nil
}

func clip(s string, n int) string {
	if len(s) > n {
		return s[:n] + "…"
	}
	return s
}

func edrLinux() ([]edrProc, []edrConn, []string, error) {
	ents, err := os.ReadDir("/proc")
	if err != nil {
		return nil, nil, nil, err
	}
	var ps []edrProc
	names := map[int]string{}
	for _, e := range ents {
		var pid int
		if _, err := fmt.Sscanf(e.Name(), "%d", &pid); err != nil || fmt.Sprint(pid) != e.Name() {
			continue
		}
		base := "/proc/" + e.Name()
		comm, _ := os.ReadFile(base + "/comm")
		exe, _ := os.Readlink(base + "/exe")
		cl, _ := os.ReadFile(base + "/cmdline")
		stat, _ := os.ReadFile(base + "/stat")
		ppid := 0
		if i := strings.LastIndexByte(string(stat), ')'); i > 0 {
			var st string
			fmt.Sscanf(string(stat)[i+1:], " %s %d", &st, &ppid)
		}
		name := strings.TrimSpace(string(comm))
		names[pid] = name
		ps = append(ps, edrProc{PID: pid, PPID: ppid, Name: name, Path: exe, Cmdline: clip(strings.TrimSpace(strings.ReplaceAll(string(cl), "\x00", " ")), 300)})
	}
	// Listening and established TCP sockets, mapped to processes through /proc/<pid>/fd.
	inodes := map[string]int{}
	for _, p := range ps {
		fds, _ := os.ReadDir("/proc/" + fmt.Sprint(p.PID) + "/fd")
		for _, fd := range fds {
			l, err := os.Readlink("/proc/" + fmt.Sprint(p.PID) + "/fd/" + fd.Name())
			if err == nil && strings.HasPrefix(l, "socket:[") {
				inodes[strings.TrimSuffix(strings.TrimPrefix(l, "socket:["), "]")] = p.PID
			}
		}
	}
	var cs []edrConn
	for _, f := range []string{"/proc/net/tcp", "/proc/net/tcp6"} {
		b, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		for i, l := range strings.Split(string(b), "\n") {
			fs := strings.Fields(l)
			if i == 0 || len(fs) < 10 {
				continue
			}
			state := map[string]string{"0A": "Listen", "01": "Established"}[fs[3]]
			if state == "" {
				continue
			}
			pid := inodes[fs[9]]
			cs = append(cs, edrConn{PID: pid, Proc: names[pid], Local: hexAddr(fs[1]), Remote: hexAddr(fs[2]), State: state})
		}
	}
	var persist []string
	for _, d := range []string{"/etc/cron.d", "/etc/cron.daily", "/etc/cron.hourly", "/var/spool/cron/crontabs", "/etc/systemd/system", "/etc/init.d"} {
		es, _ := os.ReadDir(d)
		for _, e := range es {
			persist = append(persist, filepath.Join(d, e.Name()))
		}
	}
	return ps, cs, persist, nil
}

func hexAddr(s string) string {
	i := strings.IndexByte(s, ':')
	if i < 0 {
		return s
	}
	var port int
	fmt.Sscanf(s[i+1:], "%X", &port)
	h := s[:i]
	if len(h) == 8 { // IPv4, little endian
		var b [4]byte
		for k := 0; k < 4; k++ {
			var v int
			fmt.Sscanf(h[k*2:k*2+2], "%02X", &v)
			b[3-k] = byte(v)
		}
		return fmt.Sprintf("%d.%d.%d.%d:%d", b[0], b[1], b[2], b[3], port)
	}
	return fmt.Sprintf("[v6]:%d", port)
}

func edrDarwin(ctx context.Context) ([]edrProc, []edrConn, []string, error) {
	out, err := secRun(ctx, time.Minute, "ps", "-axo", "pid=,ppid=,user=,comm=")
	if err != nil {
		return nil, nil, nil, err
	}
	var ps []edrProc
	for _, l := range strings.Split(out, "\n") {
		var pid, ppid int
		var user, comm string
		if n, _ := fmt.Sscanf(strings.TrimSpace(l), "%d %d %s %s", &pid, &ppid, &user, &comm); n == 4 {
			ps = append(ps, edrProc{PID: pid, PPID: ppid, User: user, Name: filepath.Base(comm), Path: comm})
		}
	}
	var cs []edrConn
	lo, _ := secRun(ctx, time.Minute, "lsof", "-nP", "-iTCP", "-sTCP:LISTEN,ESTABLISHED", "-F", "pcn")
	var cur edrConn
	for _, l := range strings.Split(lo, "\n") {
		if l == "" {
			continue
		}
		switch l[0] {
		case 'p':
			fmt.Sscanf(l[1:], "%d", &cur.PID)
		case 'c':
			cur.Proc = l[1:]
		case 'n':
			cs = append(cs, edrConn{PID: cur.PID, Proc: cur.Proc, Local: l[1:], State: "Open"})
		}
	}
	var persist []string
	for _, d := range []string{"/Library/LaunchDaemons", "/Library/LaunchAgents"} {
		es, _ := os.ReadDir(d)
		for _, e := range es {
			persist = append(persist, filepath.Join(d, e.Name()))
		}
	}
	return ps, cs, persist, nil
}

// ---------------- EDR: network isolation ----------------

// Isolation blocks all traffic except to the Helm server. It always carries an expiry: if the PC loses the
// server (or the server loses the PC) it releases itself, so isolation can never lock a machine away for good.

type isoState struct {
	Until time.Time `json:"until"`
	IPs   []string  `json:"ips"`
}

func isoFile(a *Agent) string { return filepath.Join(a.cfg.DataDir, "isolation.json") }

func isolationActive(a *Agent) bool {
	b, err := os.ReadFile(isoFile(a))
	if err != nil {
		return false
	}
	var st isoState
	return json.Unmarshal(b, &st) == nil && time.Now().Before(st.Until)
}

func (a *Agent) serverIPs() ([]string, string, error) {
	u, err := url.Parse(a.cfg.Server)
	if err != nil || u.Hostname() == "" {
		return nil, "", errors.New("server address unknown")
	}
	ips, err := net.LookupIP(u.Hostname())
	if err != nil || len(ips) == 0 {
		return nil, "", errors.New("could not resolve the Helm server: refusing to isolate")
	}
	var out []string
	for _, ip := range ips {
		if ip.To4() != nil {
			out = append(out, ip.String())
		}
	}
	if len(out) == 0 {
		return nil, "", errors.New("the Helm server has no IPv4 address: refusing to isolate")
	}
	port := u.Port()
	if port == "" {
		port = "443"
	}
	return out, port, nil
}

func (a *Agent) cmdEDRIsolate(ctx context.Context, c *cmdCtx) (any, error) {
	var args struct {
		Minutes int `json:"minutes"`
	}
	if err := decode(c.args, &args); err != nil {
		return nil, err
	}
	if args.Minutes < 5 || args.Minutes > 1440 {
		args.Minutes = 120
	}
	ips, port, err := a.serverIPs()
	if err != nil {
		return nil, err
	}
	var out string
	switch runtime.GOOS {
	case "windows":
		list := "'" + strings.Join(ips, "','") + "'"
		out, err = secPS(ctx, time.Minute, `$ErrorActionPreference='Stop'
Get-NetFirewallRule -DisplayName 'Helm isolation*' -ErrorAction SilentlyContinue | Remove-NetFirewallRule
New-NetFirewallRule -DisplayName 'Helm isolation allow out' -Direction Outbound -Action Allow -RemoteAddress `+list+` -Protocol TCP -RemotePort `+port+` | Out-Null
New-NetFirewallRule -DisplayName 'Helm isolation allow dns' -Direction Outbound -Action Allow -Protocol UDP -RemotePort 53 | Out-Null
Set-NetFirewallProfile -All -DefaultOutboundAction Block -DefaultInboundAction Block`)
	case "linux":
		if !haveBin("iptables") {
			return nil, errors.New("iptables is required for isolation on Linux")
		}
		cmds := [][]string{{"-N", "HELM_ISO"}, {"-F", "HELM_ISO"}, {"-A", "HELM_ISO", "-o", "lo", "-j", "ACCEPT"}, {"-A", "HELM_ISO", "-m", "state", "--state", "ESTABLISHED,RELATED", "-j", "ACCEPT"}, {"-A", "HELM_ISO", "-p", "udp", "--dport", "53", "-j", "ACCEPT"}}
		for _, ip := range ips {
			cmds = append(cmds, []string{"-A", "HELM_ISO", "-d", ip, "-p", "tcp", "--dport", port, "-j", "ACCEPT"})
		}
		cmds = append(cmds, []string{"-A", "HELM_ISO", "-j", "DROP"})
		for _, ca := range cmds {
			o, e := secRun(ctx, 20*time.Second, "iptables", ca...)
			if e != nil && ca[0] != "-N" {
				out, err = o, e
				break
			}
		}
		if err == nil {
			if _, e := secRun(ctx, 10*time.Second, "iptables", "-C", "OUTPUT", "-j", "HELM_ISO"); e != nil {
				out, err = secRun(ctx, 10*time.Second, "iptables", "-I", "OUTPUT", "1", "-j", "HELM_ISO")
			}
		}
	default:
		return nil, errors.New("isolation is not supported on macOS yet")
	}
	if err != nil {
		_, _ = a.releaseIsolation(ctx)
		return nil, errors.New("isolation failed and was rolled back: " + firstLines(out, 300))
	}
	st := isoState{Until: time.Now().Add(time.Duration(args.Minutes) * time.Minute), IPs: ips}
	b, _ := json.Marshal(st)
	_ = os.WriteFile(isoFile(a), b, 0o600)
	time.AfterFunc(time.Until(st.Until), func() { _, _ = a.releaseIsolation(context.Background()) })
	return map[string]any{"isolated": true, "until": st.Until.Unix(), "serverIPs": ips}, nil
}

func (a *Agent) releaseIsolation(ctx context.Context) (string, error) {
	var out string
	var err error
	switch runtime.GOOS {
	case "windows":
		out, err = secPS(ctx, time.Minute, `Get-NetFirewallRule -DisplayName 'Helm isolation*' -ErrorAction SilentlyContinue | Remove-NetFirewallRule
Set-NetFirewallProfile -All -DefaultOutboundAction Allow -DefaultInboundAction Block`)
	case "linux":
		if haveBin("iptables") {
			_, _ = secRun(ctx, 10*time.Second, "iptables", "-D", "OUTPUT", "-j", "HELM_ISO")
			_, _ = secRun(ctx, 10*time.Second, "iptables", "-F", "HELM_ISO")
			_, _ = secRun(ctx, 10*time.Second, "iptables", "-X", "HELM_ISO")
		}
	}
	_ = os.Remove(isoFile(a))
	return out, err
}

func (a *Agent) cmdEDRRelease(ctx context.Context, c *cmdCtx) (any, error) {
	if out, err := a.releaseIsolation(ctx); err != nil {
		return nil, errors.New(firstLines(out, 300))
	}
	return map[string]any{"isolated": false}, nil
}

// resumeIsolation runs at start-up: an isolation that has expired is lifted, a live one is re-armed.
func (a *Agent) resumeIsolation() {
	b, err := os.ReadFile(isoFile(a))
	if err != nil {
		return
	}
	var st isoState
	if json.Unmarshal(b, &st) != nil || !time.Now().Before(st.Until) {
		_, _ = a.releaseIsolation(context.Background())
		return
	}
	time.AfterFunc(time.Until(st.Until), func() { _, _ = a.releaseIsolation(context.Background()) })
}

// ---------------- component installation ----------------

// moduleInstall makes sure the things a module needs are on the PC: an antivirus engine for Antivirus, a firewall
// tool for EDR isolation. RMM needs nothing extra, it is the agent itself.

type compResult struct {
	Module string   `json:"module"`
	OK     bool     `json:"ok"`
	Steps  []string `json:"steps"`
	Note   string   `json:"note,omitempty"`
}

func secRunEnv(ctx context.Context, timeout time.Duration, env []string, name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env = append(os.Environ(), env...)
	hideWindow(cmd)
	out, err := cmd.CombinedOutput()
	if ctx.Err() == context.DeadlineExceeded {
		return string(out), errors.New("timed out")
	}
	return string(out), err
}

// installPackages installs distro packages with whichever package manager the machine has.
func installPackages(ctx context.Context, c *cmdCtx, debian, rpm, arch []string) (string, error) {
	env := []string{"DEBIAN_FRONTEND=noninteractive"}
	switch {
	case haveBin("apt-get"):
		c.progress("Installing " + strings.Join(debian, ", ") + " with apt")
		_, _ = secRunEnv(ctx, 5*time.Minute, env, "apt-get", "update", "-qq")
		return secRunEnv(ctx, 20*time.Minute, env, "apt-get", append([]string{"install", "-y", "-qq"}, debian...)...)
	case haveBin("dnf"):
		c.progress("Installing " + strings.Join(rpm, ", ") + " with dnf")
		return secRunEnv(ctx, 20*time.Minute, env, "dnf", append([]string{"install", "-y", "-q"}, rpm...)...)
	case haveBin("yum"):
		c.progress("Installing " + strings.Join(rpm, ", ") + " with yum")
		return secRunEnv(ctx, 20*time.Minute, env, "yum", append([]string{"install", "-y", "-q"}, rpm...)...)
	case haveBin("pacman"):
		c.progress("Installing " + strings.Join(arch, ", ") + " with pacman")
		return secRunEnv(ctx, 20*time.Minute, env, "pacman", append([]string{"-S", "--noconfirm", "--needed"}, arch...)...)
	case haveBin("zypper"):
		c.progress("Installing " + strings.Join(rpm, ", ") + " with zypper")
		return secRunEnv(ctx, 20*time.Minute, env, "zypper", append([]string{"--non-interactive", "install"}, rpm...)...)
	}
	return "", errors.New("no supported package manager found (apt, dnf, yum, pacman, zypper)")
}

func (a *Agent) cmdModuleInstall(ctx context.Context, c *cmdCtx) (any, error) {
	var args struct {
		Modules []string `json:"modules"`
	}
	if err := decode(c.args, &args); err != nil {
		return nil, err
	}
	var res []compResult
	for _, m := range args.Modules {
		r := compResult{Module: m}
		step := func(s string) { r.Steps = append(r.Steps, s); c.progress(s) }
		switch m {
		case "rmm":
			r.OK = true
			step("Remote management is part of the agent")
			if st, _ := configureWOL(ctx, c.progress); len(st) > 0 {
				r.Steps = append(r.Steps, st...)
			}
		case "av":
			r.OK = a.installAV(ctx, c, &r, step)
		case "edr":
			r.OK = a.installEDR(ctx, c, &r, step)
		default:
			continue
		}
		res = append(res, r)
	}
	return map[string]any{"components": res}, nil
}

func (a *Agent) installAV(ctx context.Context, c *cmdCtx, r *compResult, step func(string)) bool {
	switch runtime.GOOS {
	case "windows":
		out, _ := secPS(ctx, 2*time.Minute, `$s=Get-Service WinDefend -ErrorAction SilentlyContinue; if(-not $s){'missing'} elseif($s.Status -ne 'Running'){try{Start-Service WinDefend -ErrorAction Stop;'started'}catch{'stopped'}} else {'running'}`)
		switch st := strings.TrimSpace(out); st {
		case "running", "started":
			step("Microsoft Defender is present (" + st + ")")
			if rt, note := ensureDefenderRealtime(ctx); rt {
				step("Real-time protection is on")
			} else {
				step("Real-time protection is OFF: " + note)
				r.Note = note
			}
			return true
		case "missing":
			if o, err := secPS(ctx, 20*time.Minute, `if(Get-Command Install-WindowsFeature -ErrorAction SilentlyContinue){Install-WindowsFeature -Name Windows-Defender | Out-String}else{throw 'not a Windows Server system'}`); err == nil {
				step("Installed the Microsoft Defender Windows feature (a restart may be needed)")
				return true
			} else {
				r.Note = "Microsoft Defender is not installed and cannot be added on this edition. Another security product probably manages this PC: " + firstLines(o, 160)
			}
		default:
			r.Note = "Microsoft Defender is installed but will not start. Another security product probably manages this PC."
		}
		return false
	case "linux":
		if haveBin("clamscan") {
			step("ClamAV is already installed")
		} else {
			if out, err := installPackages(ctx, c, []string{"clamav", "clamav-freshclam"}, []string{"clamav", "clamav-update"}, []string{"clamav"}); err != nil {
				r.Note = "Could not install ClamAV: " + firstLines(out+err.Error(), 240)
				return false
			}
			step("Installed ClamAV")
		}
		if haveBin("systemctl") {
			_, _ = secRun(ctx, 30*time.Second, "systemctl", "stop", "clamav-freshclam")
		}
		c.progress("Downloading the first threat definitions")
		if out, err := runFreshclam(ctx); err != nil {
			r.Note = "ClamAV is installed but the first definition download failed: " + firstLines(out, 200)
			return false
		}
		step("Downloaded threat definitions")
		if haveBin("systemctl") {
			_, _ = secRun(ctx, 30*time.Second, "systemctl", "enable", "--now", "clamav-freshclam")
			step("Turned on ClamAV’s own automatic updates")
		}
		return true
	case "darwin":
		step("XProtect is built into macOS and updates itself")
		return true
	}
	r.Note = "Not supported on this system"
	return false
}

func (a *Agent) installEDR(ctx context.Context, c *cmdCtx, r *compResult, step func(string)) bool {
	switch runtime.GOOS {
	case "windows":
		step("Windows Firewall is built in: network isolation is ready")
		return true
	case "linux":
		if haveBin("iptables") {
			step("iptables is present: network isolation is ready")
			return true
		}
		if out, err := installPackages(ctx, c, []string{"iptables"}, []string{"iptables"}, []string{"iptables"}); err != nil {
			r.Note = "Could not install iptables, so network isolation is unavailable: " + firstLines(out+err.Error(), 200)
			return false
		}
		step("Installed iptables: network isolation is ready")
		return true
	}
	r.Note = "Process and network telemetry work; network isolation is not available on macOS yet"
	return true
}

// ---------------- Wake-on-LAN ----------------

// cmdWOLConfigure turns on wake-on-magic-packet on the PC's physical network cards, so Helm can wake it from another agent
// on the same network. Wi-Fi cannot do this reliably and is left alone.
func (a *Agent) cmdWOLConfigure(ctx context.Context, c *cmdCtx) (any, error) {
	steps, ok := configureWOL(ctx, c.progress)
	return map[string]any{"ok": ok, "steps": steps}, nil
}

func configureWOL(ctx context.Context, progress func(string)) ([]string, bool) {
	var steps []string
	add := func(s string) { steps = append(steps, s); progress(s) }
	ok := false
	switch runtime.GOOS {
	case "windows":
		out, err := secPS(ctx, 2*time.Minute, `$o=@();
Get-NetAdapter -Physical -ErrorAction SilentlyContinue | Where-Object { $_.Status -ne 'Not Present' -and $_.PhysicalMediaType -notmatch '802.11' } | ForEach-Object {
  $n=$_.Name
  try { Set-NetAdapterPowerManagement -Name $n -WakeOnMagicPacket Enabled -ErrorAction Stop; $o+="OK|$n|wake on magic packet is on" } catch { $o+="NO|$n|"+$_.Exception.Message }
  try { Set-NetAdapterAdvancedProperty -Name $n -DisplayName 'Wake on Magic Packet' -DisplayValue 'Enabled' -ErrorAction Stop } catch {}
}
try { Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power' -Name HiberbootEnabled -Value 0 -ErrorAction Stop; $o+="OK|Fast Startup|turned off, so the card stays powered when the PC is shut down" } catch { $o+="NO|Fast Startup|"+$_.Exception.Message }
$o -join [string][char]10`)
		if err != nil {
			add("Could not read the network cards: " + firstLines(out+err.Error(), 160))
			return steps, false
		}
		for _, l := range strings.Split(strings.TrimSpace(out), "\n") {
			p := strings.SplitN(strings.TrimSpace(l), "|", 3)
			if len(p) < 3 {
				continue
			}
			if p[0] == "OK" {
				ok = ok || p[1] != "Fast Startup"
				add(p[1] + ": " + p[2])
			} else {
				add(p[1] + ": could not change (" + firstLines(p[2], 120) + ")")
			}
		}
	case "linux":
		ents, _ := os.ReadDir("/sys/class/net")
		if !haveBin("ethtool") {
			add("Installing ethtool")
			_, _ = installPackages(ctx, &cmdCtx{progress: progress}, []string{"ethtool"}, []string{"ethtool"}, []string{"ethtool"})
		}
		for _, e := range ents {
			n := e.Name()
			if _, err := os.Stat("/sys/class/net/" + n + "/device"); err != nil {
				continue // virtual
			}
			if _, err := os.Stat("/sys/class/net/" + n + "/wireless"); err == nil {
				continue
			}
			if out, err := secRun(ctx, 20*time.Second, "ethtool", "-s", n, "wol", "g"); err != nil {
				add(n + ": this network card cannot do wake-on-LAN (" + firstLines(out, 100) + ")")
				continue
			}
			ok = true
			add(n + ": wake on magic packet is on")
			// Keep it across restarts.
			if haveBin("nmcli") {
				if con, _ := secRun(ctx, 10*time.Second, "nmcli", "-t", "-g", "GENERAL.CONNECTION", "device", "show", n); strings.TrimSpace(con) != "" {
					_, _ = secRun(ctx, 20*time.Second, "nmcli", "connection", "modify", strings.TrimSpace(con), "802-3-ethernet.wake-on-lan", "magic")
					continue
				}
			}
			link := "[Match]\nOriginalName=" + n + "\n\n[Link]\nWakeOnLan=magic\n"
			if err := os.MkdirAll("/etc/systemd/network", 0o755); err == nil {
				_ = os.WriteFile("/etc/systemd/network/50-helm-wol-"+n+".link", []byte(link), 0o644)
			}
		}
		if len(steps) == 0 {
			add("No wired network card was found")
		}
	case "darwin":
		if out, err := secRun(ctx, 20*time.Second, "pmset", "-a", "womp", "1"); err != nil {
			add("Could not turn on Wake for network access: " + firstLines(out, 120))
		} else {
			ok = true
			add("Wake for network access is on")
		}
	}
	return steps, ok
}

// runFreshclam updates ClamAV's definitions. It does not use freshclam's own log file: when that file is owned by
// another user, freshclam stops with "Problem with internal logger". If ClamAV's updater service is holding the
// lock, the service is paused for the update and started again.
func runFreshclam(ctx context.Context) (string, error) {
	run := func() (string, error) {
		return secRun(ctx, 20*time.Minute, "freshclam", "--stdout", "--log=/dev/null")
	}
	out, err := run()
	if err != nil && (strings.Contains(out, "lock") || strings.Contains(out, "already running") || strings.Contains(out, "Another process")) && haveBin("systemctl") {
		_, _ = secRun(ctx, 30*time.Second, "systemctl", "stop", "clamav-freshclam")
		out, err = run()
		_, _ = secRun(ctx, 30*time.Second, "systemctl", "start", "clamav-freshclam")
	}
	return out, err
}

// ensureDefenderRealtime switches Defender's real-time protection back on if it is off, and says whether it is on.
// Tamper protection or another security product can refuse the change; the note then says so.
func ensureDefenderRealtime(ctx context.Context) (bool, string) {
	out, _ := secPS(ctx, 90*time.Second, `try{Set-MpPreference -DisableRealtimeMonitoring $false -DisableBehaviorMonitoring $false -DisableIOAVProtection $false -DisableScriptScanning $false -ErrorAction Stop}catch{}
$s=Get-MpComputerStatus -ErrorAction SilentlyContinue
if($s -and $s.RealTimeProtectionEnabled){'on'}elseif($s){'off'}else{'unknown'}`)
	switch strings.TrimSpace(out) {
	case "on":
		return true, ""
	case "off":
		return false, "Real-time protection is off and Windows will not let Helm turn it on. Tamper protection or another security product is probably in control."
	}
	return false, "Could not read Defender's state"
}

// clamScan runs clamscan and reports progress as it goes: files scanned, the current folder and, when the files could
// be counted first, a percentage. Counting is skipped (no percentage) if it takes more than 90 seconds.
func clamScan(ctx context.Context, c *cmdCtx, cargs, targets []string, full bool) ([]string, error) {
	c.progress("Counting the files to scan")
	total := countFiles(ctx, targets, 90*time.Second)
	ctx, cancel := context.WithTimeout(ctx, 6*time.Hour)
	defer cancel()
	cmd := exec.CommandContext(ctx, "clamscan", append(cargs, targets...)...)
	hideWindow(cmd)
	pipe, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	var found []string
	n, last := 0, time.Time{}
	sc := bufio.NewScanner(pipe)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for sc.Scan() {
		l := strings.TrimSpace(sc.Text())
		if strings.HasSuffix(l, "FOUND") {
			found = append(found, l)
		}
		n++
		if time.Since(last) < time.Second {
			continue
		}
		last = time.Now()
		dir := filepath.Dir(strings.SplitN(l, ": ", 2)[0])
		msg := fmt.Sprintf("Scanned %d files", n)
		if total > 0 {
			msg = fmt.Sprintf("Scanned %d of about %d files", n, total)
		}
		if len(found) > 0 {
			msg += fmt.Sprintf(", %d threat(s) found", len(found))
		}
		msg += " · " + dir
		if total > 0 {
			p := n * 100 / total
			if p > 99 {
				p = 99
			}
			c.pct(p, msg)
		} else {
			c.progress(msg)
		}
	}
	werr := cmd.Wait()
	if werr != nil && !strings.Contains(werr.Error(), "exit status 1") && len(found) == 0 {
		return found, werr
	}
	return found, nil
}

// countFiles counts regular files under the targets, giving up (0) when it takes longer than the limit.
func countFiles(ctx context.Context, targets []string, limit time.Duration) int {
	deadline := time.Now().Add(limit)
	n := 0
	skip := map[string]bool{"/proc": true, "/sys": true, "/dev": true, "/run": true}
	for _, t := range targets {
		stop := false
		_ = filepath.WalkDir(t, func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				return nil
			}
			if time.Now().After(deadline) || ctx.Err() != nil {
				stop = true
				return filepath.SkipAll
			}
			if d.IsDir() && skip[p] {
				return filepath.SkipDir
			}
			if d.Type().IsRegular() {
				n++
			}
			return nil
		})
		if stop {
			return 0
		}
	}
	return n
}
