//go:build !windows

package agent

// Native macOS implementations. They return the same JSON shapes as the Windows scripts and the Linux
// handlers, so the console needs no macOS-specific pages. The code only shells out to tools every Mac ships
// with (sysctl, sw_vers, system_profiler, ps, launchctl, softwareupdate, lsof, log, pmset, ...) and the parsers
// are plain functions so they are unit-tested on any platform. It has not been run on a real Mac by the
// developers of this repository: see docs/MACOS.md.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"helm/internal/proto"
)

func macSysctl(ctx context.Context, key string) string {
	out, _ := lrun(ctx, 5*time.Second, nil, "sysctl", "-n", key)
	return out
}

func macOSInfo() (string, string) {
	ctx := context.Background()
	v, _ := lrun(ctx, 5*time.Second, nil, "sw_vers", "-productVersion")
	b, _ := lrun(ctx, 5*time.Second, nil, "sw_vers", "-buildVersion")
	return "macOS " + v, b
}

// ---- stats ----

var reTopCPU = regexp.MustCompile(`CPU usage:\s*([\d.]+)% user,\s*([\d.]+)% sys`)

func parseTopCPU(s string) float64 {
	m := reTopCPU.FindStringSubmatch(s)
	if m == nil {
		return 0
	}
	u, _ := strconv.ParseFloat(m[1], 64)
	sy, _ := strconv.ParseFloat(m[2], 64)
	return u + sy
}

// parseVMStat returns used memory in bytes: everything except free, speculative and inactive pages.
func parseVMStat(s string, total uint64) uint64 {
	page := uint64(16384)
	if m := regexp.MustCompile(`page size of (\d+) bytes`).FindStringSubmatch(s); m != nil {
		page, _ = strconv.ParseUint(m[1], 10, 64)
	}
	counts := map[string]uint64{}
	for _, ln := range strings.Split(s, "\n") {
		k, v, ok := strings.Cut(ln, ":")
		if !ok {
			continue
		}
		n, _ := strconv.ParseUint(strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(v), ".")), 10, 64)
		counts[strings.TrimSpace(k)] = n
	}
	avail := (counts["Pages free"] + counts["Pages inactive"] + counts["Pages speculative"] + counts["Pages purgeable"]) * page
	if avail > total {
		return 0
	}
	return total - avail
}

func macStats() proto.Stats {
	ctx := context.Background()
	var st proto.Stats
	if out, err := lrun(ctx, 10*time.Second, nil, "top", "-l", "2", "-n", "0", "-s", "1"); err == nil {
		// the second sample is the live one
		if i := strings.LastIndex(out, "CPU usage:"); i >= 0 {
			st.CPU = parseTopCPU(out[i:])
		}
	}
	st.MemTotal, _ = strconv.ParseUint(macSysctl(ctx, "hw.memsize"), 10, 64)
	if vm, err := lrun(ctx, 5*time.Second, nil, "vm_stat"); err == nil {
		st.MemUsed = parseVMStat(vm, st.MemTotal)
	}
	if bt := macSysctl(ctx, "kern.boottime"); bt != "" { // { sec = 1700000000, usec = 0 } ...
		if m := regexp.MustCompile(`sec = (\d+)`).FindStringSubmatch(bt); m != nil {
			s, _ := strconv.ParseInt(m[1], 10, 64)
			if s > 0 {
				st.UptimeSec = uint64(time.Now().Unix() - s)
			}
		}
	}
	for _, mp := range macMounts() {
		var fs syscall.Statfs_t
		if syscall.Statfs(mp, &fs) == nil && fs.Blocks > 0 {
			st.Disks = append(st.Disks, proto.Disk{Name: mp, Total: fs.Blocks * uint64(fs.Bsize), Free: fs.Bavail * uint64(fs.Bsize)})
		}
	}
	st.User, st.UserPresent = macLoggedOnUser()
	return st
}

func macMounts() []string {
	out := []string{"/"}
	if ents, err := os.ReadDir("/Volumes"); err == nil {
		for _, e := range ents {
			p := "/Volumes/" + e.Name()
			if fi, err := os.Lstat(p); err == nil && fi.Mode()&os.ModeSymlink == 0 {
				out = append(out, p)
			}
		}
	}
	return out
}

// macConsoleUser is the user logged in at the screen ("" when at the login window).
func macConsoleUser() string {
	out, err := lrun(context.Background(), 3*time.Second, nil, "stat", "-f", "%Su", "/dev/console")
	if err != nil || out == "root" || out == "loginwindow" {
		return ""
	}
	return out
}

func macLoggedOnUser() (string, bool) {
	u := macConsoleUser()
	return u, u != ""
}

// ---- inventory ----

type spHardware struct {
	Items []map[string]any `json:"SPHardwareDataProvider"`
}

func spJSON(ctx context.Context, dtype string, v any) error {
	out, err := lrun(ctx, 3*time.Minute, nil, "system_profiler", dtype, "-json", "-detailLevel", "mini")
	if err != nil && out == "" {
		return err
	}
	return json.Unmarshal([]byte(out), v)
}

func str(m map[string]any, k string) string {
	if v, ok := m[k]; ok && v != nil {
		return fmt.Sprint(v)
	}
	return ""
}

func (a *Agent) macInventory(ctx context.Context) (any, error) {
	host, _ := os.Hostname()
	var hw spHardware
	_ = spJSON(ctx, "SPHardwareDataProvider", &hw)
	h := map[string]any{}
	if len(hw.Items) > 0 {
		h = hw.Items[0]
	}
	ver, build := macOSInfo()
	cpu := firstNonEmpty(str(h, "chip_type"), str(h, "cpu_type"), macSysctl(ctx, "machdep.cpu.brand_string"))
	cores, _ := strconv.Atoi(macSysctl(ctx, "hw.physicalcpu"))
	threads, _ := strconv.Atoi(macSysctl(ctx, "hw.logicalcpu"))
	ram, _ := strconv.ParseUint(macSysctl(ctx, "hw.memsize"), 10, 64)
	var lastBoot any
	if m := regexp.MustCompile(`sec = (\d+)`).FindStringSubmatch(macSysctl(ctx, "kern.boottime")); m != nil {
		s, _ := strconv.ParseInt(m[1], 10, 64)
		lastBoot = time.Unix(s, 0).UTC().Format(time.RFC3339)
	}
	type nic struct {
		Description string   `json:"description"`
		MAC         string   `json:"mac"`
		IPs         []string `json:"ips"`
		DNS         []string `json:"dns"`
	}
	var nics []nic
	for _, n := range linuxNICs() {
		nics = append(nics, n)
	}
	var disks []map[string]any
	var sd struct {
		Items []map[string]any `json:"SPStorageDataProvider"`
	}
	if spJSON(ctx, "SPStorageDataProvider", &sd) == nil {
		for _, it := range sd.Items {
			sz, _ := strconv.ParseFloat(str(it, "size_in_bytes"), 64)
			disks = append(disks, map[string]any{"model": firstNonEmpty(str(it, "_name"), "Volume"), "sizeBytes": int64(sz)})
		}
	}
	return map[string]any{
		"computerName": host, "domain": "", "partOfDomain": false,
		"manufacturer": "Apple", "model": firstNonEmpty(str(h, "machine_name"), str(h, "machine_model")) + " " + str(h, "machine_model"),
		"serial": str(h, "serial_number"), "biosVersion": firstNonEmpty(str(h, "boot_rom_version"), str(h, "os_loader_version")),
		"osCaption": ver, "osVersion": strings.TrimPrefix(ver, "macOS "), "osBuild": build, "osArch": goArch(),
		"lastBoot": lastBoot, "cpu": cpu, "cores": cores, "threads": threads, "ramBytes": ram, "gpu": []string{},
		"disks": disks, "network": nics, "antivirus": []string{}, "defender": nil,
		"firewall": []map[string]any{{"name": "Application Firewall", "enabled": macFirewallOn(ctx)}},
		"timezone": macTimezone(), "pendingReboot": false,
	}, nil
}

func goArch() string {
	if a, err := exec.LookPath("uname"); err == nil {
		if out, err := exec.Command(a, "-m").Output(); err == nil {
			return strings.TrimSpace(string(out))
		}
	}
	return ""
}

func macTimezone() string {
	if p, err := os.Readlink("/etc/localtime"); err == nil {
		if i := strings.Index(p, "zoneinfo/"); i >= 0 {
			return p[i+len("zoneinfo/"):]
		}
	}
	return ""
}

const socketfilterfw = "/usr/libexec/ApplicationFirewall/socketfilterfw"

func macFirewallOn(ctx context.Context) bool {
	out, _ := lrun(ctx, 5*time.Second, nil, socketfilterfw, "--getglobalstate")
	return strings.Contains(strings.ToLower(out), "enabled") && !strings.Contains(strings.ToLower(out), "disabled")
}

// ---- software ----

type macApp struct {
	Name, Version, Publisher, Path string
}

func parseApplications(js []byte) ([]macApp, error) {
	var r struct {
		Items []map[string]any `json:"SPApplicationsDataProvider"`
	}
	if err := json.Unmarshal(js, &r); err != nil {
		return nil, err
	}
	var apps []macApp
	for _, it := range r.Items {
		name := str(it, "_name")
		if name == "" {
			continue
		}
		pub := str(it, "obtained_from")
		switch pub {
		case "apple":
			pub = "Apple"
		case "mac_app_store":
			pub = "Mac App Store"
		case "identified_developer", "unknown":
			pub = ""
		}
		if sb, ok := it["signed_by"].([]any); ok && len(sb) > 0 && (pub == "" || pub == "Mac App Store") {
			pub = strings.TrimPrefix(strings.SplitN(fmt.Sprint(sb[0]), ",", 2)[0], "Developer ID Application: ")
		}
		apps = append(apps, macApp{Name: name, Version: str(it, "version"), Publisher: pub, Path: str(it, "path")})
	}
	return apps, nil
}

func (a *Agent) macSoftware(ctx context.Context, scan bool) (any, error) {
	out, err := lrun(ctx, 5*time.Minute, nil, "system_profiler", "SPApplicationsDataProvider", "-json")
	if err != nil && out == "" {
		return nil, err
	}
	apps, err := parseApplications([]byte(out))
	if err != nil {
		return nil, err
	}
	res := make([]map[string]any, 0, len(apps))
	for _, ap := range apps {
		item := map[string]any{"name": ap.Name, "version": ap.Version, "publisher": ap.Publisher, "installDate": ""}
		if scan {
			item["scope"] = "machine"
		}
		res = append(res, item)
	}
	return res, nil
}

// ---- processes / services ----

func parsePS(out string) []map[string]any {
	res := []map[string]any{}
	for _, ln := range strings.Split(out, "\n") {
		f := strings.Fields(ln)
		if len(f) < 5 {
			continue
		}
		pid, err := strconv.Atoi(f[0])
		if err != nil {
			continue
		}
		cpu, _ := strconv.ParseFloat(f[1], 64)
		rss, _ := strconv.ParseFloat(f[2], 64)
		path := strings.Join(f[4:], " ")
		res = append(res, map[string]any{"pid": pid, "name": filepath.Base(path), "cpu": cpu, "memMB": float64(int(rss/1024*10)) / 10, "user": f[3], "path": path})
	}
	return res
}

func (a *Agent) macProcesses(ctx context.Context) (any, error) {
	out, err := lrun(ctx, 20*time.Second, nil, "ps", "-axo", "pid=,pcpu=,rss=,user=,comm=")
	if err != nil && out == "" {
		return nil, err
	}
	return parsePS(out), nil
}

func parseLaunchctlList(out string) []map[string]any {
	res := []map[string]any{}
	for i, ln := range strings.Split(out, "\n") {
		f := strings.Fields(ln)
		if i == 0 || len(f) < 3 { // header: PID Status Label
			continue
		}
		state := "Stopped"
		if f[0] != "-" {
			state = "Running"
		} else if code, _ := strconv.Atoi(f[1]); code != 0 {
			state = "Failed"
		}
		res = append(res, map[string]any{"name": f[2], "display": f[2], "state": state, "start": "Auto", "account": ""})
	}
	return res
}

func (a *Agent) macServices(ctx context.Context) (any, error) {
	out, err := lrun(ctx, time.Minute, nil, "launchctl", "list")
	if err != nil {
		return nil, errors.New("launchctl is not available")
	}
	list := parseLaunchctlList(out)
	// mark disabled system jobs
	if dis, err := lrun(ctx, 20*time.Second, nil, "launchctl", "print-disabled", "system"); err == nil {
		off := map[string]bool{}
		for _, ln := range strings.Split(dis, "\n") {
			if m := regexp.MustCompile(`"([^"]+)"\s*=>\s*(true|disabled)`).FindStringSubmatch(ln); m != nil {
				off[m[1]] = true
			}
		}
		for _, it := range list {
			if off[it["name"].(string)] {
				it["start"] = "Disabled"
			}
		}
	}
	return list, nil
}

var reLabel = regexp.MustCompile(`^[A-Za-z0-9_.@-]{1,200}$`)

func (a *Agent) macServiceControl(ctx context.Context, c *cmdCtx) (any, error) {
	var args struct{ Name, Action string }
	if err := decode(c.args, &args); err != nil {
		return nil, err
	}
	if !reLabel.MatchString(args.Name) || strings.HasPrefix(args.Name, "-") {
		return nil, errors.New("bad service name")
	}
	target := "system/" + args.Name
	var sub []string
	switch args.Action {
	case "start":
		sub = []string{"kickstart", target}
	case "restart":
		sub = []string{"kickstart", "-k", target}
	case "stop":
		sub = []string{"kill", "SIGTERM", target}
	case "auto":
		sub = []string{"enable", target}
	case "manual", "disable":
		sub = []string{"disable", target}
	default:
		return nil, errors.New("bad action")
	}
	if _, err := lrun(ctx, 2*time.Minute, nil, "launchctl", sub...); err != nil {
		return nil, err
	}
	return map[string]string{"name": args.Name, "status": "Requested", "startType": args.Action}, nil
}

// ---- event log ----

func (a *Agent) macEventLog(ctx context.Context, c *cmdCtx) (any, error) {
	args := struct {
		Log   string `json:"log"`
		Level string `json:"level"`
		Count int    `json:"count"`
	}{Log: "System", Level: "warnings", Count: 50}
	if err := decode(c.args, &args); err != nil {
		return nil, err
	}
	pred := map[string]string{"errors": "messageType == error OR messageType == fault", "warnings": "messageType == error OR messageType == fault", "all": "messageType != debug"}[args.Level]
	if pred == "" {
		return nil, errors.New("level must be errors, warnings or all")
	}
	if args.Count < 1 || args.Count > 300 {
		args.Count = 50
	}
	switch args.Log {
	case "System":
	case "Application":
		pred = "(" + pred + ") AND senderImagePath CONTAINS \"/Applications/\""
	case "Security":
		pred = "(" + pred + ") AND (subsystem == \"com.apple.securityd\" OR process == \"sudo\" OR process == \"sshd\" OR process == \"authd\")"
	case "Setup":
		pred = "(" + pred + ") AND process == \"softwareupdated\""
	default:
		return nil, errors.New("log must be System, Application, Security or Setup")
	}
	out, err := lrun(ctx, 2*time.Minute, nil, "log", "show", "--last", "6h", "--style", "ndjson", "--predicate", pred)
	if err != nil && out == "" {
		return nil, err
	}
	return parseLogNDJSON(out, args.Count), nil
}

func parseLogNDJSON(out string, count int) []map[string]any {
	res := []map[string]any{}
	for _, ln := range strings.Split(out, "\n") {
		var e map[string]any
		if json.Unmarshal([]byte(ln), &e) != nil {
			continue
		}
		lvl := map[string]string{"Error": "Error", "Fault": "Critical", "Default": "Info", "Info": "Info"}[str(e, "messageType")]
		if lvl == "" {
			lvl = "Info"
		}
		msg := str(e, "eventMessage")
		if len(msg) > 600 {
			msg = msg[:600]
		}
		ts := str(e, "timestamp")
		if t, err := time.Parse("2006-01-02 15:04:05.000000-0700", ts); err == nil {
			ts = t.UTC().Format(time.RFC3339)
		}
		res = append(res, map[string]any{"time": ts, "id": 0, "provider": firstNonEmpty(str(e, "process"), str(e, "subsystem")), "level": lvl, "message": msg})
	}
	sort.SliceStable(res, func(i, j int) bool { return res[i]["time"].(string) > res[j]["time"].(string) })
	if len(res) > count {
		res = res[:count]
	}
	return res
}

// ---- updates ----

type macUpdate struct {
	Label, Title, Version, Size string
	Restart, Recommended        bool
}

// parseSoftwareUpdate understands both layouts of `softwareupdate -l`:
//
//   - Label: macOS Sonoma 14.5-23F79
//     Title: macOS Sonoma 14.5, Version: 14.5, Size: 1234567KiB, Recommended: YES, Action: restart,
//
// and the older
//
//   - macOS Ventura 13.4-22F66
//     macOS Ventura (13.4), 1234K [recommended] [restart]
func parseSoftwareUpdate(out string) []macUpdate {
	var list []macUpdate
	for _, ln := range strings.Split(out, "\n") {
		t := strings.TrimSpace(ln)
		switch {
		case strings.HasPrefix(t, "* Label: "):
			list = append(list, macUpdate{Label: strings.TrimPrefix(t, "* Label: ")})
		case strings.HasPrefix(t, "* "):
			list = append(list, macUpdate{Label: strings.TrimPrefix(t, "* ")})
		case len(list) > 0 && t != "":
			cur := &list[len(list)-1]
			if strings.Contains(t, "Title:") {
				for _, part := range strings.Split(t, ", ") {
					k, v, _ := strings.Cut(part, ": ")
					v = strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(v), ","))
					switch strings.TrimSpace(k) {
					case "Title":
						cur.Title = v
					case "Version":
						cur.Version = v
					case "Size":
						cur.Size = v
					case "Recommended":
						cur.Recommended = v == "YES"
					case "Action":
						cur.Restart = strings.Contains(v, "restart")
					}
				}
			} else if cur.Title == "" && !strings.HasPrefix(t, "Software Update") && !strings.HasPrefix(t, "Finding") {
				cur.Title = t
				cur.Recommended = strings.Contains(t, "[recommended]")
				cur.Restart = strings.Contains(t, "[restart]")
			}
		}
	}
	return list
}

func (a *Agent) macUpdatesCheck(ctx context.Context, c *cmdCtx) (any, error) {
	out, err := lrun(ctx, 10*time.Minute, nil, "softwareupdate", "-l")
	if err != nil && out == "" {
		return nil, err
	}
	list := []map[string]any{}
	for _, u := range parseSoftwareUpdate(out) {
		sev := ""
		if u.Recommended {
			sev = "Important"
		}
		list = append(list, map[string]any{"id": u.Label, "title": firstNonEmpty(u.Title, u.Label) + " " + u.Version, "kb": []string{}, "sizeMB": 0,
			"severity": sev, "needsReboot": u.Restart, "downloaded": false, "categories": []string{"Updates"}})
	}
	return map[string]any{"updates": list, "rebootPending": false}, nil
}

func (a *Agent) macUpdatesInstall(ctx context.Context, c *cmdCtx) (any, error) {
	var args struct {
		IDs    []string `json:"ids"`
		Reboot bool     `json:"reboot"`
	}
	if err := decode(c.args, &args); err != nil {
		return nil, err
	}
	for _, id := range args.IDs {
		if strings.TrimSpace(id) == "" || len(id) > 200 || strings.HasPrefix(id, "-") || strings.ContainsAny(id, "\r\n\x00") {
			return nil, errors.New("bad update label")
		}
	}
	argv := []string{"-i"}
	if len(args.IDs) == 0 {
		argv = []string{"-i", "-r"} // all recommended
	} else {
		argv = append(argv, args.IDs...)
	}
	if args.Reboot {
		argv = append(argv, "-R")
	}
	c.progress("Installing updates…")
	out, err := lrun(ctx, 2*time.Hour, nil, "softwareupdate", argv...)
	res := map[string]any{"output": firstLines(out, 4000), "rebootNeeded": strings.Contains(out, "restart")}
	if err != nil {
		return res, err
	}
	return res, nil
}

// ---- package install ----

func (a *Agent) macPkgInstall(ctx context.Context, path string) (map[string]any, error) {
	out, err := lrun(ctx, 60*time.Minute, nil, "installer", "-pkg", path, "-target", "/")
	res := map[string]any{"exitCode": 0, "output": firstLines(out, 4000)}
	if err != nil {
		res["exitCode"] = 1
		return res, fmt.Errorf("installer failed: %w", err)
	}
	return res, nil
}

// ---- scans ----

// parseLsof reads `lsof -nP -iTCP -sTCP:LISTEN -iUDP` output.
func parseLsof(out string) []map[string]any {
	res := []map[string]any{}
	seen := map[string]bool{}
	for _, ln := range strings.Split(out, "\n") {
		f := strings.Fields(ln)
		if len(f) < 9 || f[0] == "COMMAND" {
			continue
		}
		pid, _ := strconv.Atoi(f[1])
		proto := strings.ToLower(f[7])
		if proto != "tcp" && proto != "udp" {
			continue
		}
		addr := f[8]
		if i := strings.Index(addr, "->"); i >= 0 { // established: not a listener
			continue
		}
		i := strings.LastIndex(addr, ":")
		if i < 0 {
			continue
		}
		host, port := strings.Trim(addr[:i], "[]"), addr[i+1:]
		pn, err := strconv.Atoi(port)
		if err != nil {
			continue
		}
		if host == "*" || host == "" {
			host = "0.0.0.0"
		}
		key := proto + host + port
		if seen[key] {
			continue
		}
		seen[key] = true
		res = append(res, map[string]any{"proto": proto, "address": host, "port": pn, "pid": pid, "process": strings.ReplaceAll(f[0], `\x20`, " ")})
	}
	sort.Slice(res, func(i, j int) bool { return res[i]["port"].(int) < res[j]["port"].(int) })
	return res
}

func (a *Agent) macScanPorts(ctx context.Context) (any, error) {
	out, err := lrun(ctx, time.Minute, nil, "lsof", "-nP", "-iTCP", "-sTCP:LISTEN", "-iUDP")
	if err != nil && out == "" {
		return nil, errors.New("lsof is not available")
	}
	return parseLsof(out), nil
}

func (a *Agent) macScanConfig(ctx context.Context) (any, error) {
	var checks []map[string]any
	add := func(id, title, cat, sev string, ok bool, pass, fail, fix string) {
		st, detail, f := "pass", pass, ""
		if !ok {
			st, detail, f = "fail", fail, fix
		}
		checks = append(checks, map[string]any{"id": id, "title": title, "category": cat, "severity": sev, "status": st, "detail": detail, "fix": f})
	}
	add("firewall", "Application firewall enabled", "Network", "high", macFirewallOn(ctx),
		"The macOS application firewall is on.", "The macOS application firewall is off.", "System Settings → Network → Firewall → turn it on.")
	fv, _ := lrun(ctx, 10*time.Second, nil, "fdesetup", "status")
	add("filevault", "Disk encrypted (FileVault)", "Data protection", "high", strings.Contains(fv, "FileVault is On"),
		"FileVault disk encryption is on.", "FileVault is not enabled: the disk can be read if the Mac is lost or stolen.", "System Settings → Privacy & Security → FileVault → Turn On.")
	sip, _ := lrun(ctx, 10*time.Second, nil, "csrutil", "status")
	add("sip", "System Integrity Protection enabled", "System", "high", strings.Contains(sip, "enabled"),
		"System Integrity Protection is enabled.", "System Integrity Protection is disabled.", "Boot to Recovery and run 'csrutil enable'.")
	gk, _ := lrun(ctx, 10*time.Second, nil, "spctl", "--status")
	add("gatekeeper", "Gatekeeper enabled", "Malware protection", "high", strings.Contains(gk, "enabled"),
		"Gatekeeper checks apps before they run.", "Gatekeeper is disabled: unsigned apps can run unchecked.", "Run 'sudo spctl --master-enable'.")
	auto, _ := lrun(ctx, 5*time.Second, nil, "defaults", "read", "/Library/Preferences/com.apple.SoftwareUpdate", "AutomaticCheckEnabled")
	add("autoupdate", "Automatic update checks on", "Patching", "medium", strings.TrimSpace(auto) != "0",
		"macOS checks for updates automatically.", "Automatic update checks are off.", "System Settings → General → Software Update → Automatic updates.")
	if rl, err := lrun(ctx, 10*time.Second, nil, "systemsetup", "-getremotelogin"); err == nil {
		add("ssh", "Remote Login (SSH) off unless needed", "Network", "medium", !strings.Contains(strings.ToLower(rl), "on"),
			"Remote Login is off.", "Remote Login (SSH) is on.", "Turn it off in System Settings → General → Sharing if you do not use it.")
	}
	guest, _ := lrun(ctx, 5*time.Second, nil, "defaults", "read", "/Library/Preferences/com.apple.loginwindow", "GuestEnabled")
	add("guest", "Guest account disabled", "Accounts", "medium", strings.TrimSpace(guest) != "1",
		"The guest account is disabled.", "The guest account is enabled.", "System Settings → Users & Groups → Guest User → off.")
	return map[string]any{"checks": checks, "computer": hostName(), "os": func() string { v, _ := macOSInfo(); return v }()}, nil
}

func hostName() string { h, _ := os.Hostname(); return h }

// ---- power / message / lifecycle ----

func macPower(p proto.PowerArgs) error {
	ctx := context.Background()
	mins := (p.Delay + 59) / 60
	switch p.Action {
	case "shutdown", "restart":
		flag := "-h"
		if p.Action == "restart" {
			flag = "-r"
		}
		when := "now"
		if p.Delay > 0 {
			when = "+" + strconv.Itoa(mins)
		}
		args := []string{flag, when}
		if p.Message != "" {
			args = append(args, p.Message)
		}
		_, err := lrun(ctx, 20*time.Second, nil, "shutdown", args...)
		return err
	case "sleep", "hibernate":
		_, err := lrun(ctx, 20*time.Second, nil, "pmset", "sleepnow")
		return err
	case "lock":
		// Putting the display to sleep locks the screen when "require password" is set (the managed default).
		_, err := lrun(ctx, 20*time.Second, nil, "pmset", "displaysleepnow")
		return err
	case "logoff":
		u := macConsoleUser()
		if u == "" {
			return errors.New("nobody is logged in")
		}
		uid, _ := lrun(ctx, 5*time.Second, nil, "id", "-u", u)
		_, err := lrun(ctx, 20*time.Second, nil, "launchctl", "bootout", "gui/"+uid)
		return err
	case "cancel":
		_, err := lrun(ctx, 10*time.Second, nil, "pkill", "shutdown")
		return err
	}
	return errors.New("unknown power action")
}

func macMessage(title, text string) error {
	u := macConsoleUser()
	if u == "" {
		return errors.New("nobody is logged in to show the message to")
	}
	uid, _ := lrun(context.Background(), 5*time.Second, nil, "id", "-u", u)
	script := "display dialog " + appleString(text) + " with title " + appleString(title) + " buttons {\"OK\"} default button \"OK\" giving up after 300"
	_, err := lrun(context.Background(), 20*time.Second, nil, "launchctl", "asuser", uid, "osascript", "-e", script)
	return err
}

func appleString(s string) string {
	s = strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`, "\r", "").Replace(s)
	return `"` + s + `"`
}

func macUninstall() error {
	script := `sleep 3
launchctl bootout system/com.helm.agent 2>/dev/null
rm -f /Library/LaunchDaemons/com.helm.agent.plist /usr/local/bin/helm-agent
rm -rf "/Library/Application Support/Helm"
pkgutil --forget com.helm.agent 2>/dev/null
exit 0`
	cmd := exec.Command("sh", "-c", script)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	return cmd.Start()
}

// macHandlers replaces the Windows-script based handlers on a real Mac.
func (a *Agent) macHandlers(m map[string]handlerFn) {
	unsupported := func(what string) handlerFn {
		return func(ctx context.Context, c *cmdCtx) (any, error) {
			return nil, errors.New(what + " is not available on macOS")
		}
	}
	wrap := func(f func(context.Context) (any, error)) handlerFn {
		return func(ctx context.Context, c *cmdCtx) (any, error) { return f(ctx) }
	}
	m["inventory"] = wrap(a.macInventory)
	m["software.list"] = func(ctx context.Context, c *cmdCtx) (any, error) { return a.macSoftware(ctx, false) }
	m["scan.software"] = func(ctx context.Context, c *cmdCtx) (any, error) { return a.macSoftware(ctx, true) }
	m["process.list"] = wrap(a.macProcesses)
	m["service.list"] = wrap(a.macServices)
	m["service.control"] = a.macServiceControl
	m["eventlog"] = a.macEventLog
	m["updates.check"] = a.macUpdatesCheck
	m["updates.install"] = a.macUpdatesInstall
	m["scan.ports"] = wrap(a.macScanPorts)
	m["scan.config"] = wrap(a.macScanConfig)
	m["winget.list"] = unsupported("winget")
	m["winget.upgrade"] = unsupported("winget")
	m["winget.install"] = unsupported("Installing from a package manager (upload a .pkg under Software to deploy apps)")
	m["winget.uninstall"] = unsupported("Removing software remotely")
	m["rdp.status"] = func(ctx context.Context, c *cmdCtx) (any, error) {
		return map[string]any{"enabled": false, "port": 0, "nla": false, "edition": "macOS", "supported": false, "service": "n/a"}, nil
	}
	m["rdp.enable"] = unsupported("Remote Desktop")
	m["rdp.disable"] = unsupported("Remote Desktop")
}
