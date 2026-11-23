//go:build !windows

package agent

// Native Linux implementations (Debian/Ubuntu/Raspberry Pi OS, systemd). They return the same JSON shapes as the
// Windows PowerShell scripts so the console works unchanged. Nothing here runs on Windows; on other Unixes and in
// the test-suite (HELM_FIXTURES=1) the development fixtures in plat_other.go are used instead.

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"helm/internal/proto"
)

// realLinux reports whether the agent runs on a real Linux host (not the fixture-driven test mode).

// run executes a command and returns its trimmed stdout (stderr only on failure).
func lrun(ctx context.Context, timeout time.Duration, env []string, name string, args ...string) (string, error) {
	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	cmd := exec.CommandContext(cctx, name, args...)
	cmd.Env = append(os.Environ(), env...)
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	err := cmd.Run()
	if err != nil {
		return strings.TrimSpace(out.String()), fmt.Errorf("%s: %v %s", name, err, firstLines(errb.String(), 300))
	}
	return strings.TrimSpace(out.String()), nil
}

func readFile(p string) string { b, _ := os.ReadFile(p); return strings.TrimSpace(string(b)) }

func osRelease() map[string]string {
	m := map[string]string{}
	for _, ln := range strings.Split(readFile("/etc/os-release"), "\n") {
		if k, v, ok := strings.Cut(ln, "="); ok {
			m[k] = strings.Trim(v, `"'`)
		}
	}
	return m
}

func linuxOSInfo() (string, string) {
	m := osRelease()
	name := m["PRETTY_NAME"]
	if name == "" {
		name = "Linux"
	}
	return name, "kernel " + strings.Fields(strings.ReplaceAll(readFile("/proc/sys/kernel/osrelease"), "-", " "))[0]
}

// ---- stats ----

var cpuPrev struct {
	sync.Mutex
	busy, total uint64
}

func cpuTimes() (busy, total uint64) {
	f := strings.Fields(strings.SplitN(readFile("/proc/stat"), "\n", 2)[0])
	if len(f) < 5 {
		return
	}
	for i, v := range f[1:] {
		n, _ := strconv.ParseUint(v, 10, 64)
		total += n
		if i != 3 && i != 4 { // idle, iowait
			busy += n
		}
	}
	return
}

func linuxStats() proto.Stats {
	var st proto.Stats
	b, t := cpuTimes()
	cpuPrev.Lock()
	if cpuPrev.total != 0 && t > cpuPrev.total {
		st.CPU = float64(b-cpuPrev.busy) / float64(t-cpuPrev.total) * 100
	}
	cpuPrev.busy, cpuPrev.total = b, t
	cpuPrev.Unlock()
	mem := map[string]uint64{}
	for _, ln := range strings.Split(readFile("/proc/meminfo"), "\n") {
		if k, v, ok := strings.Cut(ln, ":"); ok {
			n, _ := strconv.ParseUint(strings.Fields(v + " 0")[0], 10, 64)
			mem[k] = n << 10
		}
	}
	st.MemTotal = mem["MemTotal"]
	if mem["MemAvailable"] <= st.MemTotal {
		st.MemUsed = st.MemTotal - mem["MemAvailable"]
	}
	if f := strings.Fields(readFile("/proc/uptime")); len(f) > 0 {
		u, _ := strconv.ParseFloat(f[0], 64)
		st.UptimeSec = uint64(u)
	}
	for _, mp := range linuxMounts() {
		var fs syscall.Statfs_t
		if syscall.Statfs(mp, &fs) == nil && fs.Blocks > 0 {
			st.Disks = append(st.Disks, proto.Disk{Name: mp, Total: fs.Blocks * uint64(fs.Bsize), Free: fs.Bavail * uint64(fs.Bsize)})
		}
	}
	st.User, st.UserPresent = linuxLoggedOnUser()
	return st
}

var realFS = map[string]bool{"ext2": true, "ext3": true, "ext4": true, "xfs": true, "btrfs": true, "vfat": true, "f2fs": true, "zfs": true, "exfat": true, "ntfs": true, "ntfs3": true}

func linuxMounts() []string {
	seen := map[string]bool{}
	var out []string
	for _, ln := range strings.Split(readFile("/proc/mounts"), "\n") {
		f := strings.Fields(ln)
		if len(f) >= 3 && realFS[f[2]] && !seen[f[1]] && !strings.HasPrefix(f[1], "/var/lib/docker") && !strings.HasPrefix(f[1], "/snap") {
			seen[f[1]] = true
			out = append(out, strings.ReplaceAll(f[1], `\040`, " "))
		}
	}
	if len(out) == 0 {
		out = []string{"/"}
	}
	return out
}

func linuxLoggedOnUser() (string, bool) {
	out, err := lrun(context.Background(), 3*time.Second, nil, "who")
	if err != nil || out == "" {
		return "", false
	}
	return strings.Fields(strings.SplitN(out, "\n", 2)[0])[0], true
}

// ---- inventory / processes / services ----

func (a *Agent) linuxInventory(ctx context.Context) (any, error) {
	host, _ := os.Hostname()
	m := osRelease()
	cpuModel, threads, cores := "", 0, map[string]bool{}
	var phys string
	for _, ln := range strings.Split(readFile("/proc/cpuinfo"), "\n") {
		k, v, _ := strings.Cut(ln, ":")
		k, v = strings.TrimSpace(k), strings.TrimSpace(v)
		switch k {
		case "model name", "Model", "Hardware":
			if cpuModel == "" || k == "model name" {
				cpuModel = v
			}
		case "processor":
			threads++
		case "physical id":
			phys = v
		case "core id":
			cores[phys+"/"+v] = true
		}
	}
	nc := len(cores)
	if nc == 0 {
		nc = threads
	}
	var ramBytes uint64
	for _, ln := range strings.Split(readFile("/proc/meminfo"), "\n") {
		if strings.HasPrefix(ln, "MemTotal:") {
			n, _ := strconv.ParseUint(strings.Fields(ln)[1], 10, 64)
			ramBytes = n << 10
		}
	}
	type nic struct {
		Description string   `json:"description"`
		MAC         string   `json:"mac"`
		IPs         []string `json:"ips"`
		DNS         []string `json:"dns"`
	}
	var nics []nic
	macs, _ := netInfo()
	_ = macs
	for _, n := range linuxNICs() {
		nics = append(nics, n)
	}
	var disks []map[string]any
	if ents, err := os.ReadDir("/sys/block"); err == nil {
		for _, e := range ents {
			n := e.Name()
			if strings.HasPrefix(n, "loop") || strings.HasPrefix(n, "ram") || strings.HasPrefix(n, "zram") || strings.HasPrefix(n, "dm-") {
				continue
			}
			sz, _ := strconv.ParseInt(readFile("/sys/block/"+n+"/size"), 10, 64)
			model := readFile("/sys/block/" + n + "/device/model")
			if model == "" {
				model = n
			}
			disks = append(disks, map[string]any{"model": model, "sizeBytes": sz * 512})
		}
	}
	_, reboot := os.Stat("/var/run/reboot-required")
	tz := readFile("/etc/timezone")
	if tz == "" {
		tz, _ = lrun(ctx, 3*time.Second, nil, "timedatectl", "show", "-p", "Timezone", "--value")
	}
	var lastBoot any
	if f := strings.Fields(readFile("/proc/uptime")); len(f) > 0 {
		u, _ := strconv.ParseFloat(f[0], 64)
		lastBoot = time.Now().Add(-time.Duration(u * float64(time.Second))).UTC().Format(time.RFC3339)
	}
	return map[string]any{
		"computerName": host, "domain": "", "partOfDomain": false,
		"manufacturer": readFile("/sys/class/dmi/id/sys_vendor"), "model": firstNonEmpty(readFile("/sys/class/dmi/id/product_name"), readFile("/proc/device-tree/model")),
		"serial": readFile("/sys/class/dmi/id/product_serial"), "biosVersion": readFile("/sys/class/dmi/id/bios_version"),
		"osCaption": m["PRETTY_NAME"], "osVersion": m["VERSION_ID"], "osBuild": readFile("/proc/sys/kernel/osrelease"), "osArch": runtime.GOARCH,
		"lastBoot": lastBoot, "cpu": cpuModel, "cores": nc, "threads": threads, "ramBytes": ramBytes, "gpu": []string{},
		"disks": disks, "network": nics, "antivirus": []string{}, "defender": nil,
		"firewall": []map[string]any{{"name": "firewall", "enabled": linuxFirewallOn(ctx)}},
		"timezone": tz, "pendingReboot": reboot == nil,
	}, nil
}

func firstNonEmpty(v ...string) string {
	for _, s := range v {
		if s != "" {
			return s
		}
	}
	return ""
}

func linuxNICs() []struct {
	Description string   `json:"description"`
	MAC         string   `json:"mac"`
	IPs         []string `json:"ips"`
	DNS         []string `json:"dns"`
} {
	type nic = struct {
		Description string   `json:"description"`
		MAC         string   `json:"mac"`
		IPs         []string `json:"ips"`
		DNS         []string `json:"dns"`
	}
	var out []nic
	ents, _ := os.ReadDir("/sys/class/net")
	for _, e := range ents {
		if e.Name() == "lo" {
			continue
		}
		mac := readFile("/sys/class/net/" + e.Name() + "/address")
		var ips []string
		if ifc, err := netInterface(e.Name()); err == nil {
			ips = ifc
		}
		out = append(out, nic{Description: e.Name(), MAC: mac, IPs: ips})
	}
	return out
}

func linuxFirewallOn(ctx context.Context) bool {
	if out, err := lrun(ctx, 5*time.Second, nil, "ufw", "status"); err == nil && strings.Contains(out, "Status: active") {
		return true
	}
	if out, err := lrun(ctx, 5*time.Second, nil, "nft", "list", "ruleset"); err == nil && strings.Contains(out, "chain") && strings.Contains(out, "rule") == false && len(out) > 200 {
		return true
	}
	if out, err := lrun(ctx, 5*time.Second, nil, "iptables", "-S"); err == nil {
		for _, ln := range strings.Split(out, "\n") {
			if strings.HasPrefix(ln, "-P INPUT DROP") || strings.HasPrefix(ln, "-P INPUT REJECT") {
				return true
			}
		}
		if strings.Count(out, "\n") > 4 {
			return true
		}
	}
	return false
}

var debEpoch = regexp.MustCompile(`^\d+:`)

// upstreamVersion strips the Debian epoch and revision so version ranges can be compared ("1:2.4.52-1ubuntu4" -> "2.4.52").
func upstreamVersion(v string) string {
	v = debEpoch.ReplaceAllString(v, "")
	if i := strings.LastIndex(v, "-"); i > 0 {
		v = v[:i]
	}
	if i := strings.IndexAny(v, "+~"); i > 0 {
		v = v[:i]
	}
	return v
}

type pkgInfo struct{ Name, Version, Maintainer string }

func dpkgList(ctx context.Context) ([]pkgInfo, error) {
	out, err := lrun(ctx, 2*time.Minute, nil, "dpkg-query", "-W", "-f", "${db:Status-Abbrev}\t${Package}\t${Version}\t${Maintainer}\n")
	if err != nil {
		return nil, errors.New("dpkg-query is not available: only Debian-based systems are supported for software inventory")
	}
	var res []pkgInfo
	for _, ln := range strings.Split(out, "\n") {
		f := strings.Split(ln, "\t")
		if len(f) == 4 && strings.HasPrefix(f[0], "ii") {
			res = append(res, pkgInfo{f[1], f[2], f[3]})
		}
	}
	return res, nil
}

func (a *Agent) linuxSoftware(ctx context.Context, scan bool) (any, error) {
	pk, err := dpkgList(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]map[string]any, 0, len(pk))
	for _, p := range pk {
		v := p.Version
		if scan {
			v = upstreamVersion(v)
		}
		item := map[string]any{"name": p.Name, "version": v, "publisher": p.Maintainer, "installDate": ""}
		if scan {
			item["scope"] = "machine"
		}
		out = append(out, item)
	}
	return out, nil
}

func (a *Agent) linuxProcesses(ctx context.Context) (any, error) {
	ents, _ := os.ReadDir("/proc")
	page := int64(os.Getpagesize())
	clk := 100.0
	users := map[uint32]string{}
	lookup := func(uid uint32) string {
		if n, ok := users[uid]; ok {
			return n
		}
		n := strconv.Itoa(int(uid))
		if u, err := user.LookupId(n); err == nil {
			n = u.Username
		}
		users[uid] = n
		return n
	}
	out := []map[string]any{}
	for _, e := range ents {
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		dir := "/proc/" + e.Name()
		stat := readFile(dir + "/stat")
		i, j := strings.Index(stat, "("), strings.LastIndex(stat, ")")
		if i < 0 || j < i {
			continue
		}
		name := stat[i+1 : j]
		f := strings.Fields(stat[j+1:])
		if len(f) < 13 {
			continue
		}
		ut, _ := strconv.ParseFloat(f[11], 64)
		stt, _ := strconv.ParseFloat(f[12], 64)
		var rss int64
		if sf := strings.Fields(readFile(dir + "/statm")); len(sf) > 1 {
			rss, _ = strconv.ParseInt(sf[1], 10, 64)
		}
		var uid uint32
		if st, err := os.Stat(dir); err == nil {
			if sys, ok := st.Sys().(*syscall.Stat_t); ok {
				uid = sys.Uid
			}
		}
		exe, _ := os.Readlink(dir + "/exe")
		out = append(out, map[string]any{"pid": pid, "name": name, "cpu": float64(int((ut+stt)/clk*10)) / 10,
			"memMB": float64(int(float64(rss*page)/1048576*10)) / 10, "user": lookup(uid), "path": exe})
	}
	return out, nil
}

var reUnit = regexp.MustCompile(`^[A-Za-z0-9_.@:\\-]{1,200}$`)

func unitName(n string) string {
	if !strings.Contains(n, ".") {
		return n + ".service"
	}
	return n
}

func (a *Agent) linuxServices(ctx context.Context) (any, error) {
	units, err := lrun(ctx, time.Minute, nil, "systemctl", "list-units", "--type=service", "--all", "--no-legend", "--plain", "--no-pager")
	if err != nil {
		return nil, errors.New("systemd is not available")
	}
	files, _ := lrun(ctx, time.Minute, nil, "systemctl", "list-unit-files", "--type=service", "--no-legend", "--plain", "--no-pager")
	start := map[string]string{}
	for _, ln := range strings.Split(files, "\n") {
		if f := strings.Fields(ln); len(f) >= 2 {
			start[f[0]] = f[1]
		}
	}
	out := []map[string]any{}
	for _, ln := range strings.Split(units, "\n") {
		f := strings.Fields(ln)
		if len(f) < 4 {
			continue
		}
		name := f[0]
		state := "Stopped"
		if f[2] == "active" && f[3] == "running" {
			state = "Running"
		} else if f[2] == "failed" {
			state = "Failed"
		}
		sm := map[string]string{"enabled": "Auto", "enabled-runtime": "Auto", "static": "Manual", "indirect": "Manual", "generated": "Manual", "disabled": "Disabled", "masked": "Disabled"}[start[name]]
		if sm == "" {
			sm = "Manual"
		}
		out = append(out, map[string]any{"name": strings.TrimSuffix(name, ".service"), "display": strings.Join(f[4:], " "), "state": state, "start": sm, "account": ""})
	}
	return out, nil
}

func (a *Agent) linuxServiceControl(ctx context.Context, c *cmdCtx) (any, error) {
	var args struct{ Name, Action string }
	if err := decode(c.args, &args); err != nil {
		return nil, err
	}
	if !reUnit.MatchString(args.Name) || strings.HasPrefix(args.Name, "-") {
		return nil, errors.New("bad service name")
	}
	u := unitName(args.Name)
	var sub []string
	switch args.Action {
	case "start", "stop", "restart":
		sub = []string{args.Action, u}
	case "auto":
		sub = []string{"enable", u}
	case "manual", "disable":
		sub = []string{"disable", u}
	default:
		return nil, errors.New("bad action")
	}
	if _, err := lrun(ctx, 2*time.Minute, nil, "systemctl", sub...); err != nil {
		return nil, err
	}
	st, _ := lrun(ctx, 10*time.Second, nil, "systemctl", "is-active", u)
	en, _ := lrun(ctx, 10*time.Second, nil, "systemctl", "is-enabled", u)
	return map[string]string{"name": args.Name, "status": strings.Title(st), "startType": en}, nil
}

func (a *Agent) linuxEventLog(ctx context.Context, c *cmdCtx) (any, error) {
	args := struct {
		Log   string `json:"log"`
		Level string `json:"level"`
		Count int    `json:"count"`
	}{Log: "System", Level: "warnings", Count: 50}
	if err := decode(c.args, &args); err != nil {
		return nil, err
	}
	prio := map[string]string{"errors": "3", "warnings": "4", "all": "7"}[args.Level]
	if prio == "" {
		return nil, errors.New("level must be errors, warnings or all")
	}
	if args.Count < 1 || args.Count > 300 {
		args.Count = 50
	}
	argv := []string{"-o", "json", "--no-pager", "-n", strconv.Itoa(args.Count), "-p", prio}
	switch args.Log {
	case "System":
	case "Application":
		argv = append(argv, "_TRANSPORT=stdout", "+", "_TRANSPORT=journal")
	case "Security":
		argv = append(argv, "SYSLOG_FACILITY=4", "+", "SYSLOG_FACILITY=10")
	case "Setup":
		argv = append(argv, "-k")
	default:
		return nil, errors.New("log must be System, Application, Security or Setup")
	}
	out, err := lrun(ctx, 90*time.Second, nil, "journalctl", argv...)
	if err != nil && out == "" {
		return nil, err
	}
	names := []string{"Emergency", "Alert", "Critical", "Error", "Warning", "Notice", "Info", "Debug"}
	res := []map[string]any{}
	for _, ln := range strings.Split(out, "\n") {
		var e map[string]any
		if json.Unmarshal([]byte(ln), &e) != nil {
			continue
		}
		us, _ := strconv.ParseInt(fmt.Sprint(e["__REALTIME_TIMESTAMP"]), 10, 64)
		pr, _ := strconv.Atoi(fmt.Sprint(e["PRIORITY"]))
		lvl := "Info"
		if pr >= 0 && pr < len(names) {
			lvl = names[pr]
		}
		msg := fmt.Sprint(e["MESSAGE"])
		if len(msg) > 600 {
			msg = msg[:600]
		}
		res = append(res, map[string]any{"time": time.UnixMicro(us).UTC().Format(time.RFC3339), "id": pr, "provider": fmt.Sprint(e["SYSLOG_IDENTIFIER"]), "level": lvl, "message": msg})
	}
	return res, nil
}

// ---- apt updates ----

var reInst = regexp.MustCompile(`^Inst (\S+) \[([^\]]*)\] \((\S+) ([^)]*)\)`)

// pkgManager reports which system package manager drives updates: "apt", "dnf" (dnf or yum) or "".
func pkgManager() string {
	for _, m := range [][2]string{{"apt-get", "apt"}, {"dnf", "dnf"}, {"yum", "dnf"}} {
		if _, err := exec.LookPath(m[0]); err == nil {
			return m[1]
		}
	}
	return ""
}

func dnfBin() string {
	if _, err := exec.LookPath("dnf"); err == nil {
		return "dnf"
	}
	return "yum"
}

// parseDnfCheck reads `dnf check-update` output: "name.arch  version  repo" lines until an "Obsoleting" section.
func parseDnfCheck(out string) []map[string]any {
	list := []map[string]any{}
	for _, ln := range strings.Split(out, "\n") {
		if strings.HasPrefix(ln, "Obsoleting") {
			break
		}
		f := strings.Fields(ln)
		if len(f) != 3 || !strings.Contains(f[0], ".") || strings.HasPrefix(f[0], "Last") {
			continue
		}
		name := f[0][:strings.LastIndex(f[0], ".")]
		sev, cat := "", "Updates"
		if strings.Contains(f[2], "security") {
			sev, cat = "Important", "Security"
		}
		list = append(list, map[string]any{"id": name, "title": name + " → " + f[1], "kb": []string{}, "sizeMB": 0, "severity": sev,
			"needsReboot": strings.HasPrefix(name, "kernel") || name == "glibc" || strings.HasPrefix(name, "systemd"), "downloaded": false, "categories": []string{cat}})
	}
	return list
}

func (a *Agent) dnfUpdatesCheck(ctx context.Context) (any, error) {
	env := []string{"LC_ALL=C"}
	// exit status 100 means "updates available"; 0 means none; anything else is a failure
	out, err := lrun(ctx, 10*time.Minute, env, dnfBin(), "-q", "check-update")
	if err != nil && !strings.Contains(err.Error(), "100") && out == "" {
		return nil, fmt.Errorf("%s failed: %v", dnfBin(), err)
	}
	rb := false
	if _, e := exec.LookPath("needs-restarting"); e == nil {
		if _, e2 := lrun(ctx, time.Minute, env, "needs-restarting", "-r"); e2 != nil {
			rb = true
		}
	}
	return map[string]any{"updates": parseDnfCheck(out), "rebootPending": rb}, nil
}

func (a *Agent) linuxUpdatesCheck(ctx context.Context, c *cmdCtx) (any, error) {
	if pkgManager() == "dnf" {
		return a.dnfUpdatesCheck(ctx)
	}
	env := []string{"DEBIAN_FRONTEND=noninteractive", "LC_ALL=C"}
	_, _ = lrun(ctx, 5*time.Minute, env, "apt-get", "update", "-qq")
	out, err := lrun(ctx, 5*time.Minute, env, "apt-get", "-s", "-o", "Debug::NoLocking=1", "dist-upgrade")
	if err != nil && out == "" {
		return nil, errors.New("apt is not available: only Debian-based systems are supported for updates")
	}
	list := []map[string]any{}
	for _, ln := range strings.Split(out, "\n") {
		m := reInst.FindStringSubmatch(ln)
		if m == nil {
			continue
		}
		sev, cat := "", "Updates"
		if strings.Contains(m[4], "-security") || strings.Contains(m[4], "Security") {
			sev, cat = "Important", "Security"
		}
		list = append(list, map[string]any{"id": m[1], "title": m[1] + " " + m[2] + " → " + m[3], "kb": []string{}, "sizeMB": 0,
			"severity": sev, "needsReboot": strings.HasPrefix(m[1], "linux-image") || strings.HasPrefix(m[1], "libc6") || strings.HasPrefix(m[1], "systemd"), "downloaded": false, "categories": []string{cat}})
	}
	_, rb := os.Stat("/var/run/reboot-required")
	return map[string]any{"updates": list, "rebootPending": rb == nil}, nil
}

var rePkgName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9+._:-]{0,100}$`)

func (a *Agent) linuxUpdatesInstall(ctx context.Context, c *cmdCtx) (any, error) {
	var args struct {
		IDs    []string `json:"ids"`
		Reboot bool     `json:"reboot"`
	}
	if err := decode(c.args, &args); err != nil {
		return nil, err
	}
	for _, id := range args.IDs {
		if !rePkgName.MatchString(id) {
			return nil, errors.New("bad package name")
		}
	}
	if !a.updMu.TryLock() {
		return nil, errors.New("another update operation is already running on this machine")
	}
	defer a.updMu.Unlock()
	env := []string{"DEBIAN_FRONTEND=noninteractive", "LC_ALL=C"}
	c.progress("Installing updates…")
	if pkgManager() == "dnf" {
		argv := []string{"-y", "upgrade"}
		if len(args.IDs) > 0 {
			argv = append([]string{"-y", "upgrade"}, args.IDs...)
		}
		out, err := lrun(ctx, 3*time.Hour, env, dnfBin(), argv...)
		if err != nil {
			return nil, fmt.Errorf("%s failed: %s", dnfBin(), firstLines(lastLines(out, 6)+" "+err.Error(), 700))
		}
		n := strings.Count(out, "\n  Upgrading") + strings.Count(out, "\nUpgraded:")
		rb := false
		if _, e := exec.LookPath("needs-restarting"); e == nil {
			if _, e2 := lrun(ctx, time.Minute, env, "needs-restarting", "-r"); e2 != nil {
				rb = true
			}
		}
		if args.Reboot && rb {
			c.progress("Restart required; restarting in 60 seconds")
			if err := powerAction(proto.PowerArgs{Action: "restart", Delay: 60}); err != nil {
				return nil, fmt.Errorf("updates installed but restart failed: %w", err)
			}
		}
		return map[string]any{"installed": n, "resultCode": 2, "rebootRequired": rb, "items": []any{}}, nil
	}
	argv := []string{"-y", "-o", "Dpkg::Options::=--force-confold"}
	if len(args.IDs) == 0 {
		argv = append(argv, "dist-upgrade")
	} else {
		argv = append(argv, "install", "--only-upgrade")
		argv = append(argv, args.IDs...)
	}
	out, err := lrun(ctx, 3*time.Hour, env, "apt-get", argv...)
	if err != nil {
		return nil, fmt.Errorf("apt-get failed: %s", firstLines(lastLines(out, 6)+" "+err.Error(), 700))
	}
	_, rb := os.Stat("/var/run/reboot-required")
	n := strings.Count(out, "\nSetting up ")
	if args.Reboot && rb == nil {
		c.progress("Restart required; restarting in 60 seconds")
		if err := powerAction(proto.PowerArgs{Action: "restart", Delay: 60}); err != nil {
			return nil, fmt.Errorf("updates installed but restart failed: %w", err)
		}
	}
	return map[string]any{"installed": n, "resultCode": 2, "rebootRequired": rb == nil, "items": []any{}}, nil
}

// ---- deployment (apt packages and uploaded .deb files) ----

func (a *Agent) linuxAptInstall(ctx context.Context, c *cmdCtx, remove bool) (any, error) {
	var args struct {
		ID      string `json:"id"`
		Version string `json:"version"`
	}
	if err := decode(c.args, &args); err != nil {
		return nil, err
	}
	if !rePkgName.MatchString(args.ID) {
		return nil, fmt.Errorf("bad package name %q", args.ID)
	}
	if !a.updMu.TryLock() {
		return nil, errors.New("another update operation is already running on this machine")
	}
	defer a.updMu.Unlock()
	env := []string{"DEBIAN_FRONTEND=noninteractive", "LC_ALL=C"}
	verb, pkg := "install", args.ID
	if remove {
		verb = "remove"
	} else if args.Version != "" && reVersion.MatchString(args.Version) {
		pkg += "=" + args.Version
	}
	c.progress(strings.Title(verb) + " " + args.ID + "…")
	if !remove {
		_, _ = lrun(ctx, 5*time.Minute, env, "apt-get", "update", "-qq")
	}
	out, err := lrun(ctx, 60*time.Minute, env, "apt-get", "-y", verb, pkg)
	if err != nil {
		return nil, fmt.Errorf("apt-get failed: %s", firstLines(lastLines(out, 5)+" "+err.Error(), 700))
	}
	return map[string]any{"exitCode": 0, "tail": firstLines(lastLines(out, 6), 800)}, nil
}

func (a *Agent) linuxDebInstall(ctx context.Context, path string) (map[string]any, error) {
	env := []string{"DEBIAN_FRONTEND=noninteractive", "LC_ALL=C"}
	out, err := lrun(ctx, 60*time.Minute, env, "apt-get", "-y", "install", path)
	if err != nil {
		return nil, fmt.Errorf("installing the .deb failed: %s", firstLines(lastLines(out, 5)+" "+err.Error(), 700))
	}
	_, rb := os.Stat("/var/run/reboot-required")
	return map[string]any{"exitCode": 0, "rebootRequired": rb == nil}, nil
}

// ---- security scan ----

func (a *Agent) linuxScanPorts(ctx context.Context) (any, error) {
	out, err := lrun(ctx, time.Minute, nil, "ss", "-H", "-tulnp")
	if err != nil {
		return nil, errors.New("ss is not available")
	}
	rePID := regexp.MustCompile(`\("([^"]*)",pid=(\d+)`)
	res := []map[string]any{}
	seen := map[string]bool{}
	for _, ln := range strings.Split(out, "\n") {
		f := strings.Fields(ln)
		if len(f) < 5 {
			continue
		}
		addr := f[4]
		i := strings.LastIndex(addr, ":")
		if i < 0 {
			continue
		}
		host, port := strings.Trim(addr[:i], "[]"), addr[i+1:]
		pn, _ := strconv.Atoi(port)
		if host == "*" || host == "" {
			host = "0.0.0.0"
		}
		var pid int
		var pname string
		if m := rePID.FindStringSubmatch(ln); m != nil {
			pname = m[1]
			pid, _ = strconv.Atoi(m[2])
		}
		key := f[0] + host + port
		if seen[key] {
			continue
		}
		seen[key] = true
		res = append(res, map[string]any{"proto": f[0], "address": host, "port": pn, "pid": pid, "process": pname})
	}
	sort.Slice(res, func(i, j int) bool { return res[i]["port"].(int) < res[j]["port"].(int) })
	return res, nil
}

func (a *Agent) linuxScanConfig(ctx context.Context) (any, error) {
	var checks []map[string]any
	add := func(id, title, cat, sev, status, detail, fix string) {
		checks = append(checks, map[string]any{"id": id, "title": title, "category": cat, "severity": sev, "status": status, "detail": detail, "fix": fix})
	}
	m := osRelease()
	// firewall
	if linuxFirewallOn(ctx) {
		add("firewall", "Firewall enabled", "Network", "high", "pass", "A firewall (ufw/nftables/iptables) with rules is active.", "")
	} else {
		add("firewall", "Firewall enabled", "Network", "high", "fail", "No active firewall rules were found.", "Enable ufw ('ufw enable') or configure nftables.")
	}
	// ssh
	if out, err := lrun(ctx, 10*time.Second, nil, "sshd", "-T"); err == nil {
		cfg := map[string]string{}
		for _, ln := range strings.Split(out, "\n") {
			if k, v, ok := strings.Cut(ln, " "); ok {
				cfg[k] = v
			}
		}
		if v := cfg["permitrootlogin"]; v == "yes" {
			add("ssh_root", "SSH root login disabled", "Accounts", "high", "fail", "sshd allows root to log in with a password.", "Set 'PermitRootLogin no' (or prohibit-password) in sshd_config.")
		} else {
			add("ssh_root", "SSH root login disabled", "Accounts", "high", "pass", "PermitRootLogin is "+v+".", "")
		}
		if cfg["passwordauthentication"] == "yes" {
			add("ssh_password", "SSH password logins disabled", "Accounts", "medium", "warn", "sshd accepts passwords; keys are safer against guessing.", "Use keys and set 'PasswordAuthentication no'.")
		} else {
			add("ssh_password", "SSH password logins disabled", "Accounts", "medium", "pass", "Password logins over SSH are off.", "")
		}
	}
	// automatic updates
	if _, err := os.Stat("/usr/bin/unattended-upgrade"); err == nil {
		en := strings.Contains(readFile("/etc/apt/apt.conf.d/20auto-upgrades"), `Unattended-Upgrade "1"`)
		if en {
			add("auto_updates", "Automatic security updates", "Patching", "medium", "pass", "unattended-upgrades is enabled.", "")
		} else {
			add("auto_updates", "Automatic security updates", "Patching", "medium", "warn", "unattended-upgrades is installed but not enabled.", "Run 'dpkg-reconfigure unattended-upgrades'.")
		}
	} else {
		add("auto_updates", "Automatic security updates", "Patching", "medium", "warn", "unattended-upgrades is not installed.", "Install it: 'apt install unattended-upgrades'.")
	}
	if _, err := os.Stat("/var/run/reboot-required"); err == nil {
		add("reboot", "No restart pending", "Patching", "low", "warn", "A restart is pending; some updates are not active yet.", "Restart the machine.")
	} else {
		add("reboot", "No restart pending", "Patching", "low", "pass", "No restart pending.", "")
	}
	// ASLR
	if v := readFile("/proc/sys/kernel/randomize_va_space"); v == "2" {
		add("aslr", "Address-space randomisation (ASLR)", "Hardening", "low", "pass", "ASLR is fully enabled.", "")
	} else if v != "" {
		add("aslr", "Address-space randomisation (ASLR)", "Hardening", "low", "fail", "kernel.randomize_va_space is "+v+".", "Set kernel.randomize_va_space=2.")
	}
	// disk encryption
	if out, err := lrun(ctx, 10*time.Second, nil, "lsblk", "-rno", "TYPE"); err == nil {
		if strings.Contains(out, "crypt") {
			add("encryption", "Disk encryption (LUKS)", "Data protection", "medium", "pass", "An encrypted volume is in use.", "")
		} else {
			add("encryption", "Disk encryption (LUKS)", "Data protection", "medium", "warn", "No encrypted volumes found (not important for servers in a locked room).", "Use LUKS full-disk encryption on laptops.")
		}
	}
	// mandatory access control
	if _, err := os.Stat("/sys/kernel/security/apparmor"); err == nil || readFile("/sys/fs/selinux/enforce") == "1" {
		add("mac", "AppArmor/SELinux active", "Hardening", "low", "pass", "A mandatory access control framework is active.", "")
	} else {
		add("mac", "AppArmor/SELinux active", "Hardening", "low", "warn", "No mandatory access control framework detected.", "Enable AppArmor or SELinux.")
	}
	// time sync
	if out, err := lrun(ctx, 5*time.Second, nil, "timedatectl", "show", "-p", "NTPSynchronized", "--value"); err == nil {
		if out == "yes" {
			add("ntp", "Clock synchronised", "Hardening", "low", "pass", "The system clock is synchronised.", "")
		} else {
			add("ntp", "Clock synchronised", "Hardening", "low", "warn", "The system clock is not synchronised; logs and TLS can break.", "Enable systemd-timesyncd or chrony.")
		}
	}
	// failed units
	if out, err := lrun(ctx, 10*time.Second, nil, "systemctl", "--failed", "--no-legend", "--plain", "--no-pager"); err == nil {
		n := 0
		for _, ln := range strings.Split(out, "\n") {
			if strings.TrimSpace(ln) != "" {
				n++
			}
		}
		if n > 0 {
			add("failed_units", "No failed services", "Health", "low", "warn", fmt.Sprintf("%d systemd unit(s) have failed.", n), "Check 'systemctl --failed'.")
		} else {
			add("failed_units", "No failed services", "Health", "low", "pass", "No failed systemd units.", "")
		}
	}
	// OS support
	eol := map[string]string{"ubuntu 18.04": "2023-05-31", "ubuntu 20.04": "2025-05-31", "ubuntu 22.04": "2027-06-01", "ubuntu 24.04": "2029-06-01",
		"debian 10": "2024-06-30", "debian 11": "2026-08-31", "debian 12": "2028-06-30", "debian 13": "2030-06-30", "raspbian 10": "2024-06-30", "raspbian 11": "2026-08-31", "raspbian 12": "2028-06-30"}
	key := strings.ToLower(m["ID"] + " " + m["VERSION_ID"])
	if d, ok := eol[key]; ok {
		if t, _ := time.Parse("2006-01-02", d); time.Now().After(t) {
			add("os_support", "OS version still receives security updates", "Patching", "high", "fail", m["PRETTY_NAME"]+" reached the end of standard support on "+d+".", "Upgrade to a supported release.")
		} else {
			add("os_support", "OS version still receives security updates", "Patching", "high", "pass", m["PRETTY_NAME"]+" is supported until "+d+".", "")
		}
	}
	name, _ := linuxOSInfo()
	return map[string]any{"build": 0, "edition": name, "checks": checks}, nil
}

// ---- power / messages ----

func linuxPower(p proto.PowerArgs) error {
	ctx := context.Background()
	mins := (p.Delay + 59) / 60
	delayed := func(flag string) error {
		args := []string{flag, "+" + strconv.Itoa(mins)}
		if p.Message != "" {
			args = append(args, p.Message)
		}
		_, err := lrun(ctx, 20*time.Second, nil, "shutdown", args...)
		return err
	}
	switch p.Action {
	case "shutdown":
		if p.Delay > 0 {
			return delayed("-P")
		}
		_, err := lrun(ctx, 20*time.Second, nil, "systemctl", "poweroff")
		return err
	case "restart":
		if p.Delay > 0 {
			return delayed("-r")
		}
		_, err := lrun(ctx, 20*time.Second, nil, "systemctl", "reboot")
		return err
	case "sleep":
		_, err := lrun(ctx, 20*time.Second, nil, "systemctl", "suspend")
		return err
	case "hibernate":
		_, err := lrun(ctx, 20*time.Second, nil, "systemctl", "hibernate")
		return err
	case "lock":
		_, err := lrun(ctx, 20*time.Second, nil, "loginctl", "lock-sessions")
		return err
	case "logoff":
		out, err := lrun(ctx, 10*time.Second, nil, "loginctl", "list-sessions", "--no-legend")
		if err != nil {
			return err
		}
		for _, ln := range strings.Split(out, "\n") {
			if f := strings.Fields(ln); len(f) > 0 && f[0] != "" {
				_, _ = lrun(ctx, 10*time.Second, nil, "loginctl", "terminate-session", f[0])
			}
		}
		return nil
	case "cancel":
		_, err := lrun(ctx, 10*time.Second, nil, "shutdown", "-c")
		return err
	}
	return errors.New("unknown power action")
}

func linuxMessage(title, text string) error {
	_, err := lrun(context.Background(), 10*time.Second, nil, "wall", title+": "+text)
	return err
}

// ---- self update / uninstall ----

func linuxApplyUpdate(newExe string) error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	exe, _ = filepath.EvalSymlinks(exe)
	tmp := exe + ".new"
	in, err := os.ReadFile(newExe)
	if err != nil {
		return err
	}
	if err := os.WriteFile(tmp, in, 0o755); err != nil {
		return err
	}
	if err := os.Rename(tmp, exe); err != nil {
		return err
	}
	// systemd (Restart=always) starts the new binary after a clean exit
	go func() { time.Sleep(2 * time.Second); os.Exit(0) }()
	return nil
}

func linuxUninstall() error {
	script := `sleep 3
if dpkg -s helm-agent >/dev/null 2>&1; then DEBIAN_FRONTEND=noninteractive dpkg -P helm-agent; fi
systemctl disable --now helm-agent 2>/dev/null
rm -f /etc/systemd/system/helm-agent.service /usr/local/bin/helm-agent
rm -rf /etc/helm-agent /var/lib/helm-agent
systemctl daemon-reload`
	if _, err := exec.LookPath("systemd-run"); err == nil {
		return exec.Command("systemd-run", "--no-block", "--collect", "sh", "-c", script).Run()
	}
	cmd := exec.Command("sh", "-c", script)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	return cmd.Start()
}

// ---- configuration: /etc/helm-agent/agent.conf (KEY=VALUE), environment as fallback ----

func linuxConfig() (server, token, consent string, insecure bool) {
	cfg := map[string]string{}
	sc := bufio.NewScanner(strings.NewReader(readFile(unixConfPath())))
	for sc.Scan() {
		ln := strings.TrimSpace(sc.Text())
		if ln == "" || strings.HasPrefix(ln, "#") {
			continue
		}
		if k, v, ok := strings.Cut(ln, "="); ok {
			cfg[strings.TrimSpace(k)] = strings.Trim(strings.TrimSpace(v), `"'`)
		}
	}
	pick := func(k string) string { return firstNonEmpty(cfg[k], os.Getenv("HELM_"+k)) }
	return pick("SERVER"), pick("TOKEN"), firstNonEmpty(pick("CONSENT"), "unattended"), pick("INSECURE") == "1"
}

// linuxConsumeToken removes the one-time enrollment token from the config file once enrolled.
func linuxConsumeToken() {
	b, err := os.ReadFile(unixConfPath())
	if err != nil {
		return
	}
	var keep []string
	for _, ln := range strings.Split(string(b), "\n") {
		if !strings.HasPrefix(strings.TrimSpace(ln), "TOKEN=") {
			keep = append(keep, ln)
		}
	}
	_ = os.WriteFile(unixConfPath(), []byte(strings.Join(keep, "\n")), 0o600)
}

func linuxDataDir() string {
	if os.Geteuid() == 0 && runtime.GOOS == "darwin" {
		return "/Library/Application Support/Helm/data"
	}
	if os.Geteuid() == 0 {
		return "/var/lib/helm-agent"
	}
	h, _ := os.UserHomeDir()
	return h + "/.helm-agent"
}

// linuxHandlers replaces the Windows-script based handlers on a real Linux host.
func (a *Agent) linuxHandlers(m map[string]handlerFn) {
	unsupported := func(what string) handlerFn {
		return func(ctx context.Context, c *cmdCtx) (any, error) {
			return nil, errors.New(what + " is not available on Linux")
		}
	}
	wrap := func(f func(context.Context) (any, error)) handlerFn {
		return func(ctx context.Context, c *cmdCtx) (any, error) { return f(ctx) }
	}
	m["inventory"] = wrap(a.linuxInventory)
	m["software.list"] = func(ctx context.Context, c *cmdCtx) (any, error) { return a.linuxSoftware(ctx, false) }
	m["scan.software"] = func(ctx context.Context, c *cmdCtx) (any, error) { return a.linuxSoftware(ctx, true) }
	m["process.list"] = wrap(a.linuxProcesses)
	m["service.list"] = wrap(a.linuxServices)
	m["service.control"] = a.linuxServiceControl
	m["eventlog"] = a.linuxEventLog
	m["updates.check"] = a.linuxUpdatesCheck
	m["updates.install"] = a.linuxUpdatesInstall
	m["scan.ports"] = wrap(a.linuxScanPorts)
	m["scan.config"] = wrap(a.linuxScanConfig)
	m["winget.list"] = unsupported("winget")
	m["winget.upgrade"] = unsupported("winget")
	m["winget.install"] = func(ctx context.Context, c *cmdCtx) (any, error) { return a.linuxAptInstall(ctx, c, false) }
	m["winget.uninstall"] = func(ctx context.Context, c *cmdCtx) (any, error) { return a.linuxAptInstall(ctx, c, true) }
	m["rdp.status"] = func(ctx context.Context, c *cmdCtx) (any, error) {
		return map[string]any{"enabled": false, "port": 0, "nla": false, "edition": "Linux", "supported": false, "service": "n/a"}, nil
	}
	m["rdp.enable"] = unsupported("Remote Desktop")
	m["rdp.disable"] = unsupported("Remote Desktop")
}

func netInterface(name string) ([]string, error) {
	ifc, err := net.InterfaceByName(name)
	if err != nil {
		return nil, err
	}
	addrs, _ := ifc.Addrs()
	var ips []string
	for _, ad := range addrs {
		ips = append(ips, strings.SplitN(ad.String(), "/", 2)[0])
	}
	return ips, nil
}

// WriteLinuxConfig writes the agent config file (mode 0600): /etc/helm-agent/agent.conf on Linux, /Library/Application Support/Helm/agent.conf on macOS.
func WriteLinuxConfig(server, token, consent string) error {
	if !strings.HasPrefix(server, "https://") && !strings.HasPrefix(server, "http://") {
		return errors.New("--server must be a full URL such as https://helm.example")
	}
	if strings.ContainsAny(server+token+consent, "\r\n\"'") || token == "" {
		return errors.New("a valid --token is required")
	}
	if err := os.MkdirAll(filepath.Dir(unixConfPath()), 0o700); err != nil {
		return err
	}
	body := "SERVER=" + server + "\nTOKEN=" + token + "\nCONSENT=" + consent + "\n"
	return os.WriteFile(unixConfPath(), []byte(body), 0o600)
}
