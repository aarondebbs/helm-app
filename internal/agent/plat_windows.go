//go:build windows

package agent

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"helm/internal/proto"
)

var (
	kernel32 = syscall.NewLazyDLL("kernel32.dll")
	advapi32 = syscall.NewLazyDLL("advapi32.dll")
	user32   = syscall.NewLazyDLL("user32.dll")
	gdi32    = syscall.NewLazyDLL("gdi32.dll")
	wtsapi32 = syscall.NewLazyDLL("wtsapi32.dll")
	powrprof = syscall.NewLazyDLL("powrprof.dll")
	sasdll   = syscall.NewLazyDLL("sas.dll")

	procGetSystemTimes      = kernel32.NewProc("GetSystemTimes")
	procGlobalMemoryStatus  = kernel32.NewProc("GlobalMemoryStatusEx")
	procGetTickCount64      = kernel32.NewProc("GetTickCount64")
	procGetLogicalDrives    = kernel32.NewProc("GetLogicalDrives")
	procGetDriveType        = kernel32.NewProc("GetDriveTypeW")
	procGetDiskFreeSpaceEx  = kernel32.NewProc("GetDiskFreeSpaceExW")
	procConsoleSession      = kernel32.NewProc("WTSGetActiveConsoleSessionId")
	procWTSQuerySessionInfo = wtsapi32.NewProc("WTSQuerySessionInformationW")
	procWTSFreeMemory       = wtsapi32.NewProc("WTSFreeMemory")
	procWTSSendMessage      = wtsapi32.NewProc("WTSSendMessageW")
	procWTSLogoffSession    = wtsapi32.NewProc("WTSLogoffSession")
	procSetSuspendState     = powrprof.NewProc("SetSuspendState")
	procSendSAS             = sasdll.NewProc("SendSAS")
)

// ServiceName is the Windows service name registered by the MSI.
const ServiceName = "HelmAgent"

// ---- registry (read-only helpers on the stdlib syscall package) ----

func regOpen(path string) (syscall.Handle, error) {
	var h syscall.Handle
	p, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return 0, err
	}
	const keyWOW64_64 = 0x100
	if err := syscall.RegOpenKeyEx(syscall.HKEY_LOCAL_MACHINE, p, 0, syscall.KEY_READ|keyWOW64_64, &h); err != nil {
		return 0, err
	}
	return h, nil
}

func regQuery(path, name string) (typ uint32, data []byte, err error) {
	h, err := regOpen(path)
	if err != nil {
		return 0, nil, err
	}
	defer syscall.RegCloseKey(h)
	n, err := syscall.UTF16PtrFromString(name)
	if err != nil {
		return 0, nil, err
	}
	var size uint32
	if err = syscall.RegQueryValueEx(h, n, nil, &typ, nil, &size); err != nil {
		return 0, nil, err
	}
	if size == 0 {
		return typ, nil, nil
	}
	buf := make([]byte, size)
	if err = syscall.RegQueryValueEx(h, n, nil, &typ, &buf[0], &size); err != nil {
		return 0, nil, err
	}
	return typ, buf[:size], nil
}

func utf16BytesToString(b []byte) string {
	u := make([]uint16, 0, len(b)/2)
	for i := 0; i+1 < len(b); i += 2 {
		u = append(u, uint16(b[i])|uint16(b[i+1])<<8)
	}
	return strings.TrimRight(syscall.UTF16ToString(u), "\x00")
}

func regString(path, name string) string {
	t, d, err := regQuery(path, name)
	if err != nil || (t != 1 && t != 2) {
		return ""
	}
	return utf16BytesToString(d)
}

func regDWORD(path, name string) (uint32, bool) {
	t, d, err := regQuery(path, name)
	if err != nil || t != 4 || len(d) < 4 {
		return 0, false
	}
	return uint32(d[0]) | uint32(d[1])<<8 | uint32(d[2])<<16 | uint32(d[3])<<24, true
}

const agentRegKey = `SOFTWARE\Helm\Agent`
const ntCurrentVersion = `SOFTWARE\Microsoft\Windows NT\CurrentVersion`

// LoadInstalledConfig reads the settings the MSI stored in the registry.
func LoadInstalledConfig() (server, token, consent string, allowInsecure bool) {
	server = strings.TrimSpace(regString(agentRegKey, "Server")) // the portal pads values inside a downloaded MSI
	token = strings.TrimSpace(regString(agentRegKey, "EnrollToken"))
	consent = strings.TrimSpace(regString(agentRegKey, "ConsentMode"))
	if v, ok := regDWORD(agentRegKey, "AllowInsecure"); ok && v == 1 {
		allowInsecure = true
	}
	return
}

// DefaultDataDir is where the agent keeps its credentials and scratch files.
func DefaultDataDir() string {
	pd := os.Getenv("ProgramData")
	if pd == "" {
		pd = `C:\ProgramData`
	}
	return filepath.Join(pd, "Helm")
}

var securedDirs sync.Map

// securePath restricts a directory to SYSTEM and Administrators.
func securePath(dir string) {
	if _, done := securedDirs.LoadOrStore(dir, true); done {
		return
	}
	cmd := exec.Command(filepath.Join(sysDir(), "icacls.exe"), dir, "/inheritance:r",
		"/grant:r", "*S-1-5-18:(OI)(CI)F", "*S-1-5-32-544:(OI)(CI)F")
	hideWindow(cmd)
	_ = cmd.Run()
}

func sysDir() string {
	r := os.Getenv("SystemRoot")
	if r == "" {
		r = `C:\Windows`
	}
	return filepath.Join(r, "System32")
}

// consumeEnrollToken removes the one-time token from the registry after use.
func consumeEnrollToken() {
	cmd := exec.Command(filepath.Join(sysDir(), "reg.exe"), "delete", `HKLM\`+agentRegKey, "/v", "EnrollToken", "/f", "/reg:64")
	hideWindow(cmd)
	_ = cmd.Run()
}

// ---- stats ----

type filetime struct{ Low, High uint32 }

func (f filetime) u64() uint64 { return uint64(f.High)<<32 | uint64(f.Low) }

var cpuPrev struct {
	sync.Mutex
	idle, total uint64
	ok          bool
}

type memStatusEx struct {
	Length               uint32
	MemoryLoad           uint32
	TotalPhys, AvailPhys uint64
	TotalPageFile        uint64
	AvailPageFile        uint64
	TotalVirtual         uint64
	AvailVirtual         uint64
	AvailExtendedVirtual uint64
}

func sysStats() proto.Stats {
	var st proto.Stats
	var idle, kern, usr filetime
	if r, _, _ := procGetSystemTimes.Call(uintptr(unsafe.Pointer(&idle)), uintptr(unsafe.Pointer(&kern)), uintptr(unsafe.Pointer(&usr))); r != 0 {
		total := kern.u64() + usr.u64() // kernel time includes idle time
		cpuPrev.Lock()
		if cpuPrev.ok && total > cpuPrev.total {
			dt := float64(total - cpuPrev.total)
			di := float64(idle.u64() - cpuPrev.idle)
			st.CPU = (1 - di/dt) * 100
			if st.CPU < 0 {
				st.CPU = 0
			}
		}
		cpuPrev.idle, cpuPrev.total, cpuPrev.ok = idle.u64(), total, true
		cpuPrev.Unlock()
	}
	ms := memStatusEx{Length: uint32(unsafe.Sizeof(memStatusEx{}))}
	if r, _, _ := procGlobalMemoryStatus.Call(uintptr(unsafe.Pointer(&ms))); r != 0 {
		st.MemTotal = ms.TotalPhys
		st.MemUsed = ms.TotalPhys - ms.AvailPhys
	}
	if r, _, _ := procGetTickCount64.Call(); r != 0 {
		st.UptimeSec = uint64(r) / 1000
	}
	mask, _, _ := procGetLogicalDrives.Call()
	for i := 0; i < 26; i++ {
		if mask&(1<<uint(i)) == 0 {
			continue
		}
		root := string(rune('A'+i)) + `:\`
		rp, _ := syscall.UTF16PtrFromString(root)
		if t, _, _ := procGetDriveType.Call(uintptr(unsafe.Pointer(rp))); t != 3 { // DRIVE_FIXED
			continue
		}
		var freeAvail, total, totalFree uint64
		if r, _, _ := procGetDiskFreeSpaceEx.Call(uintptr(unsafe.Pointer(rp)), uintptr(unsafe.Pointer(&freeAvail)),
			uintptr(unsafe.Pointer(&total)), uintptr(unsafe.Pointer(&totalFree))); r != 0 {
			st.Disks = append(st.Disks, proto.Disk{Name: root, Total: total, Free: freeAvail})
		}
	}
	st.User, st.UserPresent = loggedOnUser()
	return st
}

func listDrives() []string {
	var out []string
	mask, _, _ := procGetLogicalDrives.Call()
	for i := 0; i < 26; i++ {
		if mask&(1<<uint(i)) == 0 {
			continue
		}
		root := string(rune('A'+i)) + `:\`
		rp, _ := syscall.UTF16PtrFromString(root)
		if t, _, _ := procGetDriveType.Call(uintptr(unsafe.Pointer(rp))); t == 2 || t == 3 || t == 4 {
			out = append(out, root)
		}
	}
	return out
}

func osInfo() (string, string) {
	name := regString(ntCurrentVersion, "ProductName")
	build := regString(ntCurrentVersion, "CurrentBuild")
	ver := regString(ntCurrentVersion, "DisplayVersion")
	if ver == "" {
		ver = regString(ntCurrentVersion, "ReleaseId")
	}
	edition := regString(ntCurrentVersion, "EditionID")
	if n := atoiSafe(build); n >= 22000 {
		name = strings.Replace(name, "Windows 10", "Windows 11", 1)
	}
	s := name
	if ver != "" {
		s += " " + ver
	}
	if build != "" {
		s += " (build " + build
		if ubr, ok := regDWORD(ntCurrentVersion, "UBR"); ok {
			s += fmt.Sprintf(".%d", ubr)
		}
		s += ")"
	}
	return s, edition
}

func atoiSafe(s string) int {
	n := 0
	for _, r := range s {
		if r < '0' || r > '9' {
			return 0
		}
		n = n*10 + int(r-'0')
	}
	return n
}

// ---- sessions ----

func consoleSessionID() (uint32, bool) {
	r, _, _ := procConsoleSession.Call()
	id := uint32(r)
	return id, id != 0xFFFFFFFF
}

func querySessionString(sid uint32, class uintptr) string {
	var buf *uint16
	var n uint32
	r, _, _ := procWTSQuerySessionInfo.Call(0, uintptr(sid), class, uintptr(unsafe.Pointer(&buf)), uintptr(unsafe.Pointer(&n)))
	if r == 0 || buf == nil {
		return ""
	}
	defer procWTSFreeMemory.Call(uintptr(unsafe.Pointer(buf)))
	if n < 2 {
		return ""
	}
	return syscall.UTF16ToString(unsafe.Slice(buf, n/2))
}

// loggedOnUser reports the user on the physical console, if any.
func loggedOnUser() (string, bool) {
	sid, ok := consoleSessionID()
	if !ok {
		return "", false
	}
	const wtsUserName = 5
	u := querySessionString(sid, wtsUserName)
	return u, u != ""
}

// ---- processes ----

const createNoWindow = 0x08000000

func hideWindow(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: createNoWindow}
}

func killTree(pid int) {
	cmd := exec.Command(filepath.Join(sysDir(), "taskkill.exe"), "/PID", fmt.Sprint(pid), "/T", "/F")
	hideWindow(cmd)
	_ = cmd.Run()
}

func powershellPath() string {
	return filepath.Join(sysDir(), "WindowsPowerShell", "v1.0", "powershell.exe")
}

func shellCommand(ctx context.Context, shell, path string) *exec.Cmd {
	if shell == "cmd" {
		return exec.CommandContext(ctx, filepath.Join(sysDir(), "cmd.exe"), "/D", "/C", path)
	}
	// RemoteSigned (not Bypass): the script is a local file the agent just wrote, which it allows, and
	// security products treat a blanket policy bypass as a classic malware indicator.
	return exec.CommandContext(ctx, powershellPath(), "-NoLogo", "-NoProfile", "-NonInteractive",
		"-ExecutionPolicy", "RemoteSigned", "-File", path)
}

func terminalCommand(ctx context.Context, shell string) *exec.Cmd {
	if shell == "cmd" {
		return exec.CommandContext(ctx, filepath.Join(sysDir(), "cmd.exe"), "/Q", "/D")
	}
	return exec.CommandContext(ctx, powershellPath(), "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", "-")
}

func fixtureFor(script string) (string, bool) { return "", false }

func wingetFixtureAvailable() string { return "" }

func wingetFixture(args []string) (string, bool) { return "", false }

// ---- power ----

func powerAction(p proto.PowerArgs) error {
	sd := filepath.Join(sysDir(), "shutdown.exe")
	run := func(args ...string) error {
		cmd := exec.Command(sd, args...)
		hideWindow(cmd)
		out, err := cmd.CombinedOutput()
		if err != nil {
			return fmt.Errorf("%v: %s", err, strings.TrimSpace(string(out)))
		}
		return nil
	}
	delay := p.Delay
	if delay < 3 && (p.Action == "shutdown" || p.Action == "restart") {
		delay = 3 // leave time to report the result before the PC goes down
	}
	switch p.Action {
	case "shutdown", "restart":
		flag := "/s"
		if p.Action == "restart" {
			flag = "/r"
		}
		args := []string{flag, "/t", fmt.Sprint(delay)}
		if p.Message != "" {
			args = append(args, "/c", p.Message)
		}
		if p.Force {
			args = append(args, "/f")
		}
		return run(args...)
	case "hibernate":
		return run("/h")
	case "cancel":
		return run("/a")
	case "sleep":
		go func() {
			time.Sleep(2 * time.Second)
			procSetSuspendState.Call(0, 0, 0) // sleep (not hibernate), do not force
		}()
		return nil
	case "lock":
		sid, ok := consoleSessionID()
		if !ok {
			return errors.New("no interactive session")
		}
		h, err := launchInSession(sid, `"`+filepath.Join(sysDir(), "rundll32.exe")+`" user32.dll,LockWorkStation`, `winsta0\default`)
		if err != nil {
			return err
		}
		syscall.CloseHandle(h)
		return nil
	case "logoff":
		sid, ok := consoleSessionID()
		if !ok {
			return errors.New("no interactive session")
		}
		if r, _, e := procWTSLogoffSession.Call(0, uintptr(sid), 0); r == 0 {
			return fmt.Errorf("log off failed: %v", e)
		}
		return nil
	}
	return errors.New("unknown action")
}

func sendUserMessage(title, text string) error {
	sid, ok := consoleSessionID()
	if !ok {
		return errors.New("nobody is logged on at the console")
	}
	t, _ := syscall.UTF16FromString(title)
	m, _ := syscall.UTF16FromString(text)
	const mbOKInfo = 0x40
	var resp uint32
	r, _, e := procWTSSendMessage.Call(0, uintptr(sid),
		uintptr(unsafe.Pointer(&t[0])), uintptr((len(t)-1)*2),
		uintptr(unsafe.Pointer(&m[0])), uintptr((len(m)-1)*2),
		mbOKInfo, 0, uintptr(unsafe.Pointer(&resp)), 0)
	if r == 0 {
		return fmt.Errorf("could not show the message: %v", e)
	}
	return nil
}

// sendSAS emulates Ctrl+Alt+Del. It works from the service when the policy
// "Software Secure Attention Sequence" allows services.
func sendSAS() error {
	if r, _, e := procSendSAS.Call(0); r == 0 && e != nil && e != syscall.Errno(0) {
		return fmt.Errorf("SendSAS failed (enable the 'Disable or enable software Secure Attention Sequence' policy for services): %v", e)
	}
	return nil
}

func rdpPort() int {
	if p, ok := regDWORD(`SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp`, "PortNumber"); ok && p > 0 && p < 65536 {
		return int(p)
	}
	return 3389
}

// ---- self update / uninstall ----

func detached(cmdline string) error {
	cmd := exec.Command(filepath.Join(sysDir(), "cmd.exe"), "/C", cmdline)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: 0x00000008 | 0x00000200} // DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP
	return cmd.Start()
}

func copyFile(src, dst string) error {
	in, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	return os.WriteFile(dst, in, 0o755)
}

// applyUpdate swaps the running executable for newExe and restarts the service.
// A running .exe can be renamed but not overwritten, so the old file is moved aside.
func applyUpdate(newExe string) error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	old := exe + ".old"
	_ = os.Remove(old)
	if err := os.Rename(exe, old); err != nil {
		return err
	}
	if err := copyFile(newExe, exe); err != nil {
		_ = os.Remove(exe)
		_ = os.Rename(old, exe) // roll back
		return err
	}
	return detached(`timeout /T 3 /NOBREAK >nul & net stop ` + ServiceName + ` & net start ` + ServiceName)
}

// CleanupOldBinary removes the leftover from a previous self-update.
func CleanupOldBinary() {
	if exe, err := os.Executable(); err == nil {
		_ = os.Remove(exe + ".old")
	}
}

var reGUIDBraced = regexp.MustCompile(`^\{[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\}$`)

func uninstallSelf() error {
	code := regString(agentRegKey, "ProductCode")
	if !reGUIDBraced.MatchString(code) {
		return errors.New("product code not found in the registry; uninstall from Apps & features instead")
	}
	return detached(`timeout /T 3 /NOBREAK >nul & msiexec.exe /x ` + code + ` /qn /norestart`)
}

// ---- starting processes inside a user session ----

// launchInSession starts cmdline as SYSTEM inside the given session and
// returns the process handle. The caller must close it (or terminate the process).
func launchInSession(sessionID uint32, cmdline, desktop string) (syscall.Handle, error) {
	cur, err := syscall.GetCurrentProcess()
	if err != nil {
		return 0, err
	}
	var tok syscall.Token
	if err := syscall.OpenProcessToken(cur, syscall.TOKEN_DUPLICATE|syscall.TOKEN_QUERY, &tok); err != nil {
		return 0, fmt.Errorf("OpenProcessToken: %w", err)
	}
	defer tok.Close()
	const maximumAllowed = 0x02000000
	const securityImpersonation = 2
	const tokenPrimary = 1
	var dup syscall.Handle
	if r, _, e := advapi32.NewProc("DuplicateTokenEx").Call(uintptr(tok), maximumAllowed, 0, securityImpersonation, tokenPrimary,
		uintptr(unsafe.Pointer(&dup))); r == 0 {
		return 0, fmt.Errorf("DuplicateTokenEx: %v", e)
	}
	defer syscall.CloseHandle(dup)
	const tokenSessionID = 12
	if r, _, e := advapi32.NewProc("SetTokenInformation").Call(uintptr(dup), tokenSessionID,
		uintptr(unsafe.Pointer(&sessionID)), 4); r == 0 {
		return 0, fmt.Errorf("SetTokenInformation: %v", e)
	}
	cl, err := syscall.UTF16FromString(cmdline)
	if err != nil {
		return 0, err
	}
	dsk, _ := syscall.UTF16PtrFromString(desktop)
	si := syscall.StartupInfo{Desktop: dsk}
	si.Cb = uint32(unsafe.Sizeof(si))
	var pi syscall.ProcessInformation
	r, _, e := advapi32.NewProc("CreateProcessAsUserW").Call(uintptr(dup), 0, uintptr(unsafe.Pointer(&cl[0])), 0, 0, 0,
		createNoWindow, 0, 0, uintptr(unsafe.Pointer(&si)), uintptr(unsafe.Pointer(&pi)))
	if r == 0 {
		return 0, fmt.Errorf("CreateProcessAsUser: %v", e)
	}
	syscall.CloseHandle(pi.Thread)
	return pi.Process, nil
}

func launchHelper(ctx context.Context, hl helperLaunch) (func(), error) {
	sid, ok := consoleSessionID()
	if !ok {
		return nil, errors.New("this PC has no interactive console session right now")
	}
	exe, err := os.Executable()
	if err != nil {
		return nil, err
	}
	cl := fmt.Sprintf(`"%s" helper --addr %s --token %s --consent %s`, exe, hl.Addr, hl.Token, hl.Consent)
	if hl.ViewOnly {
		cl += " --viewonly"
	}
	h, err := launchInSession(sid, cl, `winsta0\default`)
	if err != nil {
		return nil, err
	}
	var once sync.Once
	stop := func() {
		once.Do(func() {
			_ = syscall.TerminateProcess(h, 1)
			_ = syscall.CloseHandle(h)
		})
	}
	go func() { <-ctx.Done(); stop() }()
	return stop, nil
}
