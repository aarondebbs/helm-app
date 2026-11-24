package agent

import (
	"context"
	"os"
	"syscall"
	"time"
	"unsafe"
)

var (
	pWTSEnumSessions = wtsapi32.NewProc("WTSEnumerateSessionsW")
	pWTSQueryToken   = wtsapi32.NewProc("WTSQueryUserToken")
	userenv          = syscall.NewLazyDLL("userenv.dll")
	pCreateEnvBlock  = userenv.NewProc("CreateEnvironmentBlock")
	pDestroyEnvBlock = userenv.NewProc("DestroyEnvironmentBlock")
)

type wtsSessionInfo struct {
	ID    uint32
	Name  *uint16
	State int32
}

// activeSessions lists the ids of user sessions that are logged in and on screen (not session 0).
func activeSessions() []uint32 {
	var p unsafe.Pointer
	var n uint32
	if r, _, _ := pWTSEnumSessions.Call(0, 0, 1, uintptr(unsafe.Pointer(&p)), uintptr(unsafe.Pointer(&n))); r == 0 || p == nil {
		return nil
	}
	defer procWTSFreeMemory.Call(uintptr(p))
	var out []uint32
	for _, s := range unsafe.Slice((*wtsSessionInfo)(p), int(n)) {
		if s.ID != 0 && s.State == 0 { // WTSActive
			out = append(out, s.ID)
		}
	}
	return out
}

// launchAsUser starts a process in a session with that user's own rights (not SYSTEM), so everything it opens runs as them.
func launchAsUser(sessionID uint32, cmdline string) (syscall.Handle, error) {
	var tok syscall.Token
	if r, _, e := pWTSQueryToken.Call(uintptr(sessionID), uintptr(unsafe.Pointer(&tok))); r == 0 {
		return 0, e
	}
	defer tok.Close()
	var env uintptr
	if r, _, _ := pCreateEnvBlock.Call(uintptr(unsafe.Pointer(&env)), uintptr(tok), 0); r != 0 {
		defer pDestroyEnvBlock.Call(env)
	}
	cl, err := syscall.UTF16FromString(cmdline)
	if err != nil {
		return 0, err
	}
	dsk, _ := syscall.UTF16PtrFromString(`winsta0\default`)
	si := syscall.StartupInfo{Desktop: dsk}
	si.Cb = uint32(unsafe.Sizeof(si))
	var pi syscall.ProcessInformation
	const createUnicodeEnv = 0x400
	r, _, e := advapi32.NewProc("CreateProcessAsUserW").Call(uintptr(tok), 0, uintptr(unsafe.Pointer(&cl[0])), 0, 0, 0,
		createNoWindow|createUnicodeEnv, env, 0, uintptr(unsafe.Pointer(&si)), uintptr(unsafe.Pointer(&pi)))
	if r == 0 {
		return 0, e
	}
	syscall.CloseHandle(pi.Thread)
	return pi.Process, nil
}

// trayKeeper makes sure each signed-in user has the tray icon running, and removes the icons when the service stops
// (a running tray would keep helm-agent.exe locked during an update or uninstall).
func (a *Agent) trayKeeper(ctx context.Context) {
	exe, err := os.Executable()
	if err != nil {
		return
	}
	running := map[uint32]syscall.Handle{}
	stopAll := func() {
		for sid, h := range running {
			_ = syscall.TerminateProcess(h, 0)
			_ = syscall.CloseHandle(h)
			delete(running, sid)
		}
	}
	defer stopAll()
	tick := func() {
		live := map[uint32]bool{}
		for _, sid := range activeSessions() {
			live[sid] = true
			if h, ok := running[sid]; ok {
				if ev, _ := syscall.WaitForSingleObject(h, 0); ev != syscall.WAIT_TIMEOUT {
					_ = syscall.CloseHandle(h)
					delete(running, sid)
				} else {
					continue
				}
			}
			if h, err := launchAsUser(sid, `"`+exe+`" tray`); err == nil {
				running[sid] = h
			} else {
				a.log.Printf("tray: could not start in session %d: %v", sid, err)
			}
		}
		for sid, h := range running { // the user signed out
			if !live[sid] {
				_ = syscall.TerminateProcess(h, 0)
				_ = syscall.CloseHandle(h)
				delete(running, sid)
			}
		}
	}
	tick()
	t := time.NewTicker(15 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			tick()
		}
	}
}
