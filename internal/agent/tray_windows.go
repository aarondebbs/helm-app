package agent

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"
)

// The tray icon: a small process that runs as the signed-in user, shows the Helm icon in the taskbar's notification
// area and opens a menu with the agent's status. The service starts one per active user session (see trayKeeper).
// It reads the status the service writes to PublicDir(); the only thing it can ask of the service is "request support".

//go:embed trayicons/ok.png
var iconOK []byte

//go:embed trayicons/warn.png
var iconWarn []byte

//go:embed trayicons/off.png
var iconOff []byte

const (
	wmApp          = 0x8000 + 1
	wmLButtonUp    = 0x0202
	wmRButtonUp    = 0x0205
	wmContextMenu  = 0x007B
	wmTimer        = 0x0113
	wmDestroy      = 0x0002
	wmCommand      = 0x0111
	nimAdd         = 0
	nimModify      = 1
	nimDelete      = 2
	nifMessage     = 1
	nifIcon        = 2
	nifTip         = 4
	mfString       = 0
	mfGrayed       = 1
	mfSeparator    = 0x800
	tpmReturnCmd   = 0x100
	tpmRightButton = 0x2
	tpmBottomAlign = 0x20
	swShow         = 5
	idSupport      = 2
	idAbout        = 3
)

var (
	shell32  = syscall.NewLazyDLL("shell32.dll")
	user32t  = syscall.NewLazyDLL("user32.dll")
	k32t     = syscall.NewLazyDLL("kernel32.dll")
	pNotify  = shell32.NewProc("Shell_NotifyIconW")
	pShellEx = shell32.NewProc("ShellExecuteW")

	pRegisterClassEx   = user32t.NewProc("RegisterClassExW")
	pCreateWindowEx    = user32t.NewProc("CreateWindowExW")
	pDefWindowProc     = user32t.NewProc("DefWindowProcW")
	pGetMessage        = user32t.NewProc("GetMessageW")
	pTranslateMessage  = user32t.NewProc("TranslateMessage")
	pDispatchMessage   = user32t.NewProc("DispatchMessageW")
	pPostQuitMessage   = user32t.NewProc("PostQuitMessage")
	pCreatePopupMenu   = user32t.NewProc("CreatePopupMenu")
	pAppendMenu        = user32t.NewProc("AppendMenuW")
	pTrackPopupMenu    = user32t.NewProc("TrackPopupMenu")
	pDestroyMenu       = user32t.NewProc("DestroyMenu")
	pSetForegroundWnd  = user32t.NewProc("SetForegroundWindow")
	pGetCursorPos      = user32t.NewProc("GetCursorPos")
	pSetTimer          = user32t.NewProc("SetTimer")
	pRegWinMessage     = user32t.NewProc("RegisterWindowMessageW")
	pPostMessage       = user32t.NewProc("PostMessageW")
	pCreateIconFromRes = user32t.NewProc("CreateIconFromResourceEx")
	pMessageBox        = user32t.NewProc("MessageBoxW")
	pGetModuleHandle   = k32t.NewProc("GetModuleHandleW")
	pCreateMutex       = k32t.NewProc("CreateMutexW")
)

type notifyIconData struct {
	Size            uint32
	Wnd             uintptr
	ID              uint32
	Flags           uint32
	CallbackMessage uint32
	Icon            uintptr
	Tip             [128]uint16
	State           uint32
	StateMask       uint32
	Info            [256]uint16
	Version         uint32
	InfoTitle       [64]uint16
	InfoFlags       uint32
	GUID            [16]byte
	BalloonIcon     uintptr
}

type point struct{ X, Y int32 }

type msg struct {
	Wnd     uintptr
	Message uint32
	WParam  uintptr
	LParam  uintptr
	Time    uint32
	Pt      point
}

type trayApp struct {
	wnd      uintptr
	icons    [3]uintptr
	created  uint32 // TaskbarCreated message id
	shown    bool
	lastIcon int
	mu       sync.Mutex
	st       TrayStatus
	stale    bool
}

var tray trayApp

func wstr(s string) *uint16 { p, _ := syscall.UTF16PtrFromString(s); return p }

func loadIcon(png []byte) uintptr {
	r, _, _ := pCreateIconFromRes.Call(uintptr(unsafe.Pointer(&png[0])), uintptr(len(png)), 1, 0x00030000, 32, 32, 0)
	return r
}

// readStatus loads the status file the service keeps up to date.
func (t *trayApp) readStatus() {
	b, err := os.ReadFile(statusPath())
	var s TrayStatus
	if err == nil {
		err = json.Unmarshal(b, &s)
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if err != nil {
		t.st, t.stale = TrayStatus{State: "offline"}, true
		t.st.ShowTray = true
		return
	}
	t.st, t.stale = s, time.Since(s.Updated) > 3*time.Minute
}

func (t *trayApp) view() (state, headline string, icon int) {
	t.mu.Lock()
	defer t.mu.Unlock()
	st := t.st.State
	if t.stale {
		st = "stopped"
	}
	switch st {
	case "connected":
		return st, "Connected and protected", 0
	case "pending":
		return st, "Waiting for approval", 1
	case "connecting", "starting":
		return st, "Connecting…", 1
	case "stopped":
		return st, "Agent is not running", 2
	}
	return st, "Offline: will reconnect on its own", 2
}

func (t *trayApp) tooltip() string {
	_, head, _ := t.view()
	t.mu.Lock()
	org := t.st.Org
	t.mu.Unlock()
	if org != "" {
		return "Helm · " + org + "\n" + head
	}
	return "Helm Agent\n" + head
}

// sync adds, updates or removes the icon so it matches the latest status.
func (t *trayApp) sync() {
	t.readStatus()
	t.mu.Lock()
	show := t.st.ShowTray || t.stale || t.st.Updated.IsZero()
	t.mu.Unlock()
	_, _, ic := t.view()
	nid := t.nid()
	copy(nid.Tip[:], syscall.StringToUTF16(t.tooltip()))
	nid.Icon = t.icons[ic]
	switch {
	case show && !t.shown:
		pNotify.Call(nimAdd, uintptr(unsafe.Pointer(&nid)))
		t.shown = true
	case show:
		pNotify.Call(nimModify, uintptr(unsafe.Pointer(&nid)))
	case t.shown:
		pNotify.Call(nimDelete, uintptr(unsafe.Pointer(&nid)))
		t.shown = false
	}
}

func (t *trayApp) nid() notifyIconData {
	var n notifyIconData
	n.Size = uint32(unsafe.Sizeof(n))
	n.Wnd, n.ID, n.Flags, n.CallbackMessage = t.wnd, 1, nifMessage|nifIcon|nifTip, wmApp
	return n
}

func (t *trayApp) menu() {
	t.readStatus()
	state, head, _ := t.view()
	t.mu.Lock()
	s := t.st
	t.mu.Unlock()
	m, _, _ := pCreatePopupMenu.Call()
	defer pDestroyMenu.Call(m)
	add := func(flags uintptr, id uintptr, text string) {
		pAppendMenu.Call(m, flags, id, uintptr(unsafe.Pointer(wstr(text))))
	}
	title := "Helm Agent"
	if s.Org != "" {
		title = s.Org + " · Helm Agent"
	}
	add(mfString|mfGrayed, 0, title)
	add(mfSeparator, 0, "")
	add(mfString|mfGrayed, 0, head)
	if s.Computer != "" {
		add(mfString|mfGrayed, 0, "This PC: "+s.Computer)
	}
	if !s.Updated.IsZero() && !t.stale && state == "connected" {
		add(mfString|mfGrayed, 0, "Last check-in: "+s.Updated.Local().Format("15:04"))
	}
	if s.SupportText != "" {
		add(mfSeparator, 0, "")
		for _, ln := range strings.Split(wrapText(s.SupportText, 44), "\n") {
			add(mfString|mfGrayed, 0, ln)
		}
	}
	add(mfSeparator, 0, "")
	if s.AllowSupport {
		fl := uintptr(mfString)
		if state != "connected" {
			fl |= mfGrayed
		}
		add(fl, idSupport, "Request support")
	}
	add(mfSeparator, 0, "")
	add(mfString, idAbout, "About Helm Agent "+s.Version)

	var p point
	pGetCursorPos.Call(uintptr(unsafe.Pointer(&p)))
	pSetForegroundWnd.Call(t.wnd) // required so the menu closes when the user clicks elsewhere
	cmd, _, _ := pTrackPopupMenu.Call(m, tpmReturnCmd|tpmRightButton|tpmBottomAlign, uintptr(p.X), uintptr(p.Y), 0, t.wnd, 0)
	pPostMessage.Call(t.wnd, 0, 0, 0)
	switch cmd {
	case idSupport:
		go t.requestSupport(s)
	case idAbout:
		go messageBox("Helm Agent", fmt.Sprintf("Helm Agent %s\nThis PC: %s\nServer: %s\n\nHelm lets your administrator keep this PC updated and secure.\nThe agent never sees your files or passwords unless you start a remote session.", s.Version, s.Computer, s.Server))
	}
}

func wrapText(s string, n int) string {
	var out, line []string
	l := 0
	for _, w := range strings.Fields(s) {
		if l+len(w) > n && len(line) > 0 {
			out = append(out, strings.Join(line, " "))
			line, l = nil, 0
		}
		line = append(line, w)
		l += len(w) + 1
	}
	if len(line) > 0 {
		out = append(out, strings.Join(line, " "))
	}
	return strings.Join(out, "\n")
}

func messageBox(title, text string) {
	pMessageBox.Call(0, uintptr(unsafe.Pointer(wstr(text))), uintptr(unsafe.Pointer(wstr(title))), 0x40|0x10000) // information, foreground
}

func (t *trayApp) requestSupport(s TrayStatus) {
	if s.Control == "" {
		messageBox("Helm Agent", "The agent is not ready yet. Try again in a moment.")
		return
	}
	body, _ := json.Marshal(map[string]string{"msg": "Support requested from the tray on " + s.Computer + " by " + os.Getenv("USERNAME")})
	req, _ := http.NewRequest("POST", "http://"+s.Control+"/support", bytes.NewReader(body))
	req.Header.Set("X-Helm-Tray", "1")
	resp, err := (&http.Client{Timeout: 8 * time.Second}).Do(req)
	switch {
	case err != nil:
		messageBox("Helm Agent", "Could not reach the Helm agent on this PC.")
	case resp.StatusCode == http.StatusNoContent:
		messageBox("Helm Agent", "Your request was sent. Your administrator will see it in the Helm portal.")
	case resp.StatusCode == http.StatusTooManyRequests:
		messageBox("Helm Agent", "A request was sent a moment ago. Please wait a minute before sending another.")
	default:
		messageBox("Helm Agent", "The request could not be sent because this PC is not connected to the portal right now.")
	}
	if resp != nil {
		resp.Body.Close()
	}
}

func trayWndProc(hwnd, m, wp, lp uintptr) uintptr {
	switch uint32(m) {
	case wmApp:
		switch uint32(lp) {
		case wmLButtonUp, wmRButtonUp, wmContextMenu:
			tray.menu()
		}
		return 0
	case wmTimer:
		tray.sync()
		return 0
	case wmDestroy:
		nid := tray.nid()
		pNotify.Call(nimDelete, uintptr(unsafe.Pointer(&nid)))
		pPostQuitMessage.Call(0)
		return 0
	}
	if tray.created != 0 && uint32(m) == tray.created { // Explorer restarted: put the icon back
		tray.shown = false
		tray.sync()
		return 0
	}
	r, _, _ := pDefWindowProc.Call(hwnd, m, wp, lp)
	return r
}

// RunTray is the entry point of `helm-agent tray`. It runs until the user signs out.
func RunTray(args []string) int {
	runtime.LockOSThread()
	// one icon per user session
	name := wstr(`Local\HelmAgentTray`)
	h, _, e := pCreateMutex.Call(0, 1, uintptr(unsafe.Pointer(name)))
	if h == 0 || e == syscall.ERROR_ALREADY_EXISTS {
		return 0
	}
	hinst, _, _ := pGetModuleHandle.Call(0)
	cls := wstr("HelmAgentTray")
	wc := wndClassEx{Instance: hinst, ClassName: cls, WndProc: syscall.NewCallback(trayWndProc)}
	wc.Size = uint32(unsafe.Sizeof(wc))
	if r, _, _ := pRegisterClassEx.Call(uintptr(unsafe.Pointer(&wc))); r == 0 {
		return 1
	}
	rm, _, _ := pRegWinMessage.Call(uintptr(unsafe.Pointer(wstr("TaskbarCreated"))))
	tray.created = uint32(rm)
	w, _, _ := pCreateWindowEx.Call(0, uintptr(unsafe.Pointer(cls)), uintptr(unsafe.Pointer(wstr("Helm Agent"))), 0, 0, 0, 0, 0, 0, 0, hinst, 0)
	if w == 0 {
		return 1
	}
	tray.wnd = w
	for i, b := range [][]byte{iconOK, iconWarn, iconOff} {
		tray.icons[i] = loadIcon(b)
	}
	tray.sync()
	pSetTimer.Call(w, 1, uintptr((5 * time.Second).Milliseconds()), 0)
	var m msg
	for {
		r, _, _ := pGetMessage.Call(uintptr(unsafe.Pointer(&m)), 0, 0, 0)
		if int32(r) <= 0 {
			break
		}
		pTranslateMessage.Call(uintptr(unsafe.Pointer(&m)))
		pDispatchMessage.Call(uintptr(unsafe.Pointer(&m)))
	}
	return 0
}
