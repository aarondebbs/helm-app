package agent

import (
	"fmt"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"
)

// The chat window: a plain Win32 window made of a read-only text box, a one-line input and a Send button. It lives on
// the tray's UI thread (the tray's message loop dispatches for it). If it cannot be created, the tray falls back to the
// browser page (see openChatBrowser).

const (
	wsOverlapped  = 0x00CF0000 // overlapped window with caption, sizing frame and buttons
	wsChild       = 0x40000000
	wsVisible     = 0x10000000
	wsBorder      = 0x00800000
	wsVScroll     = 0x00200000
	wsTabStop     = 0x00010000
	esMultiline   = 0x0004
	esAutoVScroll = 0x0040
	esAutoHScroll = 0x0080
	esReadOnly    = 0x0800
	bsDefPush     = 0x0001
	wmSize        = 0x0005
	wmClose       = 0x0010
	wmSetFont     = 0x0030
	wmChatShow    = 0x8000 + 2 // posted to the tray window: show the chat window
	wmChatState   = 0x8000 + 3 // posted to the chat window: new conversation text is ready
	wmChatSent    = 0x8000 + 4 // posted to the chat window: a send finished (wParam 1 = ok)
	emSetSel      = 0x00B1
	emScrollCaret = 0x00B7
	emLimitText   = 0x00C5
	swHide        = 0
	swRestore     = 9
	idSendBtn     = 1 // IDOK: Enter in the input box presses the default button, which carries this id
	timerChat     = 7
)

var (
	pShowWindow       = user32t.NewProc("ShowWindow")
	pMoveWindow       = user32t.NewProc("MoveWindow")
	pSetWindowText    = user32t.NewProc("SetWindowTextW")
	pGetWindowText    = user32t.NewProc("GetWindowTextW")
	pGetTextLen       = user32t.NewProc("GetWindowTextLengthW")
	pSendMessage      = user32t.NewProc("SendMessageW")
	pGetClientRect    = user32t.NewProc("GetClientRect")
	pSetFocus         = user32t.NewProc("SetFocus")
	pIsDialogMessage  = user32t.NewProc("IsDialogMessageW")
	pFlashWindowEx    = user32t.NewProc("FlashWindowEx")
	pLoadCursor       = user32t.NewProc("LoadCursorW")
	pIsWindow         = user32t.NewProc("IsWindow")
	pDestroyWindow    = user32t.NewProc("DestroyWindow")
	pKillTimer        = user32t.NewProc("KillTimer")
	pGetForegroundWnd = user32t.NewProc("GetForegroundWindow")
	pCreateFont       = syscall.NewLazyDLL("gdi32.dll").NewProc("CreateFontW")
)

type flashInfo struct {
	Size    uint32
	Wnd     uintptr
	Flags   uint32
	Count   uint32
	Timeout uint32
}

type chatWin struct {
	wnd, log, input, send, status, font uintptr
	mu                                  sync.Mutex
	st                                  TrayStatus // where the local agent's chat endpoint is
	pending                             *chatState
	pendErr                             string
	lastText                            string
	lastAdmin                           int // number of administrator messages already seen
	primed                              bool
	sending                             bool
}

var cw chatWin

func chatRegistered() bool { return cw.font != 0 }

// openChatWindow asks the tray's UI thread to show the chat window.
func openChatWindow(s TrayStatus) {
	if chatURL(s) == "" {
		messageBox("Helm Agent", "The agent is not ready yet. Try again in a moment.")
		return
	}
	cw.mu.Lock()
	cw.st = s
	cw.mu.Unlock()
	if tray.wnd == 0 {
		openChatBrowser(s)
		return
	}
	pPostMessage.Call(tray.wnd, wmChatShow, 0, 0)
}

// showChatWindow runs on the tray's UI thread.
func showChatWindow() {
	if w := cw.wnd; w != 0 {
		if r, _, _ := pIsWindow.Call(w); r != 0 {
			pShowWindow.Call(w, swRestore)
			pSetForegroundWnd.Call(w)
			pSetFocus.Call(cw.input)
			go chatPoll()
			return
		}
		cw.wnd = 0
	}
	hinst, _, _ := pGetModuleHandle.Call(0)
	cls := wstr("HelmAgentChat")
	if !chatRegistered() {
		cur, _, _ := pLoadCursor.Call(0, 32512)                                                                                      // IDC_ARROW
		wc := wndClassEx{Instance: hinst, ClassName: cls, WndProc: syscall.NewCallback(chatWndProc), Cursor: cur, Background: 5 + 1} // COLOR_WINDOW + 1
		wc.Size = uint32(unsafe.Sizeof(wc))
		if r, _, _ := pRegisterClassEx.Call(uintptr(unsafe.Pointer(&wc))); r == 0 {
			fallbackChat()
			return
		}
		f, _, _ := pCreateFont.Call(uintptr(^uint32(14)+1), 0, 0, 0, 400, 0, 0, 0, 1, 0, 0, 5, 0, uintptr(unsafe.Pointer(wstr("Segoe UI")))) // -15 px, default charset, ClearType
		cw.font = f
		if cw.font == 0 {
			cw.font = 1 // registered; use the system font
		}
	}
	title := "Chat with support"
	if cw.st.Org != "" {
		title = cw.st.Org + " support"
	}
	w, _, _ := pCreateWindowEx.Call(0, uintptr(unsafe.Pointer(cls)), uintptr(unsafe.Pointer(wstr(title))), wsOverlapped|wsVisible, 0x80000000, 0x80000000, 420, 560, 0, 0, hinst, 0)
	if w == 0 {
		fallbackChat()
		return
	}
	cw.wnd = w
	mk := func(class string, style uintptr, id uintptr, text string) uintptr {
		c, _, _ := pCreateWindowEx.Call(0, uintptr(unsafe.Pointer(wstr(class))), uintptr(unsafe.Pointer(wstr(text))), wsChild|wsVisible|style, 0, 0, 10, 10, w, id, hinst, 0)
		if c != 0 && cw.font > 1 {
			pSendMessage.Call(c, wmSetFont, cw.font, 1)
		}
		return c
	}
	cw.status = mk("STATIC", 0, 100, "Connecting…")
	cw.log = mk("EDIT", wsBorder|wsVScroll|esMultiline|esAutoVScroll|esReadOnly, 101, "")
	cw.input = mk("EDIT", wsBorder|wsTabStop|esAutoHScroll, 102, "")
	cw.send = mk("BUTTON", wsTabStop|bsDefPush, idSendBtn, "Send")
	pSendMessage.Call(cw.log, emLimitText, 0, 0)
	pSendMessage.Call(cw.input, emLimitText, 2000, 0)
	chatLayout()
	cw.lastText, cw.primed = "", false
	pSetTimer.Call(w, timerChat, uintptr((2 * time.Second).Milliseconds()), 0)
	pSetForegroundWnd.Call(w)
	pSetFocus.Call(cw.input)
	go chatPoll()
}

func fallbackChat() {
	cw.mu.Lock()
	s := cw.st
	cw.mu.Unlock()
	go openChatBrowser(s)
}

func chatLayout() {
	var r rect
	pGetClientRect.Call(cw.wnd, uintptr(unsafe.Pointer(&r)))
	w, h := r.R-r.L, r.B-r.T
	const m, bh, sh = 10, 28, 18
	pMoveWindow.Call(cw.status, m, 8, uintptr(w-2*m), sh, 1)
	pMoveWindow.Call(cw.log, m, 30, uintptr(w-2*m), uintptr(h-30-m-bh-8), 1)
	pMoveWindow.Call(cw.input, m, uintptr(h-m-bh), uintptr(w-2*m-88), bh, 1)
	pMoveWindow.Call(cw.send, uintptr(w-m-80), uintptr(h-m-bh), 80, bh, 1)
}

// chatPoll fetches the conversation off the UI thread and hands it over with a posted message.
func chatPoll() {
	cw.mu.Lock()
	s := cw.st
	cw.mu.Unlock()
	st, err := chatFetch(s)
	cw.mu.Lock()
	if err != nil {
		cw.pending, cw.pendErr = nil, err.Error()
	} else {
		cw.pending, cw.pendErr = &st, ""
	}
	w := cw.wnd
	cw.mu.Unlock()
	if w != 0 {
		pPostMessage.Call(w, wmChatState, 0, 0)
	}
}

func chatTranscript(msgs []chatLine) string {
	var b strings.Builder
	for _, m := range msgs {
		who := "Support"
		if m.From == "user" {
			who = "You"
		}
		fmt.Fprintf(&b, "[%s] %s:\r\n%s\r\n\r\n", m.At.Local().Format("15:04"), who, strings.ReplaceAll(strings.ReplaceAll(m.Text, "\r\n", "\n"), "\n", "\r\n"))
	}
	return b.String()
}

func chatApply() {
	cw.mu.Lock()
	st, pe := cw.pending, cw.pendErr
	cw.mu.Unlock()
	if st == nil {
		pSetWindowText.Call(cw.status, uintptr(unsafe.Pointer(wstr(pe))))
		return
	}
	status := "Not connected. Messages cannot be sent right now."
	if st.Online {
		status = "Connected"
	}
	if !st.Enabled {
		status = "Chat is turned off for this PC."
	}
	pSetWindowText.Call(cw.status, uintptr(unsafe.Pointer(wstr(status))))
	text := chatTranscript(st.Messages)
	admin := 0
	for _, m := range st.Messages {
		if m.From == "admin" {
			admin++
		}
	}
	if text != cw.lastText {
		cw.lastText = text
		pSetWindowText.Call(cw.log, uintptr(unsafe.Pointer(wstr(text))))
		n := uintptr(len(text))
		pSendMessage.Call(cw.log, emSetSel, n, n)
		pSendMessage.Call(cw.log, emScrollCaret, 0, 0)
	}
	if cw.primed && admin > cw.lastAdmin {
		if fg, _, _ := pGetForegroundWnd.Call(); fg != cw.wnd {
			fi := flashInfo{Wnd: cw.wnd, Flags: 0xE, Count: 4} // FLASHW_TRAY | FLASHW_TIMERNOFG
			fi.Size = uint32(unsafe.Sizeof(fi))
			pFlashWindowEx.Call(uintptr(unsafe.Pointer(&fi)))
		}
	}
	cw.lastAdmin, cw.primed = admin, true
}

func chatSend() {
	cw.mu.Lock()
	busy := cw.sending
	s := cw.st
	cw.mu.Unlock()
	if busy {
		return
	}
	n, _, _ := pGetTextLen.Call(cw.input)
	if n == 0 {
		return
	}
	buf := make([]uint16, n+1)
	pGetWindowText.Call(cw.input, uintptr(unsafe.Pointer(&buf[0])), n+1)
	text := strings.TrimSpace(syscall.UTF16ToString(buf))
	if text == "" {
		return
	}
	cw.mu.Lock()
	cw.sending = true
	w := cw.wnd
	cw.mu.Unlock()
	go func() {
		err := chatPost(s, text)
		cw.mu.Lock()
		cw.sending = false
		if err != nil {
			cw.pending, cw.pendErr = nil, err.Error()
		}
		cw.mu.Unlock()
		ok := uintptr(1)
		if err != nil {
			ok = 0
		}
		pPostMessage.Call(w, wmChatSent, ok, 0)
		if err == nil {
			chatPoll()
		}
	}()
}

func chatWndProc(hwnd, m, wp, lp uintptr) uintptr {
	switch uint32(m) {
	case wmSize:
		if cw.log != 0 {
			chatLayout()
		}
		return 0
	case wmCommand:
		if wp&0xFFFF == idSendBtn {
			chatSend()
		}
		return 0
	case wmTimer:
		if wp == timerChat {
			go chatPoll()
		}
		return 0
	case wmChatState:
		chatApply()
		return 0
	case wmChatSent:
		if wp == 1 {
			pSetWindowText.Call(cw.input, uintptr(unsafe.Pointer(wstr(""))))
		} else {
			chatApply()
		}
		pSetFocus.Call(cw.input)
		return 0
	case wmClose:
		pDestroyWindow.Call(hwnd)
		return 0
	case wmDestroy:
		pKillTimer.Call(hwnd, timerChat)
		cw.wnd, cw.log, cw.input, cw.send, cw.status = 0, 0, 0, 0, 0
		return 0 // the tray owns the message loop; do not quit it
	}
	r, _, _ := pDefWindowProc.Call(hwnd, m, wp, lp)
	return r
}

// chatNotifyUser is only needed where the service runs outside the user's session; on Windows the tray handles it.
func (a *Agent) chatNotifyUser(string) {}

// RunChat is `helm-agent chat`: open the chat from a command line or shortcut.
func RunChat(args []string) int {
	s, err := readTrayStatus()
	if err != nil {
		messageBox("Helm Agent", "The Helm agent is not running on this PC.")
		return 1
	}
	openChatBrowser(s)
	return 0
}
