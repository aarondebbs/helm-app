//go:build windows

package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"image"
	"image/jpeg"
	"net/http"
	"os"
	"runtime"
	"sync"
	"syscall"
	"time"
	"unicode/utf16"
	"unsafe"

	"helm/internal/ws"
)

// The helper runs as SYSTEM inside the interactive console session. It shows
// the consent prompt and the "session active" banner, captures the screen of
// whichever desktop currently receives input (including the sign-in screen) and
// injects mouse/keyboard input. It talks to the service over a loopback
// WebSocket; the service relays frames to the server.

var (
	procOpenInputDesktop    = user32.NewProc("OpenInputDesktop")
	procSetThreadDesktop    = user32.NewProc("SetThreadDesktop")
	procCloseDesktop        = user32.NewProc("CloseDesktop")
	procGetUserObjectInfo   = user32.NewProc("GetUserObjectInformationW")
	procGetSystemMetrics    = user32.NewProc("GetSystemMetrics")
	procSetProcessDPIAware  = user32.NewProc("SetProcessDPIAware")
	procGetDC               = user32.NewProc("GetDC")
	procReleaseDC           = user32.NewProc("ReleaseDC")
	procSendInput           = user32.NewProc("SendInput")
	procMessageBox          = user32.NewProc("MessageBoxW")
	procRegisterClassEx     = user32.NewProc("RegisterClassExW")
	procCreateWindowEx      = user32.NewProc("CreateWindowExW")
	procDefWindowProc       = user32.NewProc("DefWindowProcW")
	procGetMessage          = user32.NewProc("GetMessageW")
	procTranslateMessage    = user32.NewProc("TranslateMessage")
	procDispatchMessage     = user32.NewProc("DispatchMessageW")
	procPostQuitMessage     = user32.NewProc("PostQuitMessage")
	procDestroyWindow       = user32.NewProc("DestroyWindow")
	procBeginPaint          = user32.NewProc("BeginPaint")
	procEndPaint            = user32.NewProc("EndPaint")
	procDrawText            = user32.NewProc("DrawTextW")
	procGetClientRect       = user32.NewProc("GetClientRect")
	procLoadCursor          = user32.NewProc("LoadCursorW")
	procGetModuleHandle     = kernel32.NewProc("GetModuleHandleW")
	procCreateDIBSection    = gdi32.NewProc("CreateDIBSection")
	procEnumDisplayMonitors = user32.NewProc("EnumDisplayMonitors")
	procGetMonitorInfo      = user32.NewProc("GetMonitorInfoW")
	procOpenClipboard       = user32.NewProc("OpenClipboard")
	procCloseClipboard      = user32.NewProc("CloseClipboard")
	procEmptyClipboard      = user32.NewProc("EmptyClipboard")
	procGetClipboardData    = user32.NewProc("GetClipboardData")
	procSetClipboardData    = user32.NewProc("SetClipboardData")
	procGlobalAlloc         = kernel32.NewProc("GlobalAlloc")
	procGlobalLock          = kernel32.NewProc("GlobalLock")
	procGlobalUnlock        = kernel32.NewProc("GlobalUnlock")
	procGlobalSize          = kernel32.NewProc("GlobalSize")
	procCreateCompatibleDC  = gdi32.NewProc("CreateCompatibleDC")
	procCreateCompatibleBmp = gdi32.NewProc("CreateCompatibleBitmap")
	procSelectObject        = gdi32.NewProc("SelectObject")
	procBitBlt              = gdi32.NewProc("BitBlt")
	procGetDIBits           = gdi32.NewProc("GetDIBits")
	procDeleteObject        = gdi32.NewProc("DeleteObject")
	procDeleteDC            = gdi32.NewProc("DeleteDC")
	procCreateSolidBrush    = gdi32.NewProc("CreateSolidBrush")
	procSetBkMode           = gdi32.NewProc("SetBkMode")
	procSetTextColor        = gdi32.NewProc("SetTextColor")
)

// RunHelper is the entry point of `helm-agent helper ...`.
func RunHelper(args []string) int {
	fs := flag.NewFlagSet("helper", flag.ContinueOnError)
	addr := fs.String("addr", "", "service rendezvous address")
	token := fs.String("token", "", "rendezvous token")
	consent := fs.String("consent", ConsentPromptIfPresent, "consent mode")
	viewOnly := fs.Bool("viewonly", false, "view-only session")
	if err := fs.Parse(args); err != nil || *addr == "" || *token == "" {
		return 2
	}
	procSetProcessDPIAware.Call()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	h := http.Header{}
	h.Set("X-Helm-Token", *token)
	c, err := ws.Dial(ctx, "ws://"+*addr+"/helper", ws.DialOptions{Header: h})
	if err != nil {
		return 3
	}
	defer c.Close(ws.CloseNormal, "")
	c.SetReadLimit(1 << 20)
	c.KeepAlive(10 * time.Second)

	// --- consent ---
	present := userPresentOnDesktop()
	need := *consent == ConsentAlwaysPrompt || (*consent == ConsentPromptIfPresent && present)
	if need {
		if !askConsent(60 * time.Second) {
			_ = sendJSON(c, map[string]any{"t": "consent", "ok": false, "msg": "the person at the PC declined or did not answer the request"})
			time.Sleep(300 * time.Millisecond)
			return 0
		}
	}
	_ = sendJSON(c, map[string]any{"t": "consent", "ok": true})

	// --- wait for start ---
	c.SetIdleTimeout(60 * time.Second)
	for {
		op, msg, err := c.ReadMessage()
		if err != nil {
			return 0
		}
		if op == ws.OpText && bytes.Contains(msg, []byte(`"start"`)) {
			break
		}
	}
	c.SetIdleTimeout(0)

	go runBanner(func() { // clicking the banner ends the session
		c.Close(ws.CloseNormal, "ended by the person at the PC")
		os.Exit(0)
	})

	in := make(chan InputMsg, 512)
	go func() {
		defer cancel()
		for {
			op, msg, err := c.ReadMessage()
			if err != nil {
				return
			}
			if op != ws.OpText || *viewOnly && !viewOnlyMsg(msg) {
				continue
			}
			var m InputMsg
			if json.Unmarshal(msg, &m) != nil {
				continue
			}
			if m.T == "mm" {
				select {
				case in <- m:
				default: // drop stale mouse moves when the queue is full
				}
				continue
			}
			select {
			case in <- m:
			case <-ctx.Done():
				return
			}
		}
	}()
	runtime.LockOSThread() // the capture loop owns this thread (and its desktop)
	captureLoop(ctx, c, in, *viewOnly)
	return 0
}

// ---- desktop helpers ----

func inputDesktop() (uintptr, string) {
	const genericAll = 0x10000000
	const maximumAllowed = 0x02000000
	h, _, _ := procOpenInputDesktop.Call(0, 0, genericAll)
	if h == 0 {
		h, _, _ = procOpenInputDesktop.Call(0, 0, maximumAllowed)
	}
	if h == 0 {
		return 0, ""
	}
	const uoiName = 2
	buf := make([]uint16, 128)
	var need uint32
	r, _, _ := procGetUserObjectInfo.Call(h, uoiName, uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)*2), uintptr(unsafe.Pointer(&need)))
	if r == 0 {
		return h, ""
	}
	return h, syscall.UTF16ToString(buf)
}

// userPresentOnDesktop is true when the normal user desktop (not the sign-in
// or lock screen) is receiving input.
func userPresentOnDesktop() bool {
	h, name := inputDesktop()
	if h != 0 {
		procCloseDesktop.Call(h)
	}
	return name == "Default"
}

func askConsent(timeout time.Duration) bool {
	host, _ := os.Hostname()
	text := "Your administrator wants to view and control this PC (" + host + ") using Helm.\n\nAllow this remote session?\n\n" +
		"A banner stays visible at the top of the screen during the session. Click it at any time to end the session."
	res := make(chan bool, 1)
	go func() {
		runtime.LockOSThread()
		const flags = 0x4 | 0x20 | 0x1000 | 0x10000 | 0x40000 // YESNO | ICONQUESTION | SYSTEMMODAL | SETFOREGROUND | TOPMOST
		t, _ := syscall.UTF16PtrFromString(text)
		c, _ := syscall.UTF16PtrFromString("Remote access request")
		r, _, _ := procMessageBox.Call(0, uintptr(unsafe.Pointer(t)), uintptr(unsafe.Pointer(c)), flags)
		res <- r == 6 // IDYES
	}()
	select {
	case ok := <-res:
		return ok
	case <-time.After(timeout):
		return false
	}
}

// ---- banner window ----

type wndClassEx struct {
	Size       uint32
	Style      uint32
	WndProc    uintptr
	ClsExtra   int32
	WndExtra   int32
	Instance   uintptr
	Icon       uintptr
	Cursor     uintptr
	Background uintptr
	MenuName   *uint16
	ClassName  *uint16
	IconSm     uintptr
}

type winMsg struct {
	Hwnd    uintptr
	Message uint32
	WParam  uintptr
	LParam  uintptr
	Time    uint32
	PtX     int32
	PtY     int32
}

type rect struct{ L, T, R, B int32 }

type paintStruct struct {
	Hdc      uintptr
	Erase    int32
	Rc       rect
	Restore  int32
	IncUpd   int32
	Reserved [32]byte
}

const bannerText = "Helm: remote session active. Click here to end it."

func runBanner(onClick func()) {
	defer func() { _ = recover() }() // the banner must never take the session down
	runtime.LockOSThread()
	hInst, _, _ := procGetModuleHandle.Call(0)
	className, _ := syscall.UTF16PtrFromString("HelmBanner")
	text, _ := syscall.UTF16PtrFromString(bannerText)
	brush, _, _ := procCreateSolidBrush.Call(uintptr(0x2020B4)) // COLORREF 0x00BBGGRR -> red-ish
	cursor, _, _ := procLoadCursor.Call(0, uintptr(32649))      // IDC_HAND

	const (
		wmDestroy   = 0x0002
		wmPaint     = 0x000F
		wmLButtonUp = 0x0202
	)
	proc := syscall.NewCallback(func(hwnd, msg, wp, lp uintptr) uintptr {
		switch msg {
		case wmPaint:
			var ps paintStruct
			hdc, _, _ := procBeginPaint.Call(hwnd, uintptr(unsafe.Pointer(&ps)))
			var rc rect
			procGetClientRect.Call(hwnd, uintptr(unsafe.Pointer(&rc)))
			procSetBkMode.Call(hdc, 1) // TRANSPARENT
			procSetTextColor.Call(hdc, 0xFFFFFF)
			const dtCenterVCenterSingle = 0x1 | 0x4 | 0x20
			procDrawText.Call(hdc, uintptr(unsafe.Pointer(text)), ^uintptr(0), uintptr(unsafe.Pointer(&rc)), dtCenterVCenterSingle)
			procEndPaint.Call(hwnd, uintptr(unsafe.Pointer(&ps)))
			return 0
		case wmLButtonUp:
			procDestroyWindow.Call(hwnd)
			go onClick()
			return 0
		case wmDestroy:
			procPostQuitMessage.Call(0)
			return 0
		}
		r, _, _ := procDefWindowProc.Call(hwnd, uintptr(msg), wp, lp)
		return r
	})
	wc := wndClassEx{Size: uint32(unsafe.Sizeof(wndClassEx{})), WndProc: proc, Instance: hInst, Cursor: cursor,
		Background: brush, ClassName: className}
	if r, _, _ := procRegisterClassEx.Call(uintptr(unsafe.Pointer(&wc))); r == 0 {
		return
	}
	sw, _, _ := procGetSystemMetrics.Call(0)
	const w, h = 460, 30
	x := (int(sw) - w) / 2
	const (
		wsPopup      = 0x80000000
		wsVisible    = 0x10000000
		wsExTopmost  = 0x00000008
		wsExTool     = 0x00000080
		wsExNoActive = 0x08000000
	)
	hwnd, _, _ := procCreateWindowEx.Call(wsExTopmost|wsExTool|wsExNoActive, uintptr(unsafe.Pointer(className)), uintptr(unsafe.Pointer(text)),
		wsPopup|wsVisible, uintptr(x), 0, w, h, 0, 0, hInst, 0)
	if hwnd == 0 {
		return
	}
	var m winMsg
	for {
		r, _, _ := procGetMessage.Call(uintptr(unsafe.Pointer(&m)), 0, 0, 0)
		if int32(r) <= 0 {
			return
		}
		procTranslateMessage.Call(uintptr(unsafe.Pointer(&m)))
		procDispatchMessage.Call(uintptr(unsafe.Pointer(&m)))
	}
}

// ---- capture ----

type bitmapInfoHeader struct {
	Size          uint32
	Width         int32
	Height        int32
	Planes        uint16
	BitCount      uint16
	Compression   uint32
	SizeImage     uint32
	XPelsPerMeter int32
	YPelsPerMeter int32
	ClrUsed       uint32
	ClrImportant  uint32
	_             [4]byte // room for the single RGBQUAD of BITMAPINFO
}

type capturer struct {
	deskName string
	deskH    uintptr
	w, h     int // native screen size
	sw, sh   int // streamed size
	scale    int
	quality  int
	fps      int
	dib      []byte // persistent capture bitmap memory, overwritten by every grab
	dibDC    uintptr
	dibBmp   uintptr
	dibOld   uintptr
	dibW     int
	dibH     int
	scaled   []byte // half-size copy, only used when scale is 2
	cur      []byte // the frame to stream: dib itself, or scaled
	prev     []byte // what the viewer already has
	force    bool
	ad       Adaptive
	adMu     sync.Mutex // the sender goroutine records timings while the capture loop reads them
	send     func(v any)
	mons     []MonRect
	mon      int // index into mons; only used when there is more than one monitor
	vx, vy   int // virtual desktop origin and size, for mapping the pointer
	vw, vh   int
}

// attach makes the calling thread use the desktop that currently receives input.
func (cp *capturer) attach() bool {
	h, name := inputDesktop()
	if h == 0 {
		return cp.deskH != 0
	}
	if cp.deskH == 0 || name != cp.deskName {
		if r, _, _ := procSetThreadDesktop.Call(h); r == 0 {
			procCloseDesktop.Call(h)
			return cp.deskH != 0
		}
		if cp.deskH != 0 {
			procCloseDesktop.Call(cp.deskH)
		}
		cp.deskH, cp.deskName = h, name
		cp.force = true
		return true
	}
	procCloseDesktop.Call(h)
	return true
}

func (cp *capturer) grab() error {
	w0, _, _ := procGetSystemMetrics.Call(0) // SM_CXSCREEN
	h0, _, _ := procGetSystemMetrics.Call(1) // SM_CYSCREEN
	w, h := int(w0), int(h0)
	ox, oy := 0, 0
	if len(cp.mons) > 1 && cp.mon < len(cp.mons) { // several monitors: capture the one the viewer picked
		m := cp.mons[cp.mon]
		w, h, ox, oy = m.W, m.H, m.X, m.Y
	}
	if w <= 0 || h <= 0 {
		return fmt.Errorf("no screen")
	}
	hdc, _, _ := procGetDC.Call(0)
	if hdc == 0 {
		return fmt.Errorf("GetDC failed")
	}
	defer procReleaseDC.Call(0, hdc)
	if cp.dibDC == 0 || cp.dibW != w || cp.dibH != h {
		if err := cp.makeDIB(hdc, w, h); err != nil {
			return err
		}
	}
	// The bitmap is a DIB section, so BitBlt writes straight into cp.dib: no per-frame bitmap, no GetDIBits copy.
	const srccopy, captureblt = 0x00CC0020, 0x40000000
	if ok, _, _ := procBitBlt.Call(cp.dibDC, 0, 0, uintptr(w), uintptr(h), hdc, uintptr(ox), uintptr(oy), srccopy|captureblt); ok == 0 {
		return fmt.Errorf("BitBlt failed")
	}
	cp.w, cp.h = w, h
	return nil
}

func (cp *capturer) makeDIB(hdc uintptr, w, h int) error {
	cp.freeDIB()
	bi := bitmapInfoHeader{Size: 40, Width: int32(w), Height: -int32(h), Planes: 1, BitCount: 32}
	var bits uintptr
	bmp, _, _ := procCreateDIBSection.Call(hdc, uintptr(unsafe.Pointer(&bi)), 0, uintptr(unsafe.Pointer(&bits)), 0, 0)
	if bmp == 0 || bits == 0 {
		return fmt.Errorf("CreateDIBSection failed")
	}
	dc, _, _ := procCreateCompatibleDC.Call(hdc)
	if dc == 0 {
		procDeleteObject.Call(bmp)
		return fmt.Errorf("CreateCompatibleDC failed")
	}
	cp.dibOld, _, _ = procSelectObject.Call(dc, bmp)
	cp.dibDC, cp.dibBmp, cp.dibW, cp.dibH = dc, bmp, w, h
	cp.dib = unsafe.Slice((*byte)(ptrOf(bits)), w*h*4)
	cp.prev = nil
	return nil
}

func (cp *capturer) freeDIB() {
	if cp.dibDC != 0 {
		procSelectObject.Call(cp.dibDC, cp.dibOld)
		procDeleteDC.Call(cp.dibDC)
		procDeleteObject.Call(cp.dibBmp)
	}
	cp.dibDC, cp.dibBmp, cp.dib, cp.dibW, cp.dibH = 0, 0, nil, 0, 0
}

// scaleFrame points cp.cur at the frame to stream: the capture bitmap itself at full size, or a half-size copy.
func (cp *capturer) scaleFrame() {
	if cp.scale < 2 {
		cp.sw, cp.sh = cp.w, cp.h
		cp.cur = cp.dib
		return
	}
	sw, sh := cp.w/2, cp.h/2
	cp.sw, cp.sh = sw, sh
	if len(cp.scaled) != sw*sh*4 {
		cp.scaled = make([]byte, sw*sh*4)
	}
	for y := 0; y < sh; y++ {
		r0 := cp.dib[(2*y)*cp.w*4:]
		r1 := cp.dib[(2*y+1)*cp.w*4:]
		o := cp.scaled[y*sw*4:]
		for x := 0; x < sw; x++ {
			for c := 0; c < 3; c++ {
				o[x*4+c] = byte((int(r0[2*x*4+c]) + int(r0[(2*x+1)*4+c]) + int(r1[2*x*4+c]) + int(r1[(2*x+1)*4+c])) / 4)
			}
			o[x*4+3] = 255
		}
	}
	cp.cur = cp.scaled
}

// encJob is one frame's worth of changed regions, already converted to RGBA so the capture buffer can be reused.
type encJob struct {
	rects   []Rect
	pix     [][]byte
	quality int
}

// encodeAndSend turns a job into JPEG tiles and writes them. It runs in its own goroutine so the next frame can be
// captured while this one is still being compressed and sent.
func (cp *capturer) encodeAndSend(c *ws.Conn, job encJob) error {
	tiles := make([]Tile, len(job.rects))
	var wg sync.WaitGroup
	sem := make(chan struct{}, max(1, runtime.NumCPU()))
	for i := range job.rects {
		wg.Add(1)
		sem <- struct{}{}
		go func(i int) {
			defer wg.Done()
			defer func() { <-sem }()
			r := job.rects[i]
			img := &image.RGBA{Pix: job.pix[i], Stride: r.W * 4, Rect: image.Rect(0, 0, r.W, r.H)}
			var buf bytes.Buffer
			_ = jpeg.Encode(&buf, img, &jpeg.Options{Quality: job.quality})
			tiles[i] = Tile{X: r.X, Y: r.Y, W: r.W, H: r.H, JPEG: buf.Bytes()}
		}(i)
	}
	wg.Wait()
	sendStart := time.Now()
	for len(tiles) > 0 { // batches keep each WebSocket message modest
		n, size := 0, 0
		for n < len(tiles) && (n == 0 || size+len(tiles[n].JPEG) < 512<<10) && n < 200 {
			size += len(tiles[n].JPEG)
			n++
		}
		if err := c.WriteMessage(ws.OpBinary, EncodeTiles(tiles[:n])); err != nil {
			return err
		}
		tiles = tiles[n:]
	}
	cp.adMu.Lock()
	cp.ad.Observe(time.Since(sendStart)) // slow sends lower fps and quality; fast ones restore them
	cp.adMu.Unlock()
	return nil
}

func captureLoop(ctx context.Context, c *ws.Conn, in <-chan InputMsg, viewOnly bool) {
	cp := &capturer{scale: 1, force: true}
	cp.ad.SetCeiling(8, 55)
	defer cp.freeDIB()
	var sendMu sync.Mutex
	cp.send = func(v any) { sendMu.Lock(); defer sendMu.Unlock(); _ = sendJSON(c, v) }

	// Stage two: compress and send. The channel holds one job, so capture runs one frame ahead at most and slows down
	// by itself when the link cannot keep up.
	jobs := make(chan encJob, 1)
	failed := make(chan struct{})
	var done sync.WaitGroup
	done.Add(1)
	go func() {
		defer done.Done()
		for job := range jobs {
			if cp.encodeAndSend(c, job) != nil {
				close(failed)
				for range jobs { // drain so the producer never blocks
				}
				return
			}
		}
	}()
	defer func() { close(jobs); done.Wait() }()

	frames := 0
	lastW, lastH := 0, 0
	next := time.Now()
	for ctx.Err() == nil {
		select {
		case <-failed:
			return
		default:
		}
		// drain pending input first so controls feel responsive
		for drain := true; drain; {
			select {
			case m := <-in:
				cp.handle(m, viewOnly)
			default:
				drain = false
			}
		}
		if wait := time.Until(next); wait > 0 {
			select {
			case m := <-in:
				cp.handle(m, viewOnly)
				continue
			case <-ctx.Done():
				return
			case <-failed:
				return
			case <-time.After(wait):
			}
		}
		cp.adMu.Lock()
		cp.fps, cp.quality = cp.ad.FPS(), cp.ad.Quality()
		cp.adMu.Unlock()
		// pace from the previous deadline, not from now, so one slow frame does not permanently lower the rate
		next = next.Add(time.Second / time.Duration(max(1, cp.fps)))
		if now := time.Now(); next.Before(now) {
			next = now
		}
		if frames%(max(1, cp.fps)*2) == 0 {
			cp.refreshMonitors()
		}
		frames++
		if !cp.attach() {
			continue
		}
		if err := cp.grab(); err != nil {
			continue
		}
		cp.scaleFrame()
		if cp.sw != lastW || cp.sh != lastH {
			lastW, lastH = cp.sw, cp.sh
			cp.prev = nil
			if sendJSON(c, map[string]any{"t": "screen", "w": cp.sw, "h": cp.sh}) != nil {
				return
			}
		}
		if cp.force {
			cp.prev, cp.force = nil, false
		}
		if len(cp.prev) != len(cp.cur) {
			cp.prev = nil
		}
		rects := ChangedRects(cp.prev, cp.cur, cp.sw, cp.sh, TileSize)
		if len(rects) == 0 {
			continue
		}
		if cp.prev == nil {
			cp.prev = make([]byte, len(cp.cur))
		}
		total := ((cp.sw + TileSize - 1) / TileSize) * ((cp.sh + TileSize - 1) / TileSize)
		job := encJob{rects: rects, pix: make([][]byte, len(rects)), quality: MotionQuality(cp.quality, len(rects), total)}
		var cw sync.WaitGroup
		sem := make(chan struct{}, max(1, runtime.NumCPU()))
		for i, r := range rects {
			cw.Add(1)
			sem <- struct{}{}
			go func(i int, r Rect) {
				defer cw.Done()
				defer func() { <-sem }()
				job.pix[i] = RectRGBA(cp.cur, cp.sw, r)
			}(i, r)
		}
		cw.Wait()
		for _, r := range rects {
			CopyRect(cp.prev, cp.cur, cp.sw, r) // the viewer will have this region once the job is sent
		}
		select {
		case jobs <- job:
		case <-ctx.Done():
			return
		case <-failed:
			return
		}
	}
}

// ---- monitors ----

type winRect struct{ L, T, R, B int32 }

type monitorInfo struct {
	Size  uint32
	Mon   winRect
	Work  winRect
	Flags uint32
}

// monOut collects the result of the enumeration callback. The callback is created once (Go never frees them) and only
// the capture goroutine calls listMonitors, so a package variable is safe.
var monOut []MonRect
var monCB = syscall.NewCallback(func(hMon, hdc, lprc, lparam uintptr) uintptr {
	mi := monitorInfo{Size: uint32(unsafe.Sizeof(monitorInfo{}))}
	if r, _, _ := procGetMonitorInfo.Call(hMon, uintptr(unsafe.Pointer(&mi))); r != 0 {
		monOut = append(monOut, MonRect{X: int(mi.Mon.L), Y: int(mi.Mon.T), W: int(mi.Mon.R - mi.Mon.L), H: int(mi.Mon.B - mi.Mon.T), Primary: mi.Flags&1 != 0})
	}
	return 1
})

// listMonitors returns the monitors with the primary first, so index 0 is what the viewer saw before this feature.
func listMonitors() []MonRect {
	monOut = monOut[:0]
	procEnumDisplayMonitors.Call(0, 0, monCB, 0)
	out := append([]MonRect(nil), monOut...)
	for i, m := range out {
		if m.Primary && i != 0 {
			out[0], out[i] = out[i], out[0]
			break
		}
	}
	return out
}

func sameMonitors(a, b []MonRect) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// refreshMonitors re-reads the monitor layout and tells the viewer when it changed.
func (cp *capturer) refreshMonitors() {
	mons := listMonitors()
	if len(mons) == 0 || sameMonitors(mons, cp.mons) {
		return
	}
	cp.mons = mons
	if cp.mon >= len(mons) {
		cp.mon = 0
	}
	g := func(i uintptr) int { v, _, _ := procGetSystemMetrics.Call(i); return int(int32(v)) }
	cp.vx, cp.vy, cp.vw, cp.vh = g(76), g(77), g(78), g(79)
	cp.force = true
	cp.announceMonitors()
}

func (cp *capturer) announceMonitors() {
	if cp.send == nil {
		return
	}
	list := make([]map[string]any, 0, len(cp.mons))
	for _, m := range cp.mons {
		list = append(list, map[string]any{"w": m.W, "h": m.H, "primary": m.Primary})
	}
	cp.send(map[string]any{"t": "monitors", "list": list, "cur": cp.mon})
}

// ---- clipboard (text only) ----

const cfUnicodeText = 13
const clipMax = 256 << 10 // characters; keeps a message well inside the relay limit

func openClipboard() bool {
	for i := 0; i < 10; i++ {
		if r, _, _ := procOpenClipboard.Call(0); r != 0 {
			return true
		}
		time.Sleep(25 * time.Millisecond)
	}
	return false
}

func ptrOf(p uintptr) unsafe.Pointer { return *(*unsafe.Pointer)(unsafe.Pointer(&p)) }

func clipboardGet() (string, bool) {
	if !openClipboard() {
		return "", false
	}
	defer procCloseClipboard.Call()
	h, _, _ := procGetClipboardData.Call(cfUnicodeText)
	if h == 0 {
		return "", true // nothing textual on the clipboard
	}
	p, _, _ := procGlobalLock.Call(h)
	if p == 0 {
		return "", false
	}
	defer procGlobalUnlock.Call(h)
	n, _, _ := procGlobalSize.Call(h)
	u := unsafe.Slice((*uint16)(ptrOf(p)), int(n)/2)
	end := 0
	for end < len(u) && u[end] != 0 && end < clipMax {
		end++
	}
	return string(utf16.Decode(u[:end])), true
}

func clipboardSet(s string) bool {
	r := []rune(s)
	if len(r) > clipMax {
		r = r[:clipMax]
	}
	u := append(utf16.Encode(r), 0)
	if !openClipboard() {
		return false
	}
	defer procCloseClipboard.Call()
	mem, _, _ := procGlobalAlloc.Call(0x2, uintptr(len(u)*2)) // GMEM_MOVEABLE
	if mem == 0 {
		return false
	}
	p, _, _ := procGlobalLock.Call(mem)
	if p == 0 {
		return false
	}
	copy(unsafe.Slice((*uint16)(ptrOf(p)), len(u)), u)
	procGlobalUnlock.Call(mem)
	procEmptyClipboard.Call()
	ok, _, _ := procSetClipboardData.Call(cfUnicodeText, mem)
	return ok != 0
}

// ---- input ----

type mouseInput struct {
	Dx, Dy    int32
	MouseData uint32
	Flags     uint32
	Time      uint32
	Extra     uintptr
}

type kbdInput struct {
	Vk, Scan uint16
	Flags    uint32
	Time     uint32
	Extra    uintptr
}

type mouseInputRec struct {
	Type uint32
	Mi   mouseInput
}

type kbdInputRec struct {
	Type uint32
	Ki   kbdInput
	_    [8]byte // pad to the size of the INPUT union
}

func sendMouse(dx, dy int32, data, flags uint32) {
	in := mouseInputRec{Type: 0, Mi: mouseInput{Dx: dx, Dy: dy, MouseData: data, Flags: flags}}
	procSendInput.Call(1, uintptr(unsafe.Pointer(&in)), unsafe.Sizeof(in))
}

func sendKey(scan uint16, flags uint32) {
	in := kbdInputRec{Type: 1, Ki: kbdInput{Scan: scan, Flags: flags}}
	procSendInput.Call(1, uintptr(unsafe.Pointer(&in)), unsafe.Sizeof(in))
}

func typeRune(r rune) {
	const keyeventfUnicode, keyeventfKeyup = 0x4, 0x2
	for _, u := range utf16.Encode([]rune{r}) {
		sendKey(u, keyeventfUnicode)
		sendKey(u, keyeventfUnicode|keyeventfKeyup)
	}
}

func (cp *capturer) handle(m InputMsg, viewOnly bool) {
	switch m.T {
	case "q":
		cp.adMu.Lock()
		q, fps := cp.ad.MaxQ, cp.ad.MaxFPS
		if m.Q >= 20 && m.Q <= 90 {
			q = m.Q
		}
		if m.FPS >= 1 && m.FPS <= 60 {
			fps = m.FPS
		}
		cp.ad.SetCeiling(fps, q)
		cp.adMu.Unlock()
		if m.Scale == 1 || m.Scale == 2 {
			cp.scale = m.Scale
		}
		cp.force = true
		return
	case "mon":
		if m.B >= 0 && m.B < len(cp.mons) && m.B != cp.mon {
			cp.mon = m.B
			cp.prev = nil
			cp.force = true
			cp.announceMonitors()
		}
		return
	case "refresh":
		cp.force = true
		return
	}
	if viewOnly {
		return
	}
	if !cp.attach() { // input must go to the desktop that is receiving input now
		return
	}
	switch m.T {
	case "clipset":
		if !clipboardSet(m.Text) && cp.send != nil {
			cp.send(map[string]any{"t": "clip", "ok": false})
		}
		return
	case "clipget":
		if txt, ok := clipboardGet(); cp.send != nil {
			cp.send(map[string]any{"t": "clip", "ok": ok, "s": txt})
		}
		return
	}
	const (
		moveAbs  = 0x0001 | 0x8000
		leftDown = 0x0002
		leftUp   = 0x0004
		rightDn  = 0x0008
		rightUp  = 0x0010
		midDown  = 0x0020
		midUp    = 0x0040
		wheel    = 0x0800
		hwheel   = 0x1000
	)
	pos := func() {
		if len(cp.mons) > 1 && cp.mon < len(cp.mons) {
			x, y := AbsPoint(cp.mons[cp.mon], cp.vx, cp.vy, cp.vw, cp.vh, m.X, m.Y)
			sendMouse(x, y, 0, moveAbs|0x4000) // MOUSEEVENTF_VIRTUALDESK
			return
		}
		sendMouse(int32(clamp01(m.X)*65535), int32(clamp01(m.Y)*65535), 0, moveAbs)
	}
	switch m.T {
	case "mm":
		pos()
	case "md", "mu":
		pos()
		down := m.T == "md"
		var f uint32
		switch m.B {
		case 0:
			f = map[bool]uint32{true: leftDown, false: leftUp}[down]
		case 1:
			f = map[bool]uint32{true: midDown, false: midUp}[down]
		case 2:
			f = map[bool]uint32{true: rightDn, false: rightUp}[down]
		}
		if f != 0 {
			sendMouse(0, 0, 0, f)
		}
	case "wh":
		if m.DY != 0 {
			sendMouse(0, 0, uint32(int32(-m.DY*1.2)), wheel)
		}
		if m.DX != 0 {
			sendMouse(0, 0, uint32(int32(m.DX*1.2)), hwheel)
		}
	case "kd", "ku":
		ka := DecideKey(m, m.T == "ku")
		if !ka.OK {
			return
		}
		if ka.Unicode != 0 {
			typeRune(ka.Unicode)
			return
		}
		flags := uint32(0x8) // KEYEVENTF_SCANCODE
		if ka.Ext {
			flags |= 0x1
		}
		if ka.Up {
			flags |= 0x2
		}
		sendKey(ka.Scan, flags)
	case "txt":
		for _, r := range m.Text {
			typeRune(r)
		}
	}
}
