//go:build !windows

package agent

import (
	"bufio"
	"context"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"os/user"
	"strings"
	"sync"
	"time"

	"helm/internal/ws"
)

// The macOS remote screen. `helm-agent helper` runs as the signed-in user (the daemon starts it with launchctl asuser).
// It speaks the same protocol as the Windows helper (consent, screen size, changed tiles, input) and uses HelmIO, a
// small Swift program in the menu-bar app, to grab the screen and inject mouse and keyboard events.

const macIOPath = "/Library/Application Support/Helm/HelmMenu.app/Contents/MacOS/HelmIO"

// macKeys maps KeyboardEvent.code to macOS virtual key codes (ANSI layout).
var macKeys = map[string]int{
	"KeyA": 0, "KeyS": 1, "KeyD": 2, "KeyF": 3, "KeyH": 4, "KeyG": 5, "KeyZ": 6, "KeyX": 7, "KeyC": 8, "KeyV": 9,
	"IntlBackslash": 10, "KeyB": 11, "KeyQ": 12, "KeyW": 13, "KeyE": 14, "KeyR": 15, "KeyY": 16, "KeyT": 17,
	"Digit1": 18, "Digit2": 19, "Digit3": 20, "Digit4": 21, "Digit6": 22, "Digit5": 23, "Equal": 24, "Digit9": 25,
	"Digit7": 26, "Minus": 27, "Digit8": 28, "Digit0": 29, "BracketRight": 30, "KeyO": 31, "KeyU": 32, "BracketLeft": 33,
	"KeyI": 34, "KeyP": 35, "Enter": 36, "KeyL": 37, "KeyJ": 38, "Quote": 39, "KeyK": 40, "Semicolon": 41,
	"Backslash": 42, "Comma": 43, "Slash": 44, "KeyN": 45, "KeyM": 46, "Period": 47, "Tab": 48, "Space": 49,
	"Backquote": 50, "Backspace": 51, "Escape": 53, "MetaRight": 54, "MetaLeft": 55, "ShiftLeft": 56, "CapsLock": 57,
	"AltLeft": 58, "ControlLeft": 59, "ShiftRight": 60, "AltRight": 61, "ControlRight": 62,
	"F5": 96, "F6": 97, "F7": 98, "F3": 99, "F8": 100, "F9": 101, "F11": 103, "F10": 109, "F12": 111, "F4": 118,
	"F2": 120, "F1": 122, "Home": 115, "PageUp": 116, "Delete": 117, "End": 119, "PageDown": 121,
	"ArrowLeft": 123, "ArrowRight": 124, "ArrowDown": 125, "ArrowUp": 126, "NumpadEnter": 76,
	"NumpadDecimal": 65, "NumpadMultiply": 67, "NumpadAdd": 69, "NumpadDivide": 75, "NumpadSubtract": 78,
	"Numpad0": 82, "Numpad1": 83, "Numpad2": 84, "Numpad3": 85, "Numpad4": 86, "Numpad5": 87, "Numpad6": 88,
	"Numpad7": 89, "Numpad8": 91, "Numpad9": 92,
}

// macFlags turns the browser's modifier state into CGEventFlags. Windows-style shortcuts map Ctrl to Control,
// Alt to Option and the Windows key to Command.
func macFlags(m InputMsg, shift bool) uint64 {
	var f uint64
	if shift {
		f |= 0x20000
	}
	if m.Ctrl {
		f |= 0x40000
	}
	if m.Alt {
		f |= 0x80000
	}
	if m.Meta {
		f |= 0x100000
	}
	return f
}

// macFrame is one captured picture, BGRA.
type macFrame struct {
	w, h int
	pix  []byte
}

type macIO struct {
	cmd   *exec.Cmd
	in    io.WriteCloser
	out   *bufio.Reader
	mu    sync.Mutex // one command at a time
	frame chan macFrame
	check chan [2]bool
	errs  chan string
}

func startMacIO(ctx context.Context) (*macIO, error) {
	if _, err := os.Stat(macIOPath); err != nil {
		return nil, fmt.Errorf("the Helm menu-bar app is not installed on this Mac (install the .pkg again)")
	}
	cmd := exec.CommandContext(ctx, macIOPath)
	in, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	out, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	m := &macIO{cmd: cmd, in: in, out: bufio.NewReaderSize(out, 1<<20), frame: make(chan macFrame, 1), check: make(chan [2]bool, 1), errs: make(chan string, 4)}
	go m.read()
	return m, nil
}

func (m *macIO) read() {
	defer close(m.errs)
	for {
		t, err := m.out.ReadByte()
		if err != nil {
			return
		}
		switch t {
		case 'F':
			var h [8]byte
			if _, err := io.ReadFull(m.out, h[:]); err != nil {
				return
			}
			w, hh := int(binary.BigEndian.Uint32(h[:4])), int(binary.BigEndian.Uint32(h[4:]))
			if w <= 0 || hh <= 0 || w*hh > 64<<20 {
				return
			}
			pix := make([]byte, w*hh*4)
			if _, err := io.ReadFull(m.out, pix); err != nil {
				return
			}
			select {
			case m.frame <- macFrame{w, hh, pix}:
			default:
			}
		case 'C':
			var b [2]byte
			if _, err := io.ReadFull(m.out, b[:]); err != nil {
				return
			}
			m.check <- [2]bool{b[0] == 1, b[1] == 1}
		case 'E':
			var h [4]byte
			if _, err := io.ReadFull(m.out, h[:]); err != nil {
				return
			}
			n := int(binary.BigEndian.Uint32(h[:]))
			if n < 0 || n > 4096 {
				return
			}
			b := make([]byte, n)
			if _, err := io.ReadFull(m.out, b); err != nil {
				return
			}
			select {
			case m.errs <- string(b):
			default:
			}
		default:
			return
		}
	}
}

func (m *macIO) send(format string, a ...any) {
	m.mu.Lock()
	defer m.mu.Unlock()
	_, _ = fmt.Fprintf(m.in, format+"\n", a...)
}

func (m *macIO) stop() {
	_ = m.in.Close()
	if m.cmd.Process != nil {
		_ = m.cmd.Process.Kill()
	}
	_ = m.cmd.Wait()
}

// macConsent asks the person at the Mac. It reports false when they decline or do not answer within a minute.
func macConsent(org string) bool {
	who := "Your administrator"
	if org != "" {
		who = org
	}
	script := fmt.Sprintf(`display dialog %q buttons {"Don't allow","Allow"} default button "Don't allow" cancel button "Don't allow" with title "Helm" with icon caution giving up after 60`,
		who+" wants to see and control this screen. Allow it?")
	out, err := exec.Command("osascript", "-e", script).Output()
	return err == nil && strings.Contains(string(out), "button returned:Allow") && !strings.Contains(string(out), "gave up:true")
}

func runMacHelper(args []string) int {
	fs := flag.NewFlagSet("helper", flag.ContinueOnError)
	addr := fs.String("addr", "", "service rendezvous address")
	token := fs.String("token", "", "rendezvous token")
	consent := fs.String("consent", ConsentPromptIfPresent, "consent mode")
	viewOnly := fs.Bool("viewonly", false, "view-only session")
	if err := fs.Parse(args); err != nil || *addr == "" || *token == "" {
		return 2
	}
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

	if *consent != ConsentUnattended && !macConsent("") {
		_ = sendJSON(c, map[string]any{"t": "consent", "ok": false, "msg": "the person at the Mac declined or did not answer the request"})
		time.Sleep(300 * time.Millisecond)
		return 0
	}
	io0, err := startMacIO(ctx)
	if err != nil {
		_ = sendJSON(c, map[string]any{"t": "error", "msg": err.Error()})
		time.Sleep(300 * time.Millisecond)
		return 0
	}
	defer io0.stop()
	io0.send("chk")
	select {
	case st := <-io0.check:
		if !st[0] {
			_ = sendJSON(c, map[string]any{"t": "error", "msg": "Screen Recording is not allowed for Helm on this Mac. Open System Settings, Privacy & Security, Screen Recording, turn on Helm, then try again."})
			time.Sleep(300 * time.Millisecond)
			return 0
		}
		if !st[1] && !*viewOnly {
			_ = sendJSON(c, map[string]any{"t": "error", "msg": "Accessibility is not allowed for Helm on this Mac, so mouse and keyboard cannot be controlled. Open System Settings, Privacy & Security, Accessibility, turn on Helm, then try again. (View only works without it.)"})
			time.Sleep(300 * time.Millisecond)
			return 0
		}
	case <-time.After(10 * time.Second):
		_ = sendJSON(c, map[string]any{"t": "error", "msg": "The Helm screen tool on this Mac did not answer."})
		return 0
	}
	_ = sendJSON(c, map[string]any{"t": "consent", "ok": true})

	// wait for the start signal
	for {
		op, msg, err := c.ReadMessage()
		if err != nil {
			return 0
		}
		if op == ws.OpText && strings.Contains(string(msg), `"start"`) {
			break
		}
	}

	s := &macSession{c: c, io: io0, viewOnly: *viewOnly, flow: NewFlowControl(), force: true}
	s.ad.SetCeiling(30, 60)
	in := make(chan InputMsg, 256)
	go func() {
		defer cancel()
		for {
			op, d, err := c.ReadMessage()
			if err != nil {
				return
			}
			if op != ws.OpText {
				continue
			}
			var m InputMsg
			if json.Unmarshal(d, &m) == nil {
				select {
				case in <- m:
				default:
				}
			}
		}
	}()
	s.loop(ctx, in)
	return 0
}

type macSession struct {
	c        *ws.Conn
	io       *macIO
	viewOnly bool
	flow     *FlowControl
	ad       Adaptive
	mu       sync.Mutex // guards ad, scale and force
	scale    int
	force    bool
	prev     []byte
	soft     SoftRegions
	changed  time.Time
}

func (s *macSession) handle(m InputMsg) {
	switch m.T {
	case "ack":
		if rtt, ok := s.flow.Ack(m.N); ok {
			s.mu.Lock()
			s.ad.ObserveRTT(rtt)
			s.mu.Unlock()
		}
		return
	case "q":
		s.mu.Lock()
		q, fps := s.ad.MaxQ, s.ad.MaxFPS
		if m.Q >= 20 && m.Q <= 90 {
			q = m.Q
		}
		if m.FPS >= 1 && m.FPS <= 60 {
			fps = m.FPS
		}
		s.ad.SetCeiling(fps, q)
		if m.Scale == 1 || m.Scale == 2 {
			s.scale = m.Scale
		}
		s.force = true
		s.mu.Unlock()
		return
	case "refresh":
		s.mu.Lock()
		s.force = true
		s.mu.Unlock()
		return
	case "mon":
		return // one display for now
	}
	if s.viewOnly {
		return
	}
	switch m.T {
	case "mm":
		s.io.send("mm %.5f %.5f", m.X, m.Y)
	case "md", "mu":
		s.io.send("%s %.5f %.5f %d", m.T, m.X, m.Y, m.B)
	case "wh":
		s.io.send("wh %.1f %.1f", m.DX, m.DY)
	case "kd", "ku":
		if r := []rune(m.Key); len(r) == 1 && r[0] >= 0x20 && r[0] != 0x7f && !m.Ctrl && !m.Meta {
			if m.T == "kd" {
				s.io.send("txt %s", hex.EncodeToString([]byte(string(r))))
			}
			return
		}
		code, ok := macKeys[m.Code]
		if !ok {
			return
		}
		s.io.send("%s %d %d", m.T, code, macFlags(m, false))
	case "txt":
		if m.Text != "" {
			s.io.send("txt %s", hex.EncodeToString([]byte(m.Text)))
		}
	case "clipset":
		cmd := exec.Command("pbcopy")
		cmd.Stdin = strings.NewReader(m.Text)
		if cmd.Run() != nil {
			_ = sendJSON(s.c, map[string]any{"t": "clip", "ok": false})
		}
	case "clipget":
		out, err := exec.Command("pbpaste").Output()
		_ = sendJSON(s.c, map[string]any{"t": "clip", "ok": err == nil, "s": string(out)})
	}
}

func (s *macSession) loop(ctx context.Context, in <-chan InputMsg) {
	lastW, lastH := 0, 0
	next := time.Now()
	for {
		// drain input first so clicks are never stuck behind a frame
	drain:
		for {
			select {
			case m := <-in:
				s.handle(m)
			default:
				break drain
			}
		}
		if ctx.Err() != nil {
			return
		}
		s.mu.Lock()
		fps, q, scale := s.ad.FPS(), s.ad.Quality(), s.scale
		s.mu.Unlock()
		if scale == 0 {
			scale = 1
		}
		if wait := time.Until(next); wait > 0 {
			select {
			case m := <-in:
				s.handle(m)
			case <-ctx.Done():
				return
			case <-time.After(wait):
			}
			continue
		}
		next = next.Add(time.Second / time.Duration(max(1, fps)))
		if n := time.Now(); next.Before(n) {
			next = n
		}
		s.mu.Lock()
		s.flow.SetMax(s.ad.Window())
		s.mu.Unlock()
		if !s.flow.CanSend() {
			continue
		}
		s.io.send("cap %d", 1920/scale)
		var f macFrame
		select {
		case f = <-s.io.frame:
		case msg, ok := <-s.io.errs:
			if ok {
				_ = sendJSON(s.c, map[string]any{"t": "error", "msg": msg})
			}
			return
		case <-time.After(5 * time.Second):
			_ = sendJSON(s.c, map[string]any{"t": "error", "msg": "The screen could not be captured."})
			return
		case <-ctx.Done():
			return
		}
		if f.w != lastW || f.h != lastH {
			lastW, lastH = f.w, f.h
			s.prev = nil
			if sendJSON(s.c, map[string]any{"t": "screen", "w": f.w, "h": f.h}) != nil {
				return
			}
		}
		s.mu.Lock()
		force := s.force
		s.force = false
		s.mu.Unlock()
		if force {
			s.prev = nil
			s.soft.Take()
		}
		if len(s.prev) != len(f.pix) {
			s.prev = nil
		}
		rects := ChangedRects(s.prev, f.pix, f.w, f.h, TileSize)
		if len(rects) == 0 {
			if s.soft.Len() > 0 && time.Since(s.changed) > 250*time.Millisecond {
				if s.sendRects(f, s.soft.Take(), nil, 90) != nil {
					return
				}
			}
			continue
		}
		s.changed = time.Now()
		if s.prev == nil {
			s.prev = make([]byte, len(f.pix))
		}
		s.soft.Invalidate(rects)
		total := ((f.w + TileSize - 1) / TileSize) * ((f.h + TileSize - 1) / TileSize)
		flat := make([]bool, len(rects))
		for i, r := range rects {
			flat[i] = FlatBGRA(f.pix, f.w, r)
		}
		merged, mflat := MergeRuns(rects, flat)
		if s.sendRects(f, merged, mflat, MotionQuality(q, len(rects), total)) != nil {
			return
		}
		for _, r := range rects {
			CopyRect(s.prev, f.pix, f.w, r)
		}
	}
}

func (s *macSession) sendRects(f macFrame, rects []Rect, flat []bool, q int) error {
	if len(rects) == 0 {
		return nil
	}
	if flat == nil {
		flat = make([]bool, len(rects))
	}
	tiles := make([]Tile, len(rects))
	for i, r := range rects {
		tiles[i] = Tile{X: r.X, Y: r.Y, W: r.W, H: r.H, JPEG: EncodeRegion(RectRGBA(f.pix, f.w, r), r.W, r.H, flat[i], q)}
		if q < 88 && !flat[i] {
			s.soft.Add(r)
		}
	}
	seq := s.flow.Sent()
	for len(tiles) > 0 {
		n, size := 0, 0
		for n < len(tiles) && (n == 0 || size+len(tiles[n].JPEG) < 512<<10) && n < 200 {
			size += len(tiles[n].JPEG)
			n++
		}
		if err := s.c.WriteMessage(ws.OpBinary, EncodeTiles(tiles[:n])); err != nil {
			return err
		}
		tiles = tiles[n:]
	}
	return s.c.WriteMessage(ws.OpText, []byte(fmt.Sprintf(`{"t":"fr","n":%d}`, seq)))
}

// consoleUID is the user id of whoever is signed in at the Mac, for launchctl asuser.
func consoleUID() (string, error) {
	name := cmdOut("stat", "-f", "%Su", "/dev/console")
	if name == "" || name == "root" {
		return "", fmt.Errorf("nobody is signed in at this Mac, so there is no screen to show")
	}
	u, err := user.Lookup(name)
	if err != nil {
		return "", err
	}
	return u.Uid, nil
}

// launchMacHelper starts the helper inside the signed-in user's session.
func launchMacHelper(ctx context.Context, hl helperLaunch) (func(), error) {
	uid, err := consoleUID()
	if err != nil {
		return nil, err
	}
	exe, err := os.Executable()
	if err != nil {
		return nil, err
	}
	args := []string{"asuser", uid, exe, "helper", "--addr", hl.Addr, "--token", hl.Token, "--consent", hl.Consent}
	if hl.ViewOnly {
		args = append(args, "--viewonly")
	}
	cmd := exec.CommandContext(ctx, "launchctl", args...)
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	return func() {
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
		_ = cmd.Wait()
	}, nil
}
