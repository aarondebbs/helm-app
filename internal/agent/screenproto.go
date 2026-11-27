package agent

import (
	"encoding/binary"
	"errors"
	"time"
	"unicode/utf8"
)

// Screen streaming protocol between helper -> server -> browser.
//
// Text frames (JSON): {"t":"screen","w":W,"h":H} announces the frame size;
// {"t":"error","msg":...}. Binary frames carry changed tiles:
//
//	u16 count, then for each tile: u16 x, u16 y, u16 w, u16 h, u32 len, JPEG bytes
//
// All integers are big endian. Coordinates are in the announced frame size.

// TileSize is the edge length of the change-detection grid.
const TileSize = 128

// Tile is one changed rectangle encoded as JPEG.
type Tile struct {
	X, Y, W, H int
	JPEG       []byte
}

// EncodeTiles serialises tiles into one binary frame.
func EncodeTiles(tiles []Tile) []byte {
	size := 2
	for _, t := range tiles {
		size += 12 + len(t.JPEG)
	}
	out := make([]byte, 0, size)
	out = binary.BigEndian.AppendUint16(out, uint16(len(tiles)))
	for _, t := range tiles {
		out = binary.BigEndian.AppendUint16(out, uint16(t.X))
		out = binary.BigEndian.AppendUint16(out, uint16(t.Y))
		out = binary.BigEndian.AppendUint16(out, uint16(t.W))
		out = binary.BigEndian.AppendUint16(out, uint16(t.H))
		out = binary.BigEndian.AppendUint32(out, uint32(len(t.JPEG)))
		out = append(out, t.JPEG...)
	}
	return out
}

// DecodeTiles parses a binary frame produced by EncodeTiles.
func DecodeTiles(b []byte) ([]Tile, error) {
	if len(b) < 2 {
		return nil, errors.New("short frame")
	}
	n := int(binary.BigEndian.Uint16(b))
	b = b[2:]
	tiles := make([]Tile, 0, n)
	for i := 0; i < n; i++ {
		if len(b) < 12 {
			return nil, errors.New("truncated tile header")
		}
		t := Tile{X: int(binary.BigEndian.Uint16(b)), Y: int(binary.BigEndian.Uint16(b[2:])),
			W: int(binary.BigEndian.Uint16(b[4:])), H: int(binary.BigEndian.Uint16(b[6:]))}
		l := int(binary.BigEndian.Uint32(b[8:]))
		b = b[12:]
		if l < 0 || l > len(b) {
			return nil, errors.New("truncated tile data")
		}
		t.JPEG = b[:l]
		b = b[l:]
		tiles = append(tiles, t)
	}
	return tiles, nil
}

// InputMsg is a message from the browser to the helper.
type InputMsg struct {
	T     string  `json:"t"`           // mm, md, mu, wh, kd, ku, txt, cad, q, refresh, mon, clipset, clipget
	X     float64 `json:"x,omitempty"` // 0..1 fraction of the frame
	Y     float64 `json:"y,omitempty"`
	B     int     `json:"b,omitempty"`  // mouse button 0 left, 1 middle, 2 right
	DY    float64 `json:"dy,omitempty"` // wheel delta (browser units, positive = down)
	DX    float64 `json:"dx,omitempty"`
	Code  string  `json:"code,omitempty"` // KeyboardEvent.code
	Key   string  `json:"key,omitempty"`  // KeyboardEvent.key
	Ctrl  bool    `json:"c,omitempty"`
	Alt   bool    `json:"a,omitempty"`
	Meta  bool    `json:"m,omitempty"`
	Text  string  `json:"s,omitempty"`
	Q     int     `json:"q,omitempty"`     // JPEG quality 20..90
	FPS   int     `json:"fps,omitempty"`   // 1..15
	Scale int     `json:"scale,omitempty"` // 1 or 2 (downscale divisor)
	N     int     `json:"n,omitempty"`     // "ack": the frame number the viewer has finished drawing
	// "mon" selects monitor number B; "clipset" puts Text on the PC's clipboard; "clipget" asks for the PC's clipboard text.
}

type scanKey struct {
	Scan uint16
	Ext  bool
}

var jsScan = map[string]scanKey{
	"Escape": {0x01, false}, "Digit1": {0x02, false}, "Digit2": {0x03, false}, "Digit3": {0x04, false},
	"Digit4": {0x05, false}, "Digit5": {0x06, false}, "Digit6": {0x07, false}, "Digit7": {0x08, false},
	"Digit8": {0x09, false}, "Digit9": {0x0A, false}, "Digit0": {0x0B, false}, "Minus": {0x0C, false},
	"Equal": {0x0D, false}, "Backspace": {0x0E, false}, "Tab": {0x0F, false},
	"KeyQ": {0x10, false}, "KeyW": {0x11, false}, "KeyE": {0x12, false}, "KeyR": {0x13, false},
	"KeyT": {0x14, false}, "KeyY": {0x15, false}, "KeyU": {0x16, false}, "KeyI": {0x17, false},
	"KeyO": {0x18, false}, "KeyP": {0x19, false}, "BracketLeft": {0x1A, false}, "BracketRight": {0x1B, false},
	"Enter": {0x1C, false}, "ControlLeft": {0x1D, false},
	"KeyA": {0x1E, false}, "KeyS": {0x1F, false}, "KeyD": {0x20, false}, "KeyF": {0x21, false},
	"KeyG": {0x22, false}, "KeyH": {0x23, false}, "KeyJ": {0x24, false}, "KeyK": {0x25, false},
	"KeyL": {0x26, false}, "Semicolon": {0x27, false}, "Quote": {0x28, false}, "Backquote": {0x29, false},
	"ShiftLeft": {0x2A, false}, "Backslash": {0x2B, false},
	"KeyZ": {0x2C, false}, "KeyX": {0x2D, false}, "KeyC": {0x2E, false}, "KeyV": {0x2F, false},
	"KeyB": {0x30, false}, "KeyN": {0x31, false}, "KeyM": {0x32, false}, "Comma": {0x33, false},
	"Period": {0x34, false}, "Slash": {0x35, false}, "ShiftRight": {0x36, false},
	"NumpadMultiply": {0x37, false}, "AltLeft": {0x38, false}, "Space": {0x39, false}, "CapsLock": {0x3A, false},
	"F1": {0x3B, false}, "F2": {0x3C, false}, "F3": {0x3D, false}, "F4": {0x3E, false}, "F5": {0x3F, false},
	"F6": {0x40, false}, "F7": {0x41, false}, "F8": {0x42, false}, "F9": {0x43, false}, "F10": {0x44, false},
	"NumLock": {0x45, false}, "ScrollLock": {0x46, false},
	"Numpad7": {0x47, false}, "Numpad8": {0x48, false}, "Numpad9": {0x49, false}, "NumpadSubtract": {0x4A, false},
	"Numpad4": {0x4B, false}, "Numpad5": {0x4C, false}, "Numpad6": {0x4D, false}, "NumpadAdd": {0x4E, false},
	"Numpad1": {0x4F, false}, "Numpad2": {0x50, false}, "Numpad3": {0x51, false}, "Numpad0": {0x52, false},
	"NumpadDecimal": {0x53, false}, "IntlBackslash": {0x56, false}, "F11": {0x57, false}, "F12": {0x58, false},
	// extended keys (E0 prefix)
	"NumpadEnter": {0x1C, true}, "ControlRight": {0x1D, true}, "NumpadDivide": {0x35, true},
	"AltRight": {0x38, true}, "PrintScreen": {0x37, true}, "Home": {0x47, true}, "ArrowUp": {0x48, true},
	"PageUp": {0x49, true}, "ArrowLeft": {0x4B, true}, "ArrowRight": {0x4D, true}, "End": {0x4F, true},
	"ArrowDown": {0x50, true}, "PageDown": {0x51, true}, "Insert": {0x52, true}, "Delete": {0x53, true},
	"MetaLeft": {0x5B, true}, "MetaRight": {0x5C, true}, "ContextMenu": {0x5D, true},
}

// KeyAction is what the helper should inject for a keyboard event.
type KeyAction struct {
	Unicode rune // when non-zero: type this character (key-down only)
	Scan    uint16
	Ext     bool
	Up      bool
	OK      bool
}

// DecideKey maps a browser keyboard event to an injection. Printable characters
// are typed as Unicode so they come out right even when the remote keyboard
// layout differs from the local one; everything else (and any shortcut with
// Ctrl/Alt/Win held) is sent as a hardware scan code.
func DecideKey(m InputMsg, up bool) KeyAction {
	if utf8.RuneCountInString(m.Key) == 1 {
		r, _ := utf8.DecodeRuneInString(m.Key)
		printable := r >= 0x20 && r != 0x7f
		altGr := m.Ctrl && m.Alt
		if printable && !m.Meta && (altGr || (!m.Ctrl && !m.Alt)) {
			if up {
				return KeyAction{OK: false} // character already typed on key-down
			}
			return KeyAction{Unicode: r, OK: true}
		}
	}
	sk, ok := jsScan[m.Code]
	if !ok {
		return KeyAction{}
	}
	return KeyAction{Scan: sk.Scan, Ext: sk.Ext, Up: up, OK: true}
}

// Adaptive keeps a remote session usable on a slow link. The viewer chooses a ceiling (frame rate and JPEG quality);
// this lowers both while sends to the server are slow and raises them again, up to the ceiling, when the link recovers.
type Adaptive struct {
	MaxFPS, MaxQ int
	fps, q       int
	ewma         float64 // smoothed duration of one frame send, in milliseconds
	rtt          float64 // smoothed frame round-trip time, in milliseconds
	floor        float64 // lowest recent round-trip time: the link's own delay
}

// SetCeiling applies the viewer's choice and clamps the current values to it.
func (a *Adaptive) SetCeiling(fps, q int) {
	a.MaxFPS, a.MaxQ = fps, q
	if a.fps == 0 || a.fps > fps {
		a.fps = fps
	}
	if a.q == 0 || a.q > q {
		a.q = q
	}
}

// Observe records how long the last frame took to send.
func (a *Adaptive) Observe(d time.Duration) {
	ms := float64(d) / float64(time.Millisecond)
	if a.ewma == 0 {
		a.ewma = ms
	} else {
		a.ewma = 0.7*a.ewma + 0.3*ms
	}
	switch {
	case a.ewma > 150:
		a.fps = max(2, a.fps*3/4)
		a.q = max(30, a.q-5)
	case a.ewma < 40:
		if a.fps < a.MaxFPS {
			a.fps++
		}
		if a.q < a.MaxQ {
			a.q = min(a.MaxQ, a.q+2)
		}
	}
}

// ObserveRTT records the round-trip time of a frame (sent until the viewer finished drawing it). The lowest value seen
// recently is the link's own delay; anything above it is a queue building up. The picture stays smooth while the queue
// is short, so the rate and quality rise while it is under about 60 ms and fall when it passes about 160 ms. A long
// link on its own (a high floor) is not a reason to slow down: see Window, which keeps more frames in flight instead.
func (a *Adaptive) ObserveRTT(d time.Duration) {
	ms := float64(d) / float64(time.Millisecond)
	if a.rtt == 0 {
		a.rtt = ms
	} else {
		a.rtt = 0.6*a.rtt + 0.4*ms
	}
	if a.floor == 0 || ms < a.floor {
		a.floor = ms
	} else {
		a.floor += (ms - a.floor) * 0.01 // let the floor follow a link that has become slower
	}
	queue := a.rtt - a.floor
	switch {
	case queue > 160:
		a.fps = max(3, a.fps*3/4)
		a.q = max(30, a.q-6)
	case queue < 60:
		if a.fps < a.MaxFPS {
			a.fps = min(a.MaxFPS, a.fps+3)
		}
		if a.q < a.MaxQ {
			a.q = min(a.MaxQ, a.q+3)
		}
	}
}

// Floor is the link's own round-trip delay in milliseconds (0 until measured).
func (a *Adaptive) Floor() float64 { return a.floor }

// Window is how many frames may be in flight: enough to keep the link busy for a whole round trip at the current rate.
// With two frames and a 200 ms link the stream could never exceed 10 frames per second, however fast everything else is.
func (a *Adaptive) Window() int {
	rtt := a.floor
	if a.rtt > 0 && rtt == 0 {
		rtt = a.rtt
	}
	n := int(float64(max(1, a.fps))*rtt/1000*1.3) + 2
	return min(12, max(2, n))
}

// RTT returns the smoothed round-trip time in milliseconds (0 when unknown).
func (a *Adaptive) RTT() float64 { return a.rtt }

func (a *Adaptive) FPS() int     { return max(1, a.fps) }
func (a *Adaptive) Quality() int { return max(20, a.q) }

// MonRect is one monitor in virtual-desktop pixels.
type MonRect struct {
	X, Y, W, H int
	Primary    bool
}

// AbsPoint converts a position given as fractions of one monitor into the 0..65535 range that SendInput expects
// for the whole virtual desktop (vx, vy, vw, vh).
func AbsPoint(m MonRect, vx, vy, vw, vh int, fx, fy float64) (int32, int32) {
	px := float64(m.X) + clamp01(fx)*float64(m.W-1)
	py := float64(m.Y) + clamp01(fy)*float64(m.H-1)
	nx := (px - float64(vx)) * 65535 / float64(max(1, vw-1))
	ny := (py - float64(vy)) * 65535 / float64(max(1, vh-1))
	return int32(nx + 0.5), int32(ny + 0.5)
}

func clamp01(v float64) float64 {
	if v < 0 {
		return 0
	}
	if v > 1 {
		return 1
	}
	return v
}

// Rect is a changed region of a frame, in pixels.
type Rect struct{ X, Y, W, H int }

// ChangedRects compares two BGRA frames of the same size tile by tile and returns the tiles that differ.
// A nil or differently sized prev means everything changed.
func ChangedRects(prev, cur []byte, w, h, tile int) []Rect {
	var out []Rect
	for ty := 0; ty < h; ty += tile {
		th := min(tile, h-ty)
		for tx := 0; tx < w; tx += tile {
			tw := min(tile, w-tx)
			diff := len(prev) != len(cur)
			for r := 0; !diff && r < th; r++ {
				off := ((ty+r)*w + tx) * 4
				if string(prev[off:off+tw*4]) != string(cur[off:off+tw*4]) { // the compiler turns this into a memequal without copying
					diff = true
				}
			}
			if diff {
				out = append(out, Rect{tx, ty, tw, th})
			}
		}
	}
	return out
}

// CopyRect copies one region of a w-pixel-wide BGRA frame from src to dst.
func CopyRect(dst, src []byte, w int, r Rect) {
	for y := r.Y; y < r.Y+r.H; y++ {
		off := (y*w + r.X) * 4
		copy(dst[off:off+r.W*4], src[off:off+r.W*4])
	}
}

// RectRGBA converts one region of a BGRA frame into tightly packed RGBA bytes, ready for the JPEG encoder.
func RectRGBA(src []byte, w int, r Rect) []byte {
	out := make([]byte, r.W*r.H*4)
	for y := 0; y < r.H; y++ {
		s := src[((r.Y+y)*w+r.X)*4:]
		d := out[y*r.W*4:]
		for x := 0; x < r.W; x++ {
			d[x*4], d[x*4+1], d[x*4+2], d[x*4+3] = s[x*4+2], s[x*4+1], s[x*4], 255
		}
	}
	return out
}

// MotionQuality lowers the JPEG quality when most of the screen changed (video, dragging a window), because there the
// frame rate matters more than crispness, and a still picture is re-sent sharply a moment later by the next change.
func MotionQuality(q, changed, total int) int {
	if total > 0 && changed*100/total >= 40 {
		return max(30, q-15)
	}
	return q
}
