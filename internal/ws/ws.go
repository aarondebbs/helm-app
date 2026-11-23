// Package ws is a small RFC 6455 WebSocket implementation (client and server)
// using only the Go standard library.
package ws

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/sha1"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Message opcodes.
const (
	OpText   = 1
	OpBinary = 2
	opClose  = 8
	opPing   = 9
	opPong   = 10
)

// Close codes.
const (
	CloseNormal    = 1000
	CloseGoingAway = 1001
	CloseProtocol  = 1002
	CloseTooBig    = 1009
	ClosePolicy    = 1008
	CloseInternal  = 1011
)

const guid = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

var (
	ErrTooBig = errors.New("ws: message too large")
	ErrClosed = errors.New("ws: connection closed")
)

// CloseError is returned from ReadMessage when the peer sends a close frame.
type CloseError struct {
	Code   int
	Reason string
}

func (e *CloseError) Error() string { return fmt.Sprintf("ws: closed (%d %s)", e.Code, e.Reason) }

// Conn is a WebSocket connection. WriteMessage is safe for concurrent use;
// ReadMessage must be called from a single goroutine.
type Conn struct {
	c         net.Conn
	br        *bufio.Reader
	isClient  bool
	wmu       sync.Mutex
	readLimit int64
	idle      time.Duration
	writeTO   time.Duration
	closed    atomic.Bool
	done      chan struct{}
	doneOnce  sync.Once
	// RemoteAddr of the underlying connection.
	Remote string
}

func newConn(c net.Conn, br *bufio.Reader, client bool) *Conn {
	return &Conn{c: c, br: br, isClient: client, readLimit: 1 << 20,
		writeTO: 30 * time.Second, done: make(chan struct{}), Remote: c.RemoteAddr().String()}
}

// SetReadLimit sets the maximum size of an incoming message in bytes.
func (c *Conn) SetReadLimit(n int64) { c.readLimit = n }

// SetIdleTimeout makes ReadMessage fail if no frame (including pings and
// pongs) arrives within d. Zero disables the timeout.
func (c *Conn) SetIdleTimeout(d time.Duration) { c.idle = d }

// SetWriteTimeout sets the per-frame write deadline.
func (c *Conn) SetWriteTimeout(d time.Duration) { c.writeTO = d }

// Done is closed once the connection is closed.
func (c *Conn) Done() <-chan struct{} { return c.done }

// ---- reading ----

func (c *Conn) readFrame() (fin bool, op int, payload []byte, err error) {
	if c.idle > 0 {
		_ = c.c.SetReadDeadline(time.Now().Add(c.idle))
	}
	var h [2]byte
	if _, err = io.ReadFull(c.br, h[:]); err != nil {
		return
	}
	fin = h[0]&0x80 != 0
	if h[0]&0x70 != 0 {
		err = errors.New("ws: reserved bits set")
		return
	}
	op = int(h[0] & 0x0f)
	masked := h[1]&0x80 != 0
	n := int64(h[1] & 0x7f)
	switch n {
	case 126:
		var b [2]byte
		if _, err = io.ReadFull(c.br, b[:]); err != nil {
			return
		}
		n = int64(binary.BigEndian.Uint16(b[:]))
	case 127:
		var b [8]byte
		if _, err = io.ReadFull(c.br, b[:]); err != nil {
			return
		}
		u := binary.BigEndian.Uint64(b[:])
		if u>>63 != 0 {
			err = errors.New("ws: bad length")
			return
		}
		n = int64(u)
	}
	if op >= 8 && (!fin || n > 125) {
		err = errors.New("ws: bad control frame")
		return
	}
	if op != 0 && op != OpText && op != OpBinary && op != opClose && op != opPing && op != opPong {
		err = fmt.Errorf("ws: unknown opcode %d", op)
		return
	}
	if n > c.readLimit {
		err = ErrTooBig
		return
	}
	if !c.isClient && !masked {
		err = errors.New("ws: client frame not masked")
		return
	}
	if c.isClient && masked {
		err = errors.New("ws: server frame masked")
		return
	}
	var key [4]byte
	if masked {
		if _, err = io.ReadFull(c.br, key[:]); err != nil {
			return
		}
	}
	payload = make([]byte, n)
	if _, err = io.ReadFull(c.br, payload); err != nil {
		return
	}
	if masked {
		for i := range payload {
			payload[i] ^= key[i&3]
		}
	}
	return
}

// ReadMessage returns the next data message. Control frames are handled
// internally. A received close frame yields *CloseError.
func (c *Conn) ReadMessage() (int, []byte, error) {
	var msgOp int
	var buf []byte
	for {
		fin, op, p, err := c.readFrame()
		if err != nil {
			if errors.Is(err, ErrTooBig) {
				c.Close(CloseTooBig, "too big")
			}
			c.shutdown()
			return 0, nil, err
		}
		switch op {
		case opPing:
			_ = c.writeFrame(opPong, p)
			continue
		case opPong:
			continue
		case opClose:
			code, reason := CloseNormal, ""
			if len(p) >= 2 {
				code = int(binary.BigEndian.Uint16(p))
				reason = string(p[2:])
			}
			_ = c.writeFrame(opClose, p)
			c.shutdown()
			return 0, nil, &CloseError{Code: code, Reason: reason}
		case OpText, OpBinary:
			if buf != nil || msgOp != 0 {
				c.Close(CloseProtocol, "unexpected data frame")
				return 0, nil, errors.New("ws: unexpected data frame")
			}
			msgOp = op
		case 0:
			if msgOp == 0 {
				c.Close(CloseProtocol, "unexpected continuation")
				return 0, nil, errors.New("ws: unexpected continuation")
			}
		}
		if int64(len(buf))+int64(len(p)) > c.readLimit {
			c.Close(CloseTooBig, "too big")
			return 0, nil, ErrTooBig
		}
		if buf == nil && fin {
			return msgOp, p, nil
		}
		buf = append(buf, p...)
		if fin {
			return msgOp, buf, nil
		}
	}
}

// ---- writing ----

func (c *Conn) writeFrame(op int, data []byte) error {
	if c.closed.Load() && op != opClose {
		return ErrClosed
	}
	var hdr [14]byte
	hdr[0] = 0x80 | byte(op)
	n := len(data)
	hl := 2
	var maskBit byte
	if c.isClient {
		maskBit = 0x80
	}
	switch {
	case n < 126:
		hdr[1] = maskBit | byte(n)
	case n < 65536:
		hdr[1] = maskBit | 126
		binary.BigEndian.PutUint16(hdr[2:], uint16(n))
		hl = 4
	default:
		hdr[1] = maskBit | 127
		binary.BigEndian.PutUint64(hdr[2:], uint64(n))
		hl = 10
	}
	payload := data
	if c.isClient {
		var key [4]byte
		if _, err := rand.Read(key[:]); err != nil {
			return err
		}
		copy(hdr[hl:], key[:])
		hl += 4
		payload = make([]byte, n)
		for i := range data {
			payload[i] = data[i] ^ key[i&3]
		}
	}
	c.wmu.Lock()
	defer c.wmu.Unlock()
	if c.writeTO > 0 {
		_ = c.c.SetWriteDeadline(time.Now().Add(c.writeTO))
	}
	bufs := net.Buffers{hdr[:hl], payload}
	if _, err := bufs.WriteTo(c.c); err != nil {
		c.shutdown()
		return err
	}
	return nil
}

// WriteMessage sends a text or binary message.
func (c *Conn) WriteMessage(op int, data []byte) error {
	if op != OpText && op != OpBinary {
		return errors.New("ws: bad opcode")
	}
	return c.writeFrame(op, data)
}

// WriteText sends a text message.
func (c *Conn) WriteText(s string) error { return c.writeFrame(OpText, []byte(s)) }

// Ping sends a ping frame.
func (c *Conn) Ping() error { return c.writeFrame(opPing, nil) }

// KeepAlive sends pings every interval until the connection closes.
func (c *Conn) KeepAlive(interval time.Duration) {
	go func() {
		t := time.NewTicker(interval)
		defer t.Stop()
		for {
			select {
			case <-t.C:
				if c.Ping() != nil {
					return
				}
			case <-c.done:
				return
			}
		}
	}()
}

func (c *Conn) shutdown() {
	c.closed.Store(true)
	c.doneOnce.Do(func() { close(c.done) })
	_ = c.c.Close()
}

// Close sends a close frame (best effort) and closes the connection.
func (c *Conn) Close(code int, reason string) {
	if c.closed.Swap(true) {
		c.shutdown()
		return
	}
	if len(reason) > 120 {
		reason = reason[:120]
	}
	p := make([]byte, 2+len(reason))
	binary.BigEndian.PutUint16(p, uint16(code))
	copy(p[2:], reason)
	c.wmu.Lock()
	_ = c.c.SetWriteDeadline(time.Now().Add(2 * time.Second))
	hdr := []byte{0x80 | opClose, 0}
	hdr[1] = byte(len(p))
	var out []byte
	if c.isClient {
		var key [4]byte
		_, _ = rand.Read(key[:])
		hdr[1] |= 0x80
		out = append(hdr, key[:]...)
		for i := range p {
			p[i] ^= key[i&3]
		}
	} else {
		out = hdr
	}
	out = append(out, p...)
	_, _ = c.c.Write(out)
	c.wmu.Unlock()
	c.shutdown()
}

// ---- server upgrade ----

// Upgrade performs the server side handshake. checkOrigin may be nil.
func Upgrade(w http.ResponseWriter, r *http.Request, checkOrigin func(*http.Request) bool) (*Conn, error) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return nil, errors.New("ws: bad method")
	}
	if !headerHas(r.Header, "Connection", "upgrade") || !headerHas(r.Header, "Upgrade", "websocket") {
		http.Error(w, "websocket upgrade required", http.StatusBadRequest)
		return nil, errors.New("ws: not an upgrade")
	}
	if r.Header.Get("Sec-WebSocket-Version") != "13" {
		w.Header().Set("Sec-WebSocket-Version", "13")
		http.Error(w, "unsupported version", http.StatusBadRequest)
		return nil, errors.New("ws: bad version")
	}
	if checkOrigin != nil && !checkOrigin(r) {
		http.Error(w, "forbidden origin", http.StatusForbidden)
		return nil, errors.New("ws: origin rejected")
	}
	key := r.Header.Get("Sec-WebSocket-Key")
	if kb, err := base64.StdEncoding.DecodeString(key); err != nil || len(kb) != 16 {
		http.Error(w, "bad key", http.StatusBadRequest)
		return nil, errors.New("ws: bad key")
	}
	rc := http.NewResponseController(w)
	nc, rw, err := rc.Hijack()
	if err != nil {
		http.Error(w, "cannot hijack", http.StatusInternalServerError)
		return nil, err
	}
	_ = nc.SetDeadline(time.Time{})
	resp := "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: " +
		acceptKey(key) + "\r\n\r\n"
	if _, err := rw.WriteString(resp); err != nil {
		nc.Close()
		return nil, err
	}
	if err := rw.Flush(); err != nil {
		nc.Close()
		return nil, err
	}
	return newConn(nc, rw.Reader, false), nil
}

func acceptKey(key string) string {
	h := sha1.Sum([]byte(key + guid))
	return base64.StdEncoding.EncodeToString(h[:])
}

func headerHas(h http.Header, name, token string) bool {
	for _, v := range h.Values(name) {
		for _, p := range strings.Split(v, ",") {
			if strings.EqualFold(strings.TrimSpace(p), token) {
				return true
			}
		}
	}
	return false
}

// ---- client ----

// DialOptions configures Dial.
type DialOptions struct {
	Header    http.Header
	TLSConfig *tls.Config
	Timeout   time.Duration
}

// Dial opens a client connection to a ws:// or wss:// URL.
func Dial(ctx context.Context, rawURL string, opt DialOptions) (*Conn, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, err
	}
	var useTLS bool
	switch u.Scheme {
	case "wss", "https":
		useTLS = true
	case "ws", "http":
	default:
		return nil, fmt.Errorf("ws: unsupported scheme %q", u.Scheme)
	}
	host := u.Host
	if u.Port() == "" {
		if useTLS {
			host = net.JoinHostPort(u.Hostname(), "443")
		} else {
			host = net.JoinHostPort(u.Hostname(), "80")
		}
	}
	to := opt.Timeout
	if to == 0 {
		to = 20 * time.Second
	}
	d := net.Dialer{Timeout: to}
	nc, err := d.DialContext(ctx, "tcp", host)
	if err != nil {
		return nil, err
	}
	if useTLS {
		cfg := opt.TLSConfig
		if cfg == nil {
			cfg = &tls.Config{}
		} else {
			cfg = cfg.Clone()
		}
		if cfg.ServerName == "" {
			cfg.ServerName = u.Hostname()
		}
		if cfg.MinVersion == 0 {
			cfg.MinVersion = tls.VersionTLS12
		}
		tc := tls.Client(nc, cfg)
		_ = tc.SetDeadline(time.Now().Add(to))
		if err := tc.HandshakeContext(ctx); err != nil {
			nc.Close()
			return nil, err
		}
		_ = tc.SetDeadline(time.Time{})
		nc = tc
	}
	var kb [16]byte
	_, _ = rand.Read(kb[:])
	key := base64.StdEncoding.EncodeToString(kb[:])
	path := u.RequestURI()
	var sb strings.Builder
	sb.WriteString("GET " + path + " HTTP/1.1\r\nHost: " + u.Host + "\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n")
	sb.WriteString("Sec-WebSocket-Key: " + key + "\r\nSec-WebSocket-Version: 13\r\n")
	for k, vs := range opt.Header {
		for _, v := range vs {
			if strings.ContainsAny(k+v, "\r\n") {
				nc.Close()
				return nil, errors.New("ws: bad header")
			}
			sb.WriteString(k + ": " + v + "\r\n")
		}
	}
	sb.WriteString("\r\n")
	_ = nc.SetDeadline(time.Now().Add(to))
	if _, err := io.WriteString(nc, sb.String()); err != nil {
		nc.Close()
		return nil, err
	}
	br := bufio.NewReaderSize(nc, 32*1024)
	resp, err := http.ReadResponse(br, &http.Request{Method: "GET"})
	if err != nil {
		nc.Close()
		return nil, err
	}
	if resp.StatusCode != http.StatusSwitchingProtocols ||
		!headerHas(resp.Header, "Upgrade", "websocket") ||
		resp.Header.Get("Sec-WebSocket-Accept") != acceptKey(key) {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		nc.Close()
		return nil, &HandshakeError{Status: resp.StatusCode, Body: strings.TrimSpace(string(body))}
	}
	_ = nc.SetDeadline(time.Time{})
	return newConn(nc, br, true), nil
}

// HandshakeError is returned when the server refuses the upgrade.
type HandshakeError struct {
	Status int
	Body   string
}

func (e *HandshakeError) Error() string {
	return fmt.Sprintf("ws: handshake failed: HTTP %d %s", e.Status, e.Body)
}
