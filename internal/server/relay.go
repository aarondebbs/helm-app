package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"helm/internal/proto"
	"helm/internal/ws"
)

var activeSessions sync.Map // deviceID+kind -> struct{}

func sendStatus(c *ws.Conn, t, msg string) {
	b, _ := json.Marshal(map[string]string{"t": t, "msg": msg})
	_ = c.WriteMessage(ws.OpText, b)
}

// handleUIChannel pairs a browser WebSocket with an agent data channel
// (remote screen or terminal).
func (s *Server) handleUIChannel(w http.ResponseWriter, r *http.Request) {
	sess := s.sessionFor(r)
	if sess == nil {
		writeErr(w, 401, "not signed in")
		return
	}
	q := r.URL.Query()
	if r.Header.Get("Origin") == "" || !sameOrigin(r) || !ctEq(q.Get("csrf"), sess.CSRF) {
		writeErr(w, 403, "bad origin or CSRF token")
		return
	}
	if !s.needStepUp(w, sess) {
		return
	}
	kind, device := q.Get("kind"), q.Get("device")
	if kind != proto.KindScreen && kind != proto.KindTerminal {
		writeErr(w, 400, "bad kind")
		return
	}
	if _, ok := s.st.device(device); !ok {
		writeErr(w, 404, "no such device")
		return
	}
	if a := s.hub.online(device); a == nil || !a.approved.Load() {
		writeErr(w, 409, "device is offline or not approved")
		return
	}
	key := device + "/" + kind
	if _, busy := activeSessions.LoadOrStore(key, struct{}{}); busy {
		writeErr(w, 409, "a "+kind+" session is already open for this device")
		return
	}
	defer activeSessions.Delete(key)

	c, err := ws.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	c.SetReadLimit(256 << 10)
	c.SetIdleTimeout(3 * time.Minute)
	c.KeepAlive(25 * time.Second)
	defer c.Close(ws.CloseNormal, "")

	viewOnly := q.Get("viewOnly") == "1"
	args := proto.OpenArgs{ViewOnly: viewOnly}
	if kind == proto.KindTerminal {
		args.Shell = q.Get("shell")
	}
	sendStatus(c, "status", "contacting the PC (waiting for permission if someone is using it)…")
	ac, err := s.hub.openChannel(device, kind, args, 80*time.Second)
	if err != nil {
		s.record(r, kind+"_refused", device, err.Error())
		s.sessionRefused(r, device, kind, err.Error())
		sendStatus(c, "error", err.Error())
		return
	}
	defer ac.Close(ws.CloseNormal, "")
	ac.SetIdleTimeout(2 * time.Minute)
	started := time.Now()
	s.record(r, kind+"_start", device, fmt.Sprintf("viewOnly=%v", viewOnly))
	recID := s.sessionStart(r, device, kind, viewOnly)
	defer func() {
		s.record(r, kind+"_end", device, time.Since(started).Round(time.Second).String())
		s.sessionEnd(recID, "ended", "")
	}()
	sendStatus(c, "status", "connected")

	done := make(chan struct{}, 2)
	go func() { // agent -> browser
		defer func() { done <- struct{}{} }()
		for {
			op, d, err := ac.ReadMessage()
			if err != nil {
				return
			}
			if c.WriteMessage(op, d) != nil {
				return
			}
		}
	}()
	go func() { // browser -> agent
		defer func() { done <- struct{}{} }()
		for {
			op, d, err := c.ReadMessage()
			if err != nil {
				return
			}
			if op != ws.OpText {
				continue
			}
			if kind == proto.KindScreen && viewOnly && !viewOnlyAllowed(d) {
				continue
			}
			if ac.WriteMessage(ws.OpText, d) != nil {
				return
			}
		}
	}()
	<-done
}

// viewOnlyAllowed permits only display-tuning messages in view-only mode.
func viewOnlyAllowed(msg []byte) bool {
	var m struct {
		T string `json:"t"`
	}
	if json.Unmarshal(msg, &m) != nil {
		return false
	}
	return m.T == "q" || m.T == "refresh"
}

// ---- file transfer ----

func contentDisposition(name string) string {
	name = strings.NewReplacer("\\", "/").Replace(name)
	if i := strings.LastIndex(name, "/"); i >= 0 {
		name = name[i+1:]
	}
	if name == "" {
		name = "download"
	}
	return "attachment; filename*=UTF-8''" + url.PathEscape(name)
}

func readCtl(c *ws.Conn) (proto.Frame, []byte, int, error) {
	op, d, err := c.ReadMessage()
	if err != nil {
		return proto.Frame{}, nil, 0, err
	}
	var f proto.Frame
	if op == ws.OpText {
		_ = json.Unmarshal(d, &f)
	}
	return f, d, op, nil
}

func (s *Server) handleFileDownload(w http.ResponseWriter, r *http.Request, sess *session) {
	if !s.needStepUp(w, sess) {
		return
	}
	id, path := r.PathValue("id"), r.URL.Query().Get("path")
	if path == "" {
		writeErr(w, 400, "path required")
		return
	}
	ac, err := s.hub.openChannel(id, proto.KindDownload, proto.OpenArgs{Path: path}, 30*time.Second)
	if err != nil {
		writeErr(w, 409, err.Error())
		return
	}
	defer ac.Close(ws.CloseNormal, "")
	ac.SetIdleTimeout(2 * time.Minute)
	ac.SetReadLimit(8 << 20)
	f, _, _, err := readCtl(ac)
	if err != nil {
		writeErr(w, 502, "PC closed the connection")
		return
	}
	if f.T == "err" {
		writeErr(w, 404, f.Msg)
		return
	}
	if f.T != "meta" {
		writeErr(w, 502, "protocol error")
		return
	}
	var meta struct {
		Size int64  `json:"size"`
		Name string `json:"name"`
	}
	_ = json.Unmarshal(f.Data, &meta)
	s.record(r, "file_download", id, path)
	fileRec := s.sessionStart(r, id, "file", false)
	defer s.sessionEnd(fileRec, "ended", "download "+path)
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", contentDisposition(meta.Name))
	w.Header().Set("Content-Length", strconv.FormatInt(meta.Size, 10))
	var sent int64
	for {
		op, d, err := ac.ReadMessage()
		if err != nil {
			panic(http.ErrAbortHandler)
		}
		if op == ws.OpBinary {
			n, werr := w.Write(d)
			sent += int64(n)
			if werr != nil {
				return
			}
			continue
		}
		var cf proto.Frame
		_ = json.Unmarshal(d, &cf)
		if cf.T == "end" && sent == meta.Size {
			return
		}
		panic(http.ErrAbortHandler) // error mid-stream or size mismatch
	}
}

func (s *Server) handleFileUpload(w http.ResponseWriter, r *http.Request, sess *session) {
	if !s.needStepUp(w, sess) {
		return
	}
	id, q := r.PathValue("id"), r.URL.Query()
	path := q.Get("path")
	if path == "" {
		writeErr(w, 400, "path required")
		return
	}
	if r.ContentLength < 0 {
		writeErr(w, http.StatusLengthRequired, "Content-Length required")
		return
	}
	if r.ContentLength > 4<<30 {
		writeErr(w, http.StatusRequestEntityTooLarge, "file too large")
		return
	}
	ac, err := s.hub.openChannel(id, proto.KindUpload,
		proto.OpenArgs{Path: path, Size: r.ContentLength, Overwrite: q.Get("overwrite") == "1"}, 30*time.Second)
	if err != nil {
		writeErr(w, 409, err.Error())
		return
	}
	defer ac.Close(ws.CloseNormal, "")
	ac.SetIdleTimeout(2 * time.Minute)
	f, _, _, err := readCtl(ac)
	if err != nil {
		writeErr(w, 502, "PC closed the connection")
		return
	}
	if f.T == "err" {
		writeErr(w, 400, f.Msg)
		return
	}
	fileRec := s.sessionStart(r, id, "file", false)
	defer s.sessionEnd(fileRec, "ended", "upload "+path)
	buf := make([]byte, 256<<10)
	var total int64
	for {
		n, rerr := r.Body.Read(buf)
		if n > 0 {
			if ac.WriteMessage(ws.OpBinary, buf[:n]) != nil {
				writeErr(w, 502, "PC closed the connection")
				return
			}
			total += int64(n)
		}
		if rerr == io.EOF {
			break
		}
		if rerr != nil {
			writeErr(w, 400, "upload interrupted")
			return
		}
	}
	_ = ac.WriteText(`{"t":"end"}`)
	f, _, _, err = readCtl(ac)
	if err != nil || f.T != "done" {
		msg := "upload failed"
		if f.Msg != "" {
			msg = f.Msg
		}
		writeErr(w, 502, msg)
		return
	}
	s.record(r, "file_upload", id, fmt.Sprintf("%s (%d bytes)", path, total))
	writeJSON(w, 200, map[string]any{"ok": true, "size": total})
}

// ---- RDP tunnels ----

type tunnel struct {
	ID       string    `json:"id"`
	DeviceID string    `json:"deviceId"`
	Bind     string    `json:"bind"`
	Port     int       `json:"port"`
	Expires  time.Time `json:"expires"`

	ln    net.Listener
	busy  atomic.Bool
	timer *time.Timer
	cmu   sync.Mutex
	conn  net.Conn
}

type tunnelMgr struct {
	s  *Server
	mu sync.Mutex
	m  map[string]*tunnel
}

func newTunnelMgr(s *Server) *tunnelMgr { return &tunnelMgr{s: s, m: map[string]*tunnel{}} }

const (
	tunnelPortLo = 33890
	tunnelPortHi = 33899
)

func (m *tunnelMgr) open(deviceID string, ttl time.Duration) (*tunnel, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, t := range m.m {
		if t.DeviceID == deviceID {
			return nil, errors.New("a tunnel for this device is already open")
		}
	}
	var ln net.Listener
	var port int
	for p := tunnelPortLo; p <= tunnelPortHi; p++ {
		l, err := net.Listen("tcp", net.JoinHostPort(m.s.cfg.RDPBind, strconv.Itoa(p)))
		if err == nil {
			ln, port = l, p
			break
		}
	}
	if ln == nil {
		return nil, errors.New("no free tunnel port")
	}
	t := &tunnel{ID: randHex(6), DeviceID: deviceID, Bind: m.s.cfg.RDPBind, Port: port, Expires: time.Now().Add(ttl), ln: ln}
	t.timer = time.AfterFunc(ttl, func() { m.close(t.ID) })
	m.m[t.ID] = t
	go m.serve(t)
	return t, nil
}

func (m *tunnelMgr) close(id string) bool {
	m.mu.Lock()
	t := m.m[id]
	delete(m.m, id)
	m.mu.Unlock()
	if t == nil {
		return false
	}
	t.timer.Stop()
	_ = t.ln.Close()
	t.cmu.Lock()
	if t.conn != nil {
		_ = t.conn.Close()
	}
	t.cmu.Unlock()
	return true
}

type tunnelView struct {
	ID       string    `json:"id"`
	DeviceID string    `json:"deviceId"`
	Bind     string    `json:"bind"`
	Port     int       `json:"port"`
	Expires  time.Time `json:"expires"`
	Active   bool      `json:"active"`
}

func (m *tunnelMgr) list() []tunnelView {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := []tunnelView{}
	for _, t := range m.m {
		out = append(out, tunnelView{t.ID, t.DeviceID, t.Bind, t.Port, t.Expires, t.busy.Load()})
	}
	return out
}

func (m *tunnelMgr) serve(t *tunnel) {
	for {
		c, err := t.ln.Accept()
		if err != nil {
			return
		}
		if !t.busy.CompareAndSwap(false, true) {
			c.Close()
			continue
		}
		t.cmu.Lock()
		t.conn = c
		t.cmu.Unlock()
		go func() {
			defer t.busy.Store(false)
			defer c.Close()
			ac, err := m.s.hub.openChannel(t.DeviceID, proto.KindTCP, proto.OpenArgs{}, 20*time.Second)
			if err != nil {
				m.s.audit.add(AuditEntry{Action: "rdp_tunnel_failed", Device: t.DeviceID, Detail: err.Error()})
				return
			}
			defer ac.Close(ws.CloseNormal, "")
			ac.SetIdleTimeout(10 * time.Minute)
			m.s.audit.add(AuditEntry{Action: "rdp_tunnel_connection", Device: t.DeviceID, Detail: c.RemoteAddr().String()})
			done := make(chan struct{}, 2)
			go func() {
				defer func() { done <- struct{}{} }()
				for {
					op, d, err := ac.ReadMessage()
					if err != nil {
						return
					}
					if op == ws.OpBinary {
						if _, err := c.Write(d); err != nil {
							return
						}
					}
				}
			}()
			go func() {
				defer func() { done <- struct{}{} }()
				buf := make([]byte, 32<<10)
				for {
					n, err := c.Read(buf)
					if n > 0 && ac.WriteMessage(ws.OpBinary, buf[:n]) != nil {
						return
					}
					if err != nil {
						return
					}
				}
			}()
			<-done
		}()
	}
}

func (s *Server) handleRDPOpen(w http.ResponseWriter, r *http.Request, sess *session) {
	if !s.needStepUp(w, sess) {
		return
	}
	id := r.PathValue("id")
	var req struct{ Minutes int }
	if !readJSON(w, r, &req) {
		return
	}
	if req.Minutes <= 0 || req.Minutes > 240 {
		req.Minutes = 30
	}
	if a := s.hub.online(id); a == nil || !a.approved.Load() {
		writeErr(w, 409, "device is offline or not approved")
		return
	}
	t, err := s.tunnels.open(id, time.Duration(req.Minutes)*time.Minute)
	if err != nil {
		writeErr(w, 409, err.Error())
		return
	}
	s.record(r, "rdp_tunnel_open", id, fmt.Sprintf("%s:%d for %dm", t.Bind, t.Port, req.Minutes))
	rid := s.sessionStart(r, id, "rdp", false)
	s.sessionEnd(rid, "ended", fmt.Sprintf("tunnel %s:%d opened for %d minutes", t.Bind, t.Port, req.Minutes))
	writeJSON(w, 200, t)
}

func (s *Server) handleTunnels(w http.ResponseWriter, r *http.Request, sess *session) {
	writeJSON(w, 200, s.tunnels.list())
}

func (s *Server) handleTunnelClose(w http.ResponseWriter, r *http.Request, sess *session) {
	if !s.tunnels.close(r.PathValue("id")) {
		writeErr(w, 404, "no such tunnel")
		return
	}
	s.record(r, "rdp_tunnel_close", "", r.PathValue("id"))
	writeJSON(w, 200, map[string]bool{"ok": true})
}
