package agent

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"time"

	"helm/internal/proto"
	"helm/internal/ws"
)

// helperLaunch describes how to start the screen helper process.
type helperLaunch struct {
	Addr     string // 127.0.0.1:port of the rendezvous listener
	Token    string
	Consent  string
	ViewOnly bool
}

// rendezvous is a one-shot loopback listener the helper connects back to.
type rendezvous struct {
	ln    net.Listener
	srv   *http.Server
	token string
	conn  chan *ws.Conn
}

func newRendezvous() (*rendezvous, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	var tb [24]byte
	_, _ = rand.Read(tb[:])
	r := &rendezvous{ln: ln, token: hex.EncodeToString(tb[:]), conn: make(chan *ws.Conn, 1)}
	mux := http.NewServeMux()
	mux.HandleFunc("/helper", func(w http.ResponseWriter, req *http.Request) {
		if subtle.ConstantTimeCompare([]byte(req.Header.Get("X-Helm-Token")), []byte(r.token)) != 1 {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		c, err := ws.Upgrade(w, req, nil)
		if err != nil {
			return
		}
		c.SetReadLimit(16 << 20)
		select {
		case r.conn <- c:
		default:
			c.Close(ws.ClosePolicy, "already connected")
		}
	})
	r.srv = &http.Server{Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	go func() { _ = r.srv.Serve(ln) }()
	return r, nil
}

func (r *rendezvous) close() {
	_ = r.srv.Close()
	_ = r.ln.Close()
}

// openScreen runs a remote screen session: it starts a helper inside the
// interactive session, waits for consent (when required), then bridges the
// helper's frames to the server channel.
func (a *Agent) openScreen(ctx context.Context, sid string, args proto.OpenArgs) error {
	if !a.screenMu.TryLock() {
		return errors.New("a screen session is already running on this PC")
	}
	defer a.screenMu.Unlock()

	rv, err := newRendezvous()
	if err != nil {
		return err
	}
	defer rv.close()
	stop, err := launchHelper(ctx, helperLaunch{Addr: rv.ln.Addr().String(), Token: rv.token,
		Consent: a.cfg.ConsentMode, ViewOnly: args.ViewOnly})
	if err != nil {
		return err
	}
	defer stop()

	var hc *ws.Conn
	select {
	case hc = <-rv.conn:
	case <-time.After(30 * time.Second):
		return errors.New("the screen helper did not start (is anyone logged on or the sign-in screen showing?)")
	case <-ctx.Done():
		return ctx.Err()
	}
	defer hc.Close(ws.CloseNormal, "")

	// Wait for the consent decision (the helper shows the prompt if needed).
	hc.SetIdleTimeout(90 * time.Second)
	for {
		op, msg, err := hc.ReadMessage()
		if err != nil {
			return errors.New("the screen helper stopped unexpectedly")
		}
		if op != ws.OpText {
			continue
		}
		var m struct {
			T   string `json:"t"`
			OK  bool   `json:"ok"`
			Msg string `json:"msg"`
		}
		if json.Unmarshal(msg, &m) != nil {
			continue
		}
		if m.T == "error" {
			return errors.New(m.Msg)
		}
		if m.T != "consent" {
			continue
		}
		if !m.OK {
			if m.Msg == "" {
				m.Msg = "the person at the PC declined the request"
			}
			return errors.New(m.Msg)
		}
		break
	}

	ch, err := a.dialChannel(ctx, sid)
	if err != nil {
		return err
	}
	defer ch.Close(ws.CloseNormal, "")
	a.log.Printf("screen session started (viewOnly=%v)", args.ViewOnly)
	defer a.log.Printf("screen session ended")
	_ = hc.WriteText(`{"t":"start"}`)
	hc.SetIdleTimeout(30 * time.Second) // the helper streams or pings continuously

	done := make(chan struct{}, 2)
	go func() { // helper -> server
		defer func() { done <- struct{}{} }()
		for {
			op, d, err := hc.ReadMessage()
			if err != nil {
				return
			}
			if ch.WriteMessage(op, d) != nil {
				return
			}
		}
	}()
	go func() { // server -> helper
		defer func() { done <- struct{}{} }()
		for {
			op, d, err := ch.ReadMessage()
			if err != nil {
				return
			}
			if op != ws.OpText {
				continue
			}
			if args.ViewOnly && !viewOnlyMsg(d) {
				continue
			}
			if isCAD(d) { // Ctrl+Alt+Del can only be raised by the service
				go func() {
					if err := sendSAS(); err != nil {
						a.log.Printf("ctrl+alt+del: %v", err)
					}
				}()
				continue
			}
			if hc.WriteMessage(ws.OpText, d) != nil {
				return
			}
		}
	}()
	select {
	case <-done:
	case <-ctx.Done():
	}
	return nil
}

func viewOnlyMsg(d []byte) bool {
	var m struct {
		T string `json:"t"`
	}
	return json.Unmarshal(d, &m) == nil && (m.T == "q" || m.T == "refresh")
}

func isCAD(d []byte) bool {
	var m struct {
		T string `json:"t"`
	}
	return json.Unmarshal(d, &m) == nil && m.T == "cad"
}
