package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"sync"
	"time"
	"unicode/utf8"

	"helm/internal/proto"
	"helm/internal/ws"
)

func (a *Agent) dialChannel(ctx context.Context, sid string) (*ws.Conn, error) {
	c, err := ws.Dial(ctx, a.wsURL("/ws/agent/chan/"+sid), ws.DialOptions{Header: a.authHeader(), TLSConfig: a.cfg.TLS})
	if err != nil {
		return nil, err
	}
	c.SetReadLimit(16 << 20)
	c.SetIdleTimeout(5 * time.Minute)
	c.KeepAlive(25 * time.Second)
	return c, nil
}

func (a *Agent) handleOpen(ctx context.Context, f proto.Frame) {
	defer func() {
		if r := recover(); r != nil {
			a.log.Printf("panic opening %s: %v", f.Kind, r)
			a.sendFrame(proto.Frame{T: proto.TOpenFail, SID: f.SID, Err: fmt.Sprintf("internal error: %v", r)})
		}
	}()
	var args proto.OpenArgs
	_ = json.Unmarshal(f.Args, &args)
	var err error
	switch f.Kind {
	case proto.KindScreen:
		err = a.openScreen(ctx, f.SID, args)
	case proto.KindTerminal:
		err = a.openTerminal(ctx, f.SID, args)
	case proto.KindDownload:
		err = a.openDownload(ctx, f.SID, args)
	case proto.KindUpload:
		err = a.openUpload(ctx, f.SID, args)
	case proto.KindTCP:
		err = a.openTCP(ctx, f.SID)
	default:
		err = fmt.Errorf("unsupported channel kind %q", f.Kind)
	}
	if err != nil {
		a.log.Printf("channel %s (%s) failed: %v", f.SID, f.Kind, err)
		a.sendFrame(proto.Frame{T: proto.TOpenFail, SID: f.SID, Err: err.Error()})
	}
}

func sendJSON(c *ws.Conn, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	return c.WriteMessage(ws.OpText, b)
}

// ---- terminal ----

// utf8Writer forwards process output to a channel as text frames, keeping
// multi-byte characters intact across chunk boundaries.
type utf8Writer struct {
	mu      sync.Mutex
	c       *ws.Conn
	pending []byte
}

func (w *utf8Writer) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	buf := append(w.pending, p...)
	buf, w.pending = splitIncompleteRune(buf)
	w.pending = append([]byte(nil), w.pending...)
	for len(buf) > 0 {
		n := len(buf)
		if n > 16<<10 {
			n = 16 << 10
			for n > 0 && !utf8.RuneStart(buf[n]) { // do not split a rune
				n--
			}
			if n == 0 {
				n = 16 << 10
			}
		}
		chunk := buf[:n]
		buf = buf[n:]
		if err := sendJSON(w.c, map[string]string{"t": "out", "d": toValidUTF8(chunk)}); err != nil {
			return len(p), err
		}
	}
	return len(p), nil
}

// splitIncompleteRune separates an incomplete multi-byte sequence at the end of b.
func splitIncompleteRune(b []byte) (complete, rest []byte) {
	for i := 1; i <= 3 && i <= len(b); i++ {
		c := b[len(b)-i]
		if c&0xC0 == 0x80 { // continuation byte, keep looking back
			continue
		}
		if utf8.RuneStart(c) && !utf8.FullRune(b[len(b)-i:]) {
			return b[:len(b)-i], b[len(b)-i:]
		}
		break
	}
	return b, nil
}

func toValidUTF8(b []byte) string {
	if utf8.Valid(b) {
		return string(b)
	}
	out := make([]rune, 0, len(b))
	for len(b) > 0 {
		r, size := utf8.DecodeRune(b)
		if r == utf8.RuneError && size == 1 {
			r = '�'
		}
		out = append(out, r)
		b = b[size:]
	}
	return string(out)
}

func (a *Agent) openTerminal(ctx context.Context, sid string, args proto.OpenArgs) error {
	shell := args.Shell
	if shell == "" {
		shell = "powershell"
	}
	if shell != "powershell" && shell != "cmd" {
		return errors.New("unsupported shell")
	}
	if realUnix() {
		shell = "bash"
	}
	c, err := a.dialChannel(ctx, sid)
	if err != nil {
		return err
	}
	defer c.Close(ws.CloseNormal, "")
	cmd := terminalCommand(ctx, shell)
	hideWindow(cmd)
	w := &utf8Writer{c: c}
	cmd.Stdout, cmd.Stderr = w, w
	stdin, err := cmd.StdinPipe()
	if err != nil {
		_ = sendJSON(c, map[string]string{"t": "error", "msg": err.Error()})
		return nil
	}
	if err := cmd.Start(); err != nil {
		_ = sendJSON(c, map[string]string{"t": "error", "msg": "cannot start shell: " + err.Error()})
		return nil
	}
	a.log.Printf("terminal session started (%s)", shell)
	switch {
	case runtime.GOOS != "windows" || shell == "bash":
		// development stand-in shell needs no setup
	case shell == "powershell":
		_, _ = io.WriteString(stdin, "[Console]::OutputEncoding=[System.Text.UTF8Encoding]::new($false); $OutputEncoding=[Console]::OutputEncoding\n")
	case shell == "cmd":
		_, _ = io.WriteString(stdin, "chcp 65001 >nul\r\n")
	}
	exited := make(chan int, 1)
	go func() {
		err := cmd.Wait()
		exited <- exitCode(err)
		c.Close(ws.CloseNormal, "shell exited")
	}()
readLoop:
	for {
		op, msg, err := c.ReadMessage()
		if err != nil {
			break
		}
		if op != ws.OpText {
			continue
		}
		var m struct {
			T string `json:"t"`
			D string `json:"d"`
		}
		if json.Unmarshal(msg, &m) != nil {
			continue
		}
		switch m.T {
		case "in":
			if len(m.D) > 64<<10 {
				continue
			}
			if _, err := io.WriteString(stdin, m.D); err != nil {
				break readLoop
			}
		case "kill":
			killTree(cmd.Process.Pid)
		}
	}
	_ = stdin.Close()
	killTree(cmd.Process.Pid)
	select {
	case code := <-exited:
		a.log.Printf("terminal session ended (exit %d)", code)
	case <-time.After(5 * time.Second):
	}
	return nil
}

// ---- file transfer ----

func (a *Agent) openDownload(ctx context.Context, sid string, args proto.OpenArgs) error {
	p, err := normPath(args.Path)
	if err != nil {
		return err
	}
	st, err := os.Stat(p)
	if err != nil {
		return err
	}
	if !st.Mode().IsRegular() {
		return errors.New("not a regular file")
	}
	f, err := os.Open(p)
	if err != nil {
		return err
	}
	defer f.Close()
	c, err := a.dialChannel(ctx, sid)
	if err != nil {
		return err
	}
	defer c.Close(ws.CloseNormal, "")
	meta, _ := json.Marshal(map[string]any{"size": st.Size(), "name": filepath.Base(p)})
	if err := sendJSON(c, proto.Frame{T: "meta", Data: meta}); err != nil {
		return nil
	}
	buf := make([]byte, 256<<10)
	var sent int64
	for {
		n, rerr := f.Read(buf)
		if n > 0 {
			if err := c.WriteMessage(ws.OpBinary, buf[:n]); err != nil {
				return nil
			}
			sent += int64(n)
		}
		if rerr == io.EOF {
			break
		}
		if rerr != nil {
			_ = sendJSON(c, proto.Frame{T: "err", Msg: rerr.Error()})
			return nil
		}
	}
	if sent != st.Size() {
		_ = sendJSON(c, proto.Frame{T: "err", Msg: "file changed while reading"})
		return nil
	}
	_ = sendJSON(c, proto.Frame{T: "end"})
	// wait for the server to close so the final frame is flushed
	c.SetIdleTimeout(10 * time.Second)
	_, _, _ = c.ReadMessage()
	return nil
}

func (a *Agent) openUpload(ctx context.Context, sid string, args proto.OpenArgs) error {
	p, err := normPath(args.Path)
	if err != nil {
		return err
	}
	if err := a.checkNotProtected(p); err != nil {
		return err
	}
	if st, err := os.Stat(filepath.Dir(p)); err != nil || !st.IsDir() {
		return errors.New("destination folder does not exist")
	}
	if _, err := os.Lstat(p); err == nil && !args.Overwrite {
		return errors.New("a file with that name already exists")
	}
	tmp := p + ".helm-part"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644)
	if err != nil {
		return err
	}
	done := false
	defer func() {
		f.Close()
		if !done {
			os.Remove(tmp)
		}
	}()
	c, err := a.dialChannel(ctx, sid)
	if err != nil {
		return err
	}
	defer c.Close(ws.CloseNormal, "")
	_ = sendJSON(c, proto.Frame{T: "ready"})
	var got int64
	for {
		op, msg, err := c.ReadMessage()
		if err != nil {
			return nil
		}
		if op == ws.OpBinary {
			n, werr := f.Write(msg)
			got += int64(n)
			if werr != nil {
				_ = sendJSON(c, proto.Frame{T: "err", Msg: werr.Error()})
				return nil
			}
			continue
		}
		var fr proto.Frame
		_ = json.Unmarshal(msg, &fr)
		if fr.T != "end" {
			continue
		}
		if err := f.Close(); err != nil {
			_ = sendJSON(c, proto.Frame{T: "err", Msg: err.Error()})
			return nil
		}
		if args.Size > 0 && got != args.Size {
			_ = sendJSON(c, proto.Frame{T: "err", Msg: fmt.Sprintf("size mismatch: expected %d bytes, got %d", args.Size, got)})
			return nil
		}
		if err := os.Rename(tmp, p); err != nil {
			_ = sendJSON(c, proto.Frame{T: "err", Msg: err.Error()})
			return nil
		}
		done = true
		_ = sendJSON(c, proto.Frame{T: "done"})
		c.SetIdleTimeout(5 * time.Second)
		_, _, _ = c.ReadMessage()
		return nil
	}
}

// ---- TCP tunnel (RDP) ----

// openTCP connects the channel to the local RDP port. The target is fixed to
// 127.0.0.1 so the tunnel cannot be used to reach other machines.
func (a *Agent) openTCP(ctx context.Context, sid string) error {
	port := rdpPort()
	conn, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), 5*time.Second)
	if err != nil {
		return fmt.Errorf("Remote Desktop is not listening on this PC (port %d): enable it first", port)
	}
	defer conn.Close()
	c, err := a.dialChannel(ctx, sid)
	if err != nil {
		return err
	}
	defer c.Close(ws.CloseNormal, "")
	c.SetIdleTimeout(10 * time.Minute)
	done := make(chan struct{}, 2)
	go func() {
		defer func() { done <- struct{}{} }()
		for {
			op, d, err := c.ReadMessage()
			if err != nil {
				return
			}
			if op == ws.OpBinary {
				if _, err := conn.Write(d); err != nil {
					return
				}
			}
		}
	}()
	go func() {
		defer func() { done <- struct{}{} }()
		buf := make([]byte, 32<<10)
		for {
			n, err := conn.Read(buf)
			if n > 0 && c.WriteMessage(ws.OpBinary, buf[:n]) != nil {
				return
			}
			if err != nil {
				return
			}
		}
	}()
	<-done
	return nil
}
