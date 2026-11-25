// Package agent implements the Helm agent that runs on managed PCs.
package agent

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"helm/internal/proto"
	"helm/internal/ws"
)

// Consent modes (see docs): how a remote screen session may start.
const (
	ConsentPromptIfPresent = "prompt_if_present"
	ConsentAlwaysPrompt    = "always_prompt"
	ConsentUnattended      = "unattended"
)

// Config is the agent configuration.
type Config struct {
	Server        string // https://host
	EnrollToken   string
	ConsentMode   string
	DataDir       string
	Version       string
	AllowInsecure bool   // permit http:// / ws:// servers (development only)
	UpdatePubKey  []byte // ed25519 public key; empty disables self-update
	ExePath       string // path of the running executable
	TLS           *tls.Config
}

type creds struct {
	Server   string `json:"server"`
	DeviceID string `json:"deviceId"`
	Secret   string `json:"secret"`
}

// Agent is the running agent.
type Agent struct {
	cfg  Config
	log  *log.Logger
	mu   sync.Mutex
	conn *ws.Conn
	cr   *creds

	stMu sync.Mutex
	tray TrayStatus

	chatMu   sync.Mutex
	chat     []chatLine
	chatLast time.Time // last message sent from this PC, for rate limiting

	cmdSem   chan struct{}
	updMu    sync.Mutex // serialises Windows Update / winget / self-update operations
	screenMu sync.Mutex // one screen session at a time
}

// New creates an agent.
func New(cfg Config, logger *log.Logger) (*Agent, error) {
	cfg.Server = strings.TrimRight(strings.TrimSpace(cfg.Server), "/")
	if cfg.ConsentMode == "" {
		cfg.ConsentMode = ConsentPromptIfPresent
	}
	switch cfg.ConsentMode {
	case ConsentPromptIfPresent, ConsentAlwaysPrompt, ConsentUnattended:
	default:
		return nil, fmt.Errorf("invalid consent mode %q", cfg.ConsentMode)
	}
	if logger == nil {
		logger = log.New(os.Stderr, "", log.LstdFlags)
	}
	if cfg.DataDir == "" {
		return nil, errors.New("data directory not set")
	}
	return &Agent{cfg: cfg, log: logger, cmdSem: make(chan struct{}, 8)}, nil
}

func (a *Agent) credsPath() string { return filepath.Join(a.cfg.DataDir, "device.json") }

func (a *Agent) loadCreds() *creds {
	b, err := os.ReadFile(a.credsPath())
	if err != nil {
		return nil
	}
	var c creds
	if json.Unmarshal(b, &c) != nil || c.DeviceID == "" || c.Secret == "" {
		return nil
	}
	return &c
}

func (a *Agent) saveCreds(c *creds) error {
	if err := os.MkdirAll(a.cfg.DataDir, 0o700); err != nil {
		return err
	}
	securePath(a.cfg.DataDir)
	b, _ := json.Marshal(c)
	tmp := a.credsPath() + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, a.credsPath())
}

func (a *Agent) checkServerURL() error {
	if a.cfg.Server == "" {
		return errors.New("server URL not configured")
	}
	if strings.HasPrefix(a.cfg.Server, "https://") {
		return nil
	}
	if a.cfg.AllowInsecure && strings.HasPrefix(a.cfg.Server, "http://") {
		return nil
	}
	return errors.New("server URL must start with https://")
}

func (a *Agent) wsURL(path string) string {
	switch {
	case strings.HasPrefix(a.cfg.Server, "https://"):
		return "wss://" + strings.TrimPrefix(a.cfg.Server, "https://") + path
	default:
		return "ws://" + strings.TrimPrefix(a.cfg.Server, "http://") + path
	}
}

func (a *Agent) httpClient() *http.Client {
	tr := &http.Transport{TLSClientConfig: a.cfg.TLS, Proxy: http.ProxyFromEnvironment,
		TLSHandshakeTimeout: 20 * time.Second, ResponseHeaderTimeout: 60 * time.Second}
	return &http.Client{Transport: tr, Timeout: 0}
}

// ---- Run loop ----

// Run connects to the server and serves commands until ctx is cancelled.
func (a *Agent) Run(ctx context.Context) {
	a.log.Printf("helm agent %s starting (server %s)", a.cfg.Version, a.cfg.Server)
	go a.statusLoop(ctx)
	go a.serveControl(ctx)
	go a.trayKeeper(ctx)
	backoff := 3 * time.Second
	for ctx.Err() == nil {
		started := time.Now()
		err := a.session(ctx)
		if ctx.Err() != nil {
			return
		}
		a.setState("offline")
		a.log.Printf("session ended: %v", err)
		var he *ws.HandshakeError
		switch {
		case errors.As(err, &he) && he.Status == http.StatusUnauthorized:
			backoff = 10 * time.Minute // revoked or unknown; wait for an admin
		case time.Since(started) > time.Minute:
			backoff = 3 * time.Second
		default:
			backoff *= 2
			if backoff > 5*time.Minute {
				backoff = 5 * time.Minute
			}
		}
		d := backoff + time.Duration(rand.Int63n(int64(backoff/2)+1))
		select {
		case <-ctx.Done():
			return
		case <-time.After(d):
		}
	}
}

func (a *Agent) enroll(ctx context.Context) error {
	if a.cfg.EnrollToken == "" {
		return errors.New("not enrolled and no enrollment token configured")
	}
	h := a.collectHello()
	body, _ := json.Marshal(proto.EnrollRequest{Token: a.cfg.EnrollToken, Hello: h})
	req, _ := http.NewRequestWithContext(ctx, "POST", a.cfg.Server+"/api/agent/enroll", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err := a.httpClient().Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	if resp.StatusCode != 200 {
		return fmt.Errorf("enrollment refused: HTTP %d %s", resp.StatusCode, strings.TrimSpace(string(b)))
	}
	var er proto.EnrollResponse
	if err := json.Unmarshal(b, &er); err != nil || er.DeviceID == "" || er.Secret == "" {
		return errors.New("bad enrollment response")
	}
	c := &creds{Server: a.cfg.Server, DeviceID: er.DeviceID, Secret: er.Secret}
	if err := a.saveCreds(c); err != nil {
		return fmt.Errorf("cannot store credentials: %w", err)
	}
	a.cr = c
	a.log.Printf("enrolled as device %s (waiting for admin approval)", c.DeviceID)
	consumeEnrollToken() // do not leave the token readable in the registry
	return nil
}

func (a *Agent) authHeader() http.Header {
	h := http.Header{}
	h.Set("X-Helm-Device", a.cr.DeviceID)
	h.Set("Authorization", "Bearer "+a.cr.Secret)
	return h
}

func (a *Agent) session(ctx context.Context) error {
	if err := a.checkServerURL(); err != nil {
		return err
	}
	if a.cr == nil {
		a.cr = a.loadCreds()
	}
	if a.cr != nil && a.cr.Server != a.cfg.Server && a.cfg.EnrollToken != "" {
		a.cr = nil // reinstalled against a different server
	}
	a.setState("connecting")
	if a.cr == nil {
		if err := a.enroll(ctx); err != nil {
			return err
		}
	}
	c, err := ws.Dial(ctx, a.wsURL("/ws/agent"), ws.DialOptions{Header: a.authHeader(), TLSConfig: a.cfg.TLS})
	if err != nil {
		var he *ws.HandshakeError
		if errors.As(err, &he) && he.Status == http.StatusUnauthorized && a.cfg.EnrollToken != "" {
			// Device was removed on the server; try to enrol again with the token (if still valid).
			a.log.Printf("credentials rejected; attempting re-enrolment")
			a.cr = nil
			_ = os.Remove(a.credsPath())
		}
		return err
	}
	c.SetReadLimit(4 << 20)
	c.SetIdleTimeout(90 * time.Second)
	c.KeepAlive(25 * time.Second)
	a.mu.Lock()
	a.conn = c
	a.mu.Unlock()
	defer func() {
		c.Close(ws.CloseNormal, "")
		a.mu.Lock()
		a.conn = nil
		a.mu.Unlock()
	}()
	a.log.Printf("connected to server as %s", a.cr.DeviceID)
	a.setState("pending") // becomes "connected" when the server says the PC is approved

	sctx, cancel := context.WithCancel(ctx)
	defer cancel()
	go func() { // close the connection when ctx is cancelled
		select {
		case <-sctx.Done():
			c.Close(ws.CloseGoingAway, "shutting down")
		case <-c.Done():
		}
	}()
	hello := a.collectHello()
	a.sendFrame(proto.Frame{T: proto.THello, Data: mustJSON(hello)})
	go a.statsLoop(sctx)
	go a.updateLoop(sctx)

	for {
		op, msg, err := c.ReadMessage()
		if err != nil {
			return err
		}
		if op != ws.OpText {
			continue
		}
		var f proto.Frame
		if json.Unmarshal(msg, &f) != nil {
			continue
		}
		switch f.T {
		case proto.TConfig:
			var cfg proto.Config
			if json.Unmarshal(f.Data, &cfg) == nil {
				a.setConfig(cfg)
			}
		case proto.TChat:
			a.chatIncoming(f.ID, f.Msg)
		case proto.TApproved:
			a.log.Printf("approved by administrator")
			a.setState("connected")
		case proto.TRevoked:
			a.log.Printf("revoked by administrator")
		case proto.TCmd:
			a.runCommand(ctx, f)
		case proto.TOpen:
			go a.handleOpen(ctx, f)
		}
	}
}

func (a *Agent) sendFrame(f proto.Frame) {
	a.mu.Lock()
	c := a.conn
	a.mu.Unlock()
	if c == nil {
		return
	}
	b, _ := json.Marshal(f)
	_ = c.WriteMessage(ws.OpText, b)
}

func mustJSON(v any) json.RawMessage {
	b, err := json.Marshal(v)
	if err != nil {
		return nil
	}
	return b
}

func (a *Agent) statsLoop(ctx context.Context) {
	t := time.NewTicker(15 * time.Second)
	defer t.Stop()
	for {
		st := sysStats()
		a.sendFrame(proto.Frame{T: proto.TStats, Data: mustJSON(st)})
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

func (a *Agent) collectHello() proto.Hello {
	host, _ := os.Hostname()
	osv, ed := osInfo()
	user, _ := loggedOnUser()
	macs, ips := netInfo()
	return proto.Hello{Version: a.cfg.Version, Hostname: host, OS: helloOS(), OSVersion: osv, Edition: ed,
		Arch: runtime.GOARCH, User: user, MACs: macs, IPs: ips, ConsentMode: a.cfg.ConsentMode, CanRDP: canHostRDP(ed)}
}

// netInfo lists the MAC and IPv4 addresses of physical-looking interfaces.
func netInfo() (macs, ips []string) {
	ifs, _ := net.Interfaces()
	for _, ifc := range ifs {
		if ifc.Flags&net.FlagUp == 0 || ifc.Flags&net.FlagLoopback != 0 || len(ifc.HardwareAddr) != 6 {
			continue
		}
		n := strings.ToLower(ifc.Name)
		skip := false
		for _, bad := range []string{"vethernet", "virtualbox", "vmware", "hyper-v", "loopback", "bluetooth", "docker", "veth", "tailscale", "wsl"} {
			if strings.Contains(n, bad) {
				skip = true
			}
		}
		if skip {
			continue
		}
		addrs, _ := ifc.Addrs()
		got := false
		for _, ad := range addrs {
			if ipn, ok := ad.(*net.IPNet); ok {
				if v4 := ipn.IP.To4(); v4 != nil && !v4.IsLinkLocalUnicast() {
					ips = append(ips, v4.String())
					got = true
				}
			}
		}
		if got {
			macs = append(macs, ifc.HardwareAddr.String())
		}
	}
	return
}

// helloOS is the platform reported to the console: "linux" on a real Linux host, otherwise "windows"
// (development fixtures stand in for a Windows PC).
func helloOS() string {
	if realLinux() {
		return "linux"
	}
	if realMac() {
		return "darwin"
	}
	return "windows"
}
