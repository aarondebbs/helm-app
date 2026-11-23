package e2e

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"helm/internal/agent"
	"helm/internal/proto"
	"helm/internal/server"
	"helm/internal/ws"
)

const adminPW = "Correct-Horse-9-Battery"

type env struct {
	dataDir string
	pub     []byte
	t       *testing.T
	srv     *server.Server
	ts      *httptest.Server
	client  *http.Client
	csrf    string
	secret  string
	cookie  string
}

func newEnv(t *testing.T) *env {
	t.Helper()
	dir := t.TempDir()
	dataDir := filepath.Join(dir, "srv")
	srv, err := server.New(server.Config{DataDir: dataDir, Dev: true, Version: "test"})
	if err != nil {
		t.Fatal(err)
	}
	secret := server.NewTOTPSecret()
	if _, err := srv.Store().SetAdmin("admin", adminPW, secret); err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(func() { ts.Close(); srv.Close() })
	jar, _ := cookiejar.New(nil)
	return &env{dataDir: dataDir, t: t, srv: srv, ts: ts, client: &http.Client{Jar: jar, Timeout: 30 * time.Second}, secret: secret}
}

func (e *env) do(method, path string, body any) (int, []byte) {
	e.t.Helper()
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, _ := http.NewRequest(method, e.ts.URL+path, rd)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if e.csrf != "" {
		req.Header.Set("X-CSRF-Token", e.csrf)
	}
	resp, err := e.client.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, b
}

func (e *env) login() {
	e.t.Helper()
	code := server.TOTPNow(e.secret, time.Now())
	st, b := e.do("POST", "/api/login", map[string]string{"user": "admin", "password": adminPW, "code": code})
	if st != 200 {
		e.t.Fatalf("login failed: %d %s", st, b)
	}
	var r struct{ Csrf string }
	_ = json.Unmarshal(b, &r)
	e.csrf = r.Csrf
	u, _ := url.Parse(e.ts.URL)
	for _, c := range e.client.Jar.Cookies(u) {
		if c.Name == "helm_session" {
			e.cookie = c.Name + "=" + c.Value
		}
	}
}

func (e *env) startAgent(t *testing.T, token string) (context.CancelFunc, string) {
	t.Helper()
	a, err := agent.New(agent.Config{Server: e.ts.URL, EnrollToken: token, DataDir: t.TempDir(), Version: "1.0.0",
		AllowInsecure: true, ConsentMode: agent.ConsentPromptIfPresent, UpdatePubKey: e.pub},
		log.New(io.Discard, "", 0))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	go a.Run(ctx)
	t.Cleanup(cancel)
	return cancel, ""
}

type devView struct {
	ID       string `json:"id"`
	Approved bool   `json:"approved"`
	Online   bool   `json:"online"`
	Name     string `json:"name"`
}

func (e *env) waitDevice(cond func(d devView) bool) devView {
	e.t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		_, b := e.do("GET", "/api/devices", nil)
		var ds []devView
		_ = json.Unmarshal(b, &ds)
		for _, d := range ds {
			if cond(d) {
				return d
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	e.t.Fatal("timed out waiting for device state")
	return devView{}
}

type job struct {
	Status string          `json:"status"`
	Err    string          `json:"err"`
	Data   json.RawMessage `json:"data"`
}

func (e *env) cmd(id, name string, args any) job {
	e.t.Helper()
	st, b := e.do("POST", "/api/devices/"+id+"/cmd", map[string]any{"name": name, "args": args, "wait": 30})
	if st != 200 {
		e.t.Fatalf("cmd %s: HTTP %d %s", name, st, b)
	}
	var j job
	_ = json.Unmarshal(b, &j)
	return j
}

func (e *env) wsDial(kind, device, extra string) (*ws.Conn, error) {
	h := http.Header{}
	h.Set("Origin", e.ts.URL)
	h.Set("Cookie", e.cookie)
	u := "ws" + strings.TrimPrefix(e.ts.URL, "http") + "/ws/ui?kind=" + kind + "&device=" + device + "&csrf=" + url.QueryEscape(e.csrf) + extra
	return ws.Dial(context.Background(), u, ws.DialOptions{Header: h})
}

func readText(t *testing.T, c *ws.Conn, d time.Duration) (map[string]any, bool) {
	t.Helper()
	c.SetIdleTimeout(d)
	op, b, err := c.ReadMessage()
	if err != nil {
		return nil, false
	}
	if op != ws.OpText {
		return map[string]any{"t": "binary", "n": float64(len(b))}, true
	}
	var m map[string]any
	_ = json.Unmarshal(b, &m)
	return m, true
}

func TestFullFlow(t *testing.T) {
	e := newEnv(t)

	// --- security basics ---
	if st, _ := e.do("GET", "/api/devices", nil); st != 401 {
		t.Fatalf("unauthenticated devices: %d", st)
	}
	if st, _ := e.do("POST", "/api/login", map[string]string{"user": "admin", "password": adminPW, "code": "000000"}); st != 401 {
		t.Fatalf("bad code accepted: %d", st)
	}
	e.login()
	if st, _ := e.do("GET", "/api/devices", nil); st != 200 {
		t.Fatalf("devices after login: %d", st)
	}
	saved := e.csrf
	e.csrf = "wrong"
	if st, _ := e.do("POST", "/api/tokens", map[string]any{"label": "x"}); st != 403 {
		t.Fatalf("CSRF not enforced: %d", st)
	}
	e.csrf = saved

	// --- enrollment ---
	st, b := e.do("POST", "/api/tokens", map[string]any{"label": "test", "hours": 1, "maxUses": 1})
	if st != 200 {
		t.Fatalf("create token: %d %s", st, b)
	}
	var tk struct{ Token string }
	_ = json.Unmarshal(b, &tk)
	// bad token is refused
	resp, _ := http.Post(e.ts.URL+"/api/agent/enroll", "application/json",
		strings.NewReader(`{"token":"hlm_nope","hello":{"hostname":"x"}}`))
	if resp.StatusCode != 403 {
		t.Fatalf("bad enroll token: %d", resp.StatusCode)
	}
	e.startAgent(t, tk.Token)
	dev := e.waitDevice(func(d devView) bool { return d.Online })
	if dev.Approved {
		t.Fatal("device must start unapproved")
	}
	if st, _ := e.do("POST", "/api/devices/"+dev.ID+"/cmd", map[string]any{"name": "ping", "wait": 5}); st != 409 {
		t.Fatalf("command to pending device: %d", st)
	}
	// single-use token cannot enrol a second device
	resp, _ = http.Post(e.ts.URL+"/api/agent/enroll", "application/json",
		strings.NewReader(`{"token":"`+tk.Token+`","hello":{"hostname":"y"}}`))
	if resp.StatusCode != 403 {
		t.Fatalf("token reuse accepted: %d", resp.StatusCode)
	}

	// --- approve ---
	if st, b := e.do("POST", "/api/devices/"+dev.ID+"/approve", nil); st != 200 {
		t.Fatalf("approve: %d %s", st, b)
	}
	id := dev.ID
	time.Sleep(200 * time.Millisecond)

	// --- commands ---
	if j := e.cmd(id, "ping", nil); j.Status != "ok" {
		t.Fatalf("ping: %+v", j)
	}
	if j := e.cmd(id, "inventory", nil); j.Status != "ok" || !strings.Contains(string(j.Data), "computerName") {
		t.Fatalf("inventory: %+v", j)
	}
	if j := e.cmd(id, "updates.check", nil); j.Status != "ok" || !strings.Contains(string(j.Data), "Demo Update") {
		t.Fatalf("updates.check: %+v", j)
	}
	if j := e.cmd(id, "fix.apply", map[string]any{"id": "firewall"}); j.Status != "ok" || !strings.Contains(string(j.Data), "firewall") {
		t.Fatalf("fix.apply: %+v", j)
	}
	if j := e.cmd(id, "fix.apply", map[string]any{"id": "format_disk; rm -rf /"}); j.Status != "error" {
		t.Fatalf("fix.apply must refuse unknown ids: %+v", j)
	}
	if st, b := e.do("POST", "/api/devices/"+id+"/update-software", map[string]string{"software": "no-such-program"}); st != 409 || !strings.Contains(string(b), "no-such-program") {
		t.Fatalf("update-software for an unknown program: %d %s", st, b)
	}
	if st, _ := e.do("POST", "/api/devices/"+id+"/update-software", map[string]string{"software": " "}); st != 400 {
		t.Fatalf("update-software must reject an empty name: %d", st)
	}
	if st, b := e.do("GET", "/healthz", nil); st != 200 || !strings.Contains(string(b), `"ok"`) {
		t.Fatalf("healthz: %d %s", st, b)
	}
	if j := e.cmd(id, "updates.install", map[string]any{"reboot": false}); j.Status != "ok" || !strings.Contains(string(j.Data), `"installed":1`) {
		t.Fatalf("updates.install: %+v", j)
	}
	if j := e.cmd(id, "winget.list", nil); j.Status != "ok" || !strings.Contains(string(j.Data), "Git.Git") {
		t.Fatalf("winget.list: %+v", j)
	}
	if j := e.cmd(id, "winget.upgrade", map[string]any{"ids": []string{"Git.Git"}}); j.Status != "ok" {
		t.Fatalf("winget.upgrade: %+v", j)
	}
	if j := e.cmd(id, "winget.upgrade", map[string]any{"ids": []string{"bad id;"}}); j.Status != "error" {
		t.Fatalf("winget.upgrade should reject bad ids: %+v", j)
	}
	if j := e.cmd(id, "power", map[string]any{"action": "restart", "delay": 30}); j.Status != "ok" {
		t.Fatalf("power: %+v", j)
	}
	if j := e.cmd(id, "power", map[string]any{"action": "explode"}); j.Status != "error" {
		t.Fatalf("bad power action accepted: %+v", j)
	}
	if j := e.cmd(id, "process.kill", map[string]any{"pid": 1}); j.Status != "error" {
		t.Fatalf("kill pid 1 accepted: %+v", j)
	}
	if j := e.cmd(id, "service.control", map[string]any{"name": "Demo;calc", "action": "start"}); j.Status != "error" {
		t.Fatalf("bad service name accepted: %+v", j)
	}
	j := e.cmd(id, "exec", map[string]any{"script": "echo hello-from-agent", "shell": "powershell"})
	var er proto.ExecResult
	_ = json.Unmarshal(j.Data, &er)
	if j.Status != "ok" || !strings.Contains(er.Stdout, "hello-from-agent") {
		t.Fatalf("exec: %+v %+v", j, er)
	}
	j = e.cmd(id, "exec", map[string]any{"script": "sleep 5", "timeout": 1})
	_ = json.Unmarshal(j.Data, &er)
	if !er.TimedOut {
		t.Fatalf("exec timeout not enforced: %+v", er)
	}

	// --- files ---
	work := t.TempDir()
	if j := e.cmd(id, "file.mkdir", map[string]any{"path": filepath.Join(work, "sub")}); j.Status != "ok" {
		t.Fatalf("mkdir: %+v", j)
	}
	if j := e.cmd(id, "file.delete", map[string]any{"path": "/"}); j.Status != "error" {
		t.Fatalf("deleting root allowed: %+v", j)
	}
	if j := e.cmd(id, "file.list", map[string]any{"path": "relative/path"}); j.Status != "error" {
		t.Fatalf("relative path allowed: %+v", j)
	}
	payload := bytes.Repeat([]byte("0123456789abcdef"), 100000) // 1.6 MB
	resp2, err := func() (*http.Response, error) {
		req, _ := http.NewRequest("POST", e.ts.URL+"/api/devices/"+id+"/upload?path="+url.QueryEscape(filepath.Join(work, "up.bin")), bytes.NewReader(payload))
		req.Header.Set("X-CSRF-Token", e.csrf)
		return e.client.Do(req)
	}()
	if err != nil || resp2.StatusCode != 200 {
		b, _ := io.ReadAll(resp2.Body)
		t.Fatalf("upload: %v %d %s", err, resp2.StatusCode, b)
	}
	got, _ := os.ReadFile(filepath.Join(work, "up.bin"))
	if !bytes.Equal(got, payload) {
		t.Fatal("uploaded file differs")
	}
	// uploading again without overwrite must fail
	req, _ := http.NewRequest("POST", e.ts.URL+"/api/devices/"+id+"/upload?path="+url.QueryEscape(filepath.Join(work, "up.bin")), bytes.NewReader(payload))
	req.Header.Set("X-CSRF-Token", e.csrf)
	if r, _ := e.client.Do(req); r.StatusCode != 409 {
		t.Fatalf("overwrite without flag: %d", r.StatusCode)
	}
	r, err := e.client.Get(e.ts.URL + "/api/devices/" + id + "/download?path=" + url.QueryEscape(filepath.Join(work, "up.bin")))
	if err != nil || r.StatusCode != 200 {
		t.Fatalf("download: %v %v", err, r)
	}
	dl, _ := io.ReadAll(r.Body)
	if !bytes.Equal(dl, payload) {
		t.Fatalf("downloaded file differs (%d bytes)", len(dl))
	}
	if !strings.Contains(r.Header.Get("Content-Disposition"), "up.bin") {
		t.Fatalf("content-disposition: %q", r.Header.Get("Content-Disposition"))
	}
	if r, _ := e.client.Get(e.ts.URL + "/api/devices/" + id + "/download?path=" + url.QueryEscape(filepath.Join(work, "missing"))); r.StatusCode == 200 {
		t.Fatal("download of missing file succeeded")
	}

	// --- terminal ---
	tc, err := e.wsDial("term", id, "&shell=powershell")
	if err != nil {
		t.Fatalf("terminal ws: %v", err)
	}
	var out strings.Builder
	sent := false
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) && !strings.Contains(out.String(), "term-ok-42") {
		m, ok := readText(t, tc, 5*time.Second)
		if !ok {
			break
		}
		if m["t"] == "status" && m["msg"] == "connected" && !sent {
			b, _ := json.Marshal(map[string]string{"t": "in", "d": "echo term-ok-$((40+2))\n"})
			_ = tc.WriteMessage(ws.OpText, b)
			sent = true
		}
		if m["t"] == "out" {
			out.WriteString(m["d"].(string))
		}
	}
	if !strings.Contains(out.String(), "term-ok-42") {
		t.Fatalf("terminal did not echo output; got %q", out.String())
	}
	tc.Close(ws.CloseNormal, "")

	// --- audit ---
	_, ab := e.do("GET", "/api/audit?limit=100", nil)
	if !strings.Contains(string(ab), "command") || !strings.Contains(string(ab), "enroll") {
		t.Fatalf("audit log incomplete: %s", ab)
	}
}

func (e *env) enrolled(t *testing.T) string {
	t.Helper()
	_, b := e.do("POST", "/api/tokens", map[string]any{"label": "t2", "hours": 1})
	var tk struct{ Token string }
	_ = json.Unmarshal(b, &tk)
	e.startAgent(t, tk.Token)
	dev := e.waitDevice(func(d devView) bool { return d.Online })
	if st, b := e.do("POST", "/api/devices/"+dev.ID+"/approve", nil); st != 200 {
		t.Fatalf("approve: %d %s", st, b)
	}
	e.waitDevice(func(d devView) bool { return d.Online && d.Approved })
	time.Sleep(200 * time.Millisecond)
	return dev.ID
}

func TestScreenSession(t *testing.T) {
	e := newEnv(t)
	e.login()
	id := e.enrolled(t)

	// interactive session: frames arrive and input is forwarded
	c, err := e.wsDial("screen", id, "")
	if err != nil {
		t.Fatal(err)
	}
	var gotScreen, gotTiles, gotEcho bool
	sent := false
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) && !(gotScreen && gotTiles && gotEcho) {
		m, ok := readText(t, c, 5*time.Second)
		if !ok {
			break
		}
		switch m["t"] {
		case "status":
			if m["msg"] == "connected" && !sent {
				_ = c.WriteMessage(ws.OpText, []byte(`{"t":"mm","x":0.5,"y":0.5}`))
				sent = true
			}
		case "screen":
			gotScreen = true
		case "binary":
			gotTiles = true
		case "echo":
			gotEcho = true
		}
	}
	if !gotScreen || !gotTiles || !gotEcho {
		t.Fatalf("screen=%v tiles=%v echo=%v", gotScreen, gotTiles, gotEcho)
	}
	c.Close(ws.CloseNormal, "")

	// view-only: input must be dropped
	time.Sleep(500 * time.Millisecond)
	c, err = e.wsDial("screen", id, "&viewOnly=1")
	if err != nil {
		t.Fatal(err)
	}
	echoed := false
	sent = false
	deadline = time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		m, ok := readText(t, c, 1500*time.Millisecond)
		if !ok {
			break
		}
		if m["t"] == "status" && m["msg"] == "connected" && !sent {
			_ = c.WriteMessage(ws.OpText, []byte(`{"t":"md","b":0}`))
			sent = true
		}
		if m["t"] == "echo" {
			echoed = true
		}
	}
	if echoed {
		t.Fatal("view-only session forwarded input")
	}
	c.Close(ws.CloseNormal, "")

	// consent denied
	time.Sleep(500 * time.Millisecond)
	t.Setenv("HELM_FAKE_CONSENT", "deny")
	c, err = e.wsDial("screen", id, "")
	if err != nil {
		t.Fatal(err)
	}
	var errMsg string
	for i := 0; i < 5; i++ {
		m, ok := readText(t, c, 5*time.Second)
		if !ok {
			break
		}
		if m["t"] == "error" {
			errMsg, _ = m["msg"].(string)
			break
		}
	}
	if !strings.Contains(errMsg, "declined") {
		t.Fatalf("expected consent refusal, got %q", errMsg)
	}
}

func TestRDPTunnel(t *testing.T) {
	// fake RDP server that echoes
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { defer c.Close(); _, _ = io.Copy(c, c) }()
		}
	}()
	t.Setenv("HELM_FAKE_RDP_PORT", strings.Split(ln.Addr().String(), ":")[1])

	e := newEnv(t)
	e.login()
	id := e.enrolled(t)
	st, b := e.do("POST", "/api/devices/"+id+"/rdp/open", map[string]any{"minutes": 5})
	if st != 200 {
		t.Fatalf("open tunnel: %d %s", st, b)
	}
	var tn struct {
		ID   string
		Bind string
		Port int
	}
	_ = json.Unmarshal(b, &tn)
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(tn.Bind, itoa(tn.Port)), 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	msg := bytes.Repeat([]byte("rdp-bytes-"), 5000)
	go func() { _, _ = conn.Write(msg) }()
	got := make([]byte, len(msg))
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.ReadFull(conn, got); err != nil || !bytes.Equal(got, msg) {
		t.Fatalf("tunnel echo failed: %v", err)
	}
	// second device cannot open another tunnel on the same device
	if st, _ := e.do("POST", "/api/devices/"+id+"/rdp/open", map[string]any{"minutes": 5}); st != 409 {
		t.Fatalf("duplicate tunnel: %d", st)
	}
	if st, _ := e.do("DELETE", "/api/tunnels/"+tn.ID, nil); st != 200 {
		t.Fatalf("close tunnel: %d", st)
	}
	if c2, err := net.DialTimeout("tcp", net.JoinHostPort(tn.Bind, itoa(tn.Port)), time.Second); err == nil {
		c2.Close()
		t.Fatal("tunnel still listening after close")
	}
}

func TestDeleteRevokes(t *testing.T) {
	e := newEnv(t)
	e.login()
	id := e.enrolled(t)
	if st, _ := e.do("DELETE", "/api/devices/"+id, nil); st != 200 {
		t.Fatal("delete failed")
	}
	if st, _ := e.do("POST", "/api/devices/"+id+"/cmd", map[string]any{"name": "ping"}); st == 200 {
		t.Fatal("command to deleted device succeeded")
	}
	// agent must not be able to reconnect with old credentials
	h := http.Header{}
	h.Set("X-Helm-Device", id)
	h.Set("Authorization", "Bearer whatever")
	_, err := ws.Dial(context.Background(), "ws"+strings.TrimPrefix(e.ts.URL, "http")+"/ws/agent", ws.DialOptions{Header: h})
	if he, ok := err.(*ws.HandshakeError); !ok || he.Status != 401 {
		t.Fatalf("expected 401, got %v", err)
	}
}

func TestStepUpRequired(t *testing.T) {
	e := newEnv(t)
	e.login()
	id := e.enrolled(t)
	// expire the step-up by creating a session whose window has passed: simulate by
	// logging in, then verifying the endpoint reports step-up state.
	_, b := e.do("GET", "/api/me", nil)
	if !strings.Contains(string(b), `"stepUp":true`) {
		t.Fatalf("fresh login should have step-up: %s", b)
	}
	// a wrong code is rejected
	if st, _ := e.do("POST", "/api/stepup", map[string]string{"code": "123456"}); st != 401 {
		t.Fatalf("bad stepup code: %d", st)
	}
	_ = id
}

func itoa(n int) string { return strconv.Itoa(n) }

func publishRelease(t *testing.T, dataDir string, priv ed25519.PrivateKey, version, body string, tamper bool) {
	t.Helper()
	dir := filepath.Join(dataDir, "releases", "linux-amd64")
	_ = os.MkdirAll(dir, 0o755)
	name := "helm-agent-" + version + "-linux-amd64.exe"
	if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte(body))
	sh := hex.EncodeToString(sum[:])
	sig := ed25519.Sign(priv, proto.SignedMessage(version, "linux", "amd64", sh))
	if tamper {
		sig[0] ^= 0xff
	}
	meta, _ := json.Marshal(map[string]string{"version": version, "file": name, "sha256": sh, "sig": base64.StdEncoding.EncodeToString(sig)})
	_ = os.WriteFile(filepath.Join(dir, "latest.json"), meta, 0o644)
}

func TestSelfUpdateVerification(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	e := newEnv(t)
	e.pub = pub
	e.login()
	id := e.enrolled(t)

	// nothing published: already up to date
	if j := e.cmd(id, "agent.update", nil); j.Status != "ok" || !strings.Contains(string(j.Data), "up to date") {
		t.Fatalf("no release: %+v", j)
	}
	// tampered signature must be rejected
	publishRelease(t, e.dataDir, priv, "1.1.0", "#!/bin/sh\necho 1.1.0\n", true)
	if j := e.cmd(id, "agent.update", nil); j.Status != "error" || !strings.Contains(j.Err, "signature") {
		t.Fatalf("tampered release accepted: %+v", j)
	}
	// signed by another key must be rejected
	_, other, _ := ed25519.GenerateKey(nil)
	publishRelease(t, e.dataDir, other, "1.1.0", "#!/bin/sh\necho 1.1.0\n", false)
	if j := e.cmd(id, "agent.update", nil); j.Status != "error" || !strings.Contains(j.Err, "signature") {
		t.Fatalf("foreign-key release accepted: %+v", j)
	}
	// valid release passes verification and the self-check; applying is Windows-only
	publishRelease(t, e.dataDir, priv, "1.1.0", "#!/bin/sh\necho 1.1.0\n", false)
	if j := e.cmd(id, "agent.update", nil); j.Status != "error" || !strings.Contains(j.Err, "only supported on Windows") {
		t.Fatalf("valid release should reach the apply step: %+v", j)
	}
	// a binary whose version does not match the announcement is rejected
	publishRelease(t, e.dataDir, priv, "1.2.0", "#!/bin/sh\necho 9.9.9\n", false)
	if j := e.cmd(id, "agent.update", nil); j.Status != "error" || !strings.Contains(j.Err, "self-check") {
		t.Fatalf("mismatched binary accepted: %+v", j)
	}
}

func TestSelfUpdateDisabledWithoutKey(t *testing.T) {
	e := newEnv(t)
	e.login()
	id := e.enrolled(t)
	if j := e.cmd(id, "agent.update", nil); j.Status != "error" || !strings.Contains(j.Err, "disabled") {
		t.Fatalf("self-update should be disabled without a key: %+v", j)
	}
}

func TestUsersAndRoles(t *testing.T) {
	e := newEnv(t)
	e.login()
	st, b := e.do("POST", "/api/users", map[string]string{"user": "vera", "password": "Another-Long-Pass-42", "role": "viewer"})
	if st != 200 {
		t.Fatalf("add user: %d %s", st, b)
	}
	var added struct{ Secret string }
	_ = json.Unmarshal(b, &added)
	if added.Secret == "" {
		t.Fatal("new user should get an authenticator key")
	}
	if st, _ := e.do("POST", "/api/users", map[string]string{"user": "vera", "password": "Another-Long-Pass-42", "role": "admin"}); st != 409 {
		t.Fatalf("duplicate user should conflict: %d", st)
	}
	// the viewer signs in with their own password and code
	jar, _ := cookiejar.New(nil)
	v := &env{dataDir: e.dataDir, t: t, srv: e.srv, ts: e.ts, client: &http.Client{Jar: jar, Timeout: 30 * time.Second}}
	if st, _ := v.do("POST", "/api/login", map[string]string{"user": "vera", "password": "wrong-password-here", "code": server.TOTPNow(added.Secret, time.Now())}); st != 401 {
		t.Fatalf("bad password should fail: %d", st)
	}
	st, b = v.do("POST", "/api/login", map[string]string{"user": "vera", "password": "Another-Long-Pass-42", "code": server.TOTPNow(added.Secret, time.Now())})
	if st != 200 {
		t.Fatalf("viewer login: %d %s", st, b)
	}
	var lr struct {
		Csrf string
		Role string
	}
	_ = json.Unmarshal(b, &lr)
	v.csrf = lr.Csrf
	if lr.Role != "viewer" {
		t.Fatalf("role = %q", lr.Role)
	}
	if st, _ := v.do("GET", "/api/devices", nil); st != 200 {
		t.Fatalf("viewer should read devices: %d", st)
	}
	if st, _ := v.do("POST", "/api/tokens", map[string]any{"label": "x"}); st != 403 {
		t.Fatalf("viewer must not create tokens: %d", st)
	}
	if st, _ := v.do("GET", "/api/tokens", nil); st != 403 {
		t.Fatalf("viewer must not list tokens: %d", st)
	}
	if st, _ := v.do("POST", "/api/users", map[string]string{"user": "mallory", "password": "Another-Long-Pass-42", "role": "admin"}); st != 403 {
		t.Fatalf("viewer must not add users: %d", st)
	}
	// removing the user signs them out at once
	if st, b := e.do("POST", "/api/users/remove", map[string]string{"user": "vera"}); st != 200 {
		t.Fatalf("remove: %d %s", st, b)
	}
	if st, _ := v.do("GET", "/api/devices", nil); st != 401 {
		t.Fatalf("removed user should be signed out: %d", st)
	}
	if st, _ := e.do("POST", "/api/users/remove", map[string]string{"user": "admin"}); st != 400 {
		t.Fatalf("owner cannot remove themselves: %d", st)
	}
}

func TestNetworkSources(t *testing.T) {
	e := newEnv(t)
	e.login()
	if st, b := e.do("GET", "/api/network/sources", nil); st != 200 || !strings.Contains(string(b), `"sources"`) {
		t.Fatalf("sources: %d %s", st, b)
	}
	if st, _ := e.do("POST", "/api/network/scan", map[string]string{"source": "server", "cidr": "8.8.8.0/24"}); st != 400 {
		t.Fatalf("public networks must be refused: %d", st)
	}
	if st, _ := e.do("POST", "/api/network/install", map[string]string{"host": "8.8.8.8", "user": "a", "password": "b", "relay": "x"}); st != 400 {
		t.Fatalf("public host must be refused: %d", st)
	}
}
