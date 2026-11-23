package e2e

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"helm/internal/server"
)

// A fake Google token endpoint that returns an ID token built from whatever the test asks for.
func fakeGoogle(t *testing.T, claims func(r *http.Request) map[string]any) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		if r.Form.Get("code") != "good-code" || r.Form.Get("code_verifier") == "" || r.Form.Get("client_secret") != "shh-secret" {
			http.Error(w, `{"error":"invalid_grant"}`, 400)
			return
		}
		b, _ := json.Marshal(claims(r))
		tok := "e30." + base64.RawURLEncoding.EncodeToString(b) + ".sig"
		_ = json.NewEncoder(w).Encode(map[string]string{"id_token": tok})
	}))
}

func TestGoogleSignIn(t *testing.T) {
	var nonce string
	override := map[string]any{}
	g := fakeGoogle(t, func(r *http.Request) map[string]any {
		c := map[string]any{"iss": "https://accounts.google.com", "aud": "client-123456.apps.googleusercontent.com", "exp": time.Now().Add(time.Hour).Unix(),
			"nonce": nonce, "email": "Me@Gmail.com", "email_verified": true}
		for k, v := range override {
			c[k] = v
		}
		return c
	})
	defer g.Close()

	dir := t.TempDir()
	srv, err := server.New(server.Config{DataDir: dir, Dev: true, Version: "test", GoogleTokenURL: g.URL})
	if err != nil {
		t.Fatal(err)
	}
	secret := server.NewTOTPSecret()
	if _, err := srv.Store().SetAdmin("admin", adminPW, secret); err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(srv.Handler())
	defer func() { ts.Close(); srv.Close() }()
	jar, _ := cookiejar.New(nil)
	e := &env{dataDir: dir, t: t, srv: srv, ts: ts, client: &http.Client{Jar: jar, Timeout: 30 * time.Second}, secret: secret}
	e.login()

	// not configured: the login page offers no Google button and the flow refuses
	if _, b := e.do("GET", "/api/auth/config", nil); strings.Contains(string(b), `"google":true`) {
		t.Fatalf("google must be off by default: %s", b)
	}
	code := server.TOTPNow(e.secret, time.Now().Add(30*time.Second))
	if st, b := e.do("POST", "/api/stepup", map[string]string{"code": code}); st != 200 {
		t.Fatalf("stepup: %d %s", st, b)
	}
	if st := e.json("PUT", "/api/settings/google", map[string]string{"clientId": "bad id!"}, nil); st != 400 {
		t.Errorf("bad client id accepted: %d", st)
	}
	var gv struct {
		SecretSet   bool
		Enabled     bool
		RedirectUri string
	}
	if st := e.json("PUT", "/api/settings/google", map[string]string{"clientId": "client-123456.apps.googleusercontent.com", "clientSecret": "shh-secret", "email": "me@gmail.com"}, &gv); st != 200 || !gv.SecretSet || !gv.Enabled {
		t.Fatalf("configure google: %d %+v", st, gv)
	}
	if _, raw := e.do("GET", "/api/settings/google", nil); strings.Contains(string(raw), "shh-secret") {
		t.Fatal("client secret must never be returned")
	}
	if !strings.HasSuffix(gv.RedirectUri, "/api/auth/google/callback") {
		t.Errorf("redirect uri: %s", gv.RedirectUri)
	}
	if _, b := e.do("GET", "/api/auth/config", nil); !strings.Contains(string(b), `"google":true`) {
		t.Errorf("login page should offer google now: %s", b)
	}

	// a fresh browser (no session) runs the flow
	noRedirect := func() *http.Client {
		j, _ := cookiejar.New(nil)
		return &http.Client{Jar: j, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	}
	start := func(c *http.Client) (loc *url.URL, state string) {
		resp, err := c.Get(ts.URL + "/api/auth/google/start")
		if err != nil || resp.StatusCode != 302 {
			t.Fatalf("start: %v %v", err, resp)
		}
		l, _ := url.Parse(resp.Header.Get("Location"))
		return l, l.Query().Get("state")
	}
	cb := func(c *http.Client, state, code string) *http.Response {
		resp, err := c.Get(fmt.Sprintf("%s/api/auth/google/callback?state=%s&code=%s", ts.URL, url.QueryEscape(state), code))
		if err != nil {
			t.Fatal(err)
		}
		return resp
	}
	loc, state := start(noRedirect())
	q := loc.Query()
	if loc.Host != "accounts.google.com" || q.Get("code_challenge_method") != "S256" || q.Get("code_challenge") == "" || q.Get("client_id") == "" || q.Get("scope") != "openid email" {
		t.Fatalf("authorization request: %s", loc)
	}
	nonce = q.Get("nonce")

	// happy path
	c1 := noRedirect()
	resp := cb(c1, state, "good-code")
	if resp.StatusCode != 302 || resp.Header.Get("Location") != "/" {
		t.Fatalf("callback: %d %s", resp.StatusCode, resp.Header.Get("Location"))
	}
	cu, _ := url.Parse(ts.URL)
	c1.Jar.SetCookies(cu, resp.Cookies())
	r2, _ := c1.Get(ts.URL + "/api/me")
	if r2.StatusCode != 200 {
		t.Errorf("session after google sign-in: %d", r2.StatusCode)
	}
	var me struct {
		Csrf   string
		StepUp bool
	}
	_ = json.NewDecoder(r2.Body).Decode(&me)
	if me.StepUp {
		t.Error("a Google sign-in must not carry a step-up window")
	}
	rq, _ := http.NewRequest("PUT", ts.URL+"/api/settings/google", strings.NewReader(`{"clear":true}`))
	rq.Header.Set("X-CSRF-Token", me.Csrf)
	rq.Header.Set("Content-Type", "application/json")
	if r3, err := c1.Do(rq); err != nil || r3.StatusCode != 428 {
		t.Errorf("sensitive change after Google sign-in must need the authenticator code: %v %v", err, r3)
	}
	// the state is single-use
	if r := cb(noRedirect(), state, "good-code"); !strings.Contains(r.Header.Get("Location"), "sso_error") {
		t.Errorf("replayed state accepted: %s", r.Header.Get("Location"))
	}
	// failures: wrong address, unverified, expired, wrong audience, wrong nonce, bad code
	for name, ov := range map[string]map[string]any{
		"other account": {"email": "someone@gmail.com"},
		"unverified":    {"email_verified": false},
		"expired":       {"exp": time.Now().Add(-time.Hour).Unix()},
		"wrong client":  {"aud": "another-client"},
		"wrong issuer":  {"iss": "https://evil.example"},
		"wrong nonce":   {"nonce": "nope"},
	} {
		override = ov
		l, st := start(noRedirect())
		nonce = l.Query().Get("nonce")
		r := cb(noRedirect(), st, "good-code")
		if !strings.Contains(r.Header.Get("Location"), "sso_error") || len(r.Cookies()) != 0 {
			t.Errorf("%s was let in: %s cookies=%d", name, r.Header.Get("Location"), len(r.Cookies()))
		}
	}
	override = map[string]any{}
	l, st := start(noRedirect())
	nonce = l.Query().Get("nonce")
	if r := cb(noRedirect(), st, "bad-code"); !strings.Contains(r.Header.Get("Location"), "sso_error") {
		t.Errorf("bad code accepted")
	}
	// clearing turns it off again
	if st := e.json("PUT", "/api/settings/google", map[string]any{"clear": true}, &gv); st != 200 || gv.Enabled {
		t.Errorf("clear: %d %+v", st, gv)
	}
	if r, _ := noRedirect().Get(ts.URL + "/api/auth/google/start"); !strings.Contains(r.Header.Get("Location"), "sso_error") {
		t.Errorf("start must refuse when off")
	}
}
