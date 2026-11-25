package agent

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestStatusPanelServedAndGuarded(t *testing.T) {
	a := &Agent{chatQuiet: true}
	a.tray.State, a.tray.ChatToken, a.tray.AllowSupport, a.tray.Org = "connected", "tok123", true, "Acme"
	t.Setenv("TMPDIR", t.TempDir())
	mux := http.NewServeMux()
	a.chatRoutes(mux, "127.0.0.1:1")
	get := func(path, host string) *httptest.ResponseRecorder {
		r := httptest.NewRequest("GET", path, nil)
		r.Host = host
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, r)
		return w
	}
	if w := get("/panel/tok123/", "127.0.0.1:1"); w.Code != 200 || !strings.Contains(w.Body.String(), "Request support") {
		t.Fatalf("panel page: %d", w.Code)
	}
	if w := get("/panel/wrong/s", "127.0.0.1:1"); w.Code != 404 {
		t.Fatalf("bad token allowed: %d", w.Code)
	}
	if w := get("/panel/tok123/s", "evil.example"); w.Code != 404 {
		t.Fatalf("bad host allowed: %d", w.Code)
	}
	w := get("/panel/tok123/s", "127.0.0.1:1")
	if w.Code != 200 || !strings.Contains(w.Body.String(), "Connected and protected") || !strings.Contains(w.Body.String(), "Acme") {
		t.Fatalf("status: %d %s", w.Code, w.Body.String())
	}
	r := httptest.NewRequest("POST", "/panel/tok123/support", nil)
	r.Host = "127.0.0.1:1"
	pw := httptest.NewRecorder()
	mux.ServeHTTP(pw, r)
	if pw.Code != 403 {
		t.Fatalf("support without the custom header: %d", pw.Code)
	}
}
