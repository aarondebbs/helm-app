package agent

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func chatTestAgent(t *testing.T) (*Agent, http.Handler, string) {
	t.Helper()
	t.Setenv("TMPDIR", t.TempDir())
	a := &Agent{chatQuiet: true}
	a.tray.State, a.tray.ChatToken = "connected", "tok123"
	a.tray.AllowSupport = true
	mux := http.NewServeMux()
	a.chatRoutes(mux, "127.0.0.1:5555")
	return a, mux, "/chat/tok123"
}

func do(h http.Handler, method, path, host, body string, hdr map[string]string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	r.Host = host
	for k, v := range hdr {
		r.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func TestChatGuards(t *testing.T) {
	_, h, base := chatTestAgent(t)
	const host = "127.0.0.1:5555"
	if w := do(h, "GET", base+"/", host, "", nil); w.Code != 200 || !strings.Contains(w.Body.String(), "Chat with support") {
		t.Fatalf("page: %d", w.Code)
	}
	if w := do(h, "GET", "/chat/wrong/m", host, "", nil); w.Code != 404 {
		t.Fatalf("wrong token must 404, got %d", w.Code)
	}
	if w := do(h, "GET", base+"/m", "evil.example:5555", "", nil); w.Code != 404 {
		t.Fatalf("wrong Host must 404, got %d", w.Code)
	}
	if w := do(h, "POST", base+"/send", host, `{"text":"hi"}`, nil); w.Code != 403 {
		t.Fatalf("a post without the custom header must be refused, got %d", w.Code)
	}
}

func TestChatRoundTrip(t *testing.T) {
	a, h, base := chatTestAgent(t)
	const host = "127.0.0.1:5555"
	a.chatIncoming("m1", "  hello\x00 there ")
	if a.tray.ChatSeq != 1 || a.tray.ChatUnread != 1 {
		t.Fatalf("tray not told: %+v", a.tray)
	}
	w := do(h, "GET", base+"/m", host, "", nil)
	if !strings.Contains(w.Body.String(), "hello there") || a.tray.ChatUnread != 0 {
		t.Fatalf("messages not served or unread not cleared: %s", w.Body.String())
	}
	hdr := map[string]string{"X-Helm-Chat": "1"}
	if w := do(h, "POST", base+"/send", host, `{"text":"thanks"}`, hdr); w.Code != 204 {
		t.Fatalf("send: %d", w.Code)
	}
	if w := do(h, "POST", base+"/send", host, `{"text":"again"}`, hdr); w.Code != 429 {
		t.Fatalf("a second message within a moment must be throttled, got %d", w.Code)
	}
	if w := do(h, "POST", base+"/send", host, `{"text":"   "}`, hdr); w.Code == 204 {
		t.Fatal("an empty message was accepted")
	}
	if len(a.chat) != 2 || a.chat[1].From != "user" {
		t.Fatalf("conversation: %+v", a.chat)
	}
	a.stMu.Lock()
	a.tray.State = "offline"
	a.stMu.Unlock()
	a.chatLast = a.chatLast.Add(-5e9)
	if w := do(h, "POST", base+"/send", host, `{"text":"x"}`, hdr); w.Code != 503 {
		t.Fatalf("offline PC must refuse, got %d", w.Code)
	}
}
