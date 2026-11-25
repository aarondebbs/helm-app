package server

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

func newTestServer(t *testing.T) *Server {
	t.Helper()
	s, err := New(Config{DataDir: t.TempDir(), Listen: "127.0.0.1:0", Dev: true, Version: "test"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	return s
}

func TestTelegramSend(t *testing.T) {
	var mu sync.Mutex
	var got []map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		var m map[string]any
		_ = json.Unmarshal(b, &m)
		if !strings.HasPrefix(r.URL.Path, "/botTOKEN/sendMessage") {
			t.Errorf("unexpected path %s", r.URL.Path)
		}
		mu.Lock()
		got = append(got, m)
		mu.Unlock()
		if m["chat_id"] == "bad" {
			w.Write([]byte(`{"ok":false,"description":"chat not found"}`))
			return
		}
		w.Write([]byte(`{"ok":true}`))
	}))
	defer srv.Close()
	old := telegramBase
	telegramBase = srv.URL
	defer func() { telegramBase = old }()
	if err := sendTelegram(t.Context(), "TOKEN", "42", "hello"); err != nil {
		t.Fatal(err)
	}
	if err := sendTelegram(t.Context(), "TOKEN", "bad", "x"); err == nil || !strings.Contains(err.Error(), "chat not found") {
		t.Fatalf("expected API error, got %v", err)
	}
	if len(got) != 2 || got[0]["text"] != "hello" || got[0]["chat_id"] != "42" {
		t.Fatalf("unexpected payload %v", got)
	}
}

func TestAlertLifecycleAndNotify(t *testing.T) {
	var mu sync.Mutex
	var msgs []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		var m map[string]any
		_ = json.Unmarshal(b, &m)
		mu.Lock()
		msgs = append(msgs, m["text"].(string))
		mu.Unlock()
		w.Write([]byte(`{"ok":true}`))
	}))
	defer srv.Close()
	old := telegramBase
	telegramBase = srv.URL
	defer func() { telegramBase = old }()

	s := newTestServer(t)
	defer s.wg.Wait() // let in-flight notifications finish before telegramBase is restored
	s.db.update(func(d *dbData) {
		d.Settings.Telegram.Enabled, d.Settings.Telegram.Token, d.Settings.Telegram.ChatID = true, "TOKEN", "7"
	})
	_ = s.st.update(func(d *data) error {
		d.Devices["dev1"] = &Device{ID: "dev1", Name: "Front desk", Approved: true, LastSeen: time.Now().Add(-2 * time.Hour), CreatedAt: time.Now()}
		return nil
	})
	s.evalAlerts()
	s.evalAlerts() // second pass must not duplicate or re-notify
	open := func() []Alert {
		var out []Alert
		s.db.view(func(d *dbData) {
			for _, a := range d.Alerts {
				if a.Resolved.IsZero() {
					out = append(out, *a)
				}
			}
		})
		return out
	}
	if a := open(); len(a) != 1 || a[0].Rule != RuleOffline || !strings.Contains(a[0].Title, "Front desk") {
		t.Fatalf("expected exactly one offline alert, got %+v", a)
	}
	time.Sleep(300 * time.Millisecond)
	mu.Lock()
	n := len(msgs)
	mu.Unlock()
	if n != 1 || !strings.Contains(msgs[0], "Front desk is offline") {
		t.Fatalf("expected one Telegram message, got %v", msgs)
	}
	// disabling the rule closes the alert
	s.db.update(func(d *dbData) { d.Settings.Rules[RuleOffline] = false })
	s.evalAlerts()
	if a := open(); len(a) != 0 {
		t.Fatalf("alert should resolve when its rule is disabled: %+v", a)
	}
}

func TestTargetResolution(t *testing.T) {
	s := newTestServer(t)
	_ = s.st.update(func(d *data) error {
		d.Devices["a"] = &Device{ID: "a", Name: "A", Approved: true, Group: "Front", Tags: []string{"vip"}}
		d.Devices["b"] = &Device{ID: "b", Name: "B", Approved: true, Group: "Back", Tags: []string{"laptop"}}
		d.Devices["c"] = &Device{ID: "c", Name: "C", Approved: false, Group: "Front"}
		return nil
	})
	names := func(t Target) string {
		var n []string
		for _, d := range s.resolveTarget(t) {
			n = append(n, d.Name)
		}
		return strings.Join(n, ",")
	}
	if got := names(Target{All: true}); got != "A,B" {
		t.Errorf("all: %q (pending PCs must be excluded)", got)
	}
	if got := names(Target{Group: "Front"}); got != "A" {
		t.Errorf("group: %q", got)
	}
	if got := names(Target{Tag: "LAPTOP"}); got != "B" {
		t.Errorf("tag: %q", got)
	}
	if got := names(Target{Devices: []string{"b", "c", "zz"}}); got != "B" {
		t.Errorf("devices: %q (unapproved/unknown must be dropped)", got)
	}
	if got := names(Target{}); got != "" {
		t.Errorf("empty target must match nothing, got %q", got)
	}
}

func TestNextRun(t *testing.T) {
	loc := time.UTC
	from := time.Date(2026, 11, 21, 10, 0, 0, 0, loc) // a Saturday
	d := &Schedule{Kind: "daily", At: "03:30"}
	if got := nextRun(d, from); !got.Equal(time.Date(2026, 11, 22, 3, 30, 0, 0, loc)) {
		t.Errorf("daily: %v", got)
	}
	w := &Schedule{Kind: "weekly", At: "12:00", Days: []int{1}} // Monday
	if got := nextRun(w, from); !got.Equal(time.Date(2026, 11, 23, 12, 0, 0, 0, loc)) {
		t.Errorf("weekly: %v", got)
	}
	i := &Schedule{Kind: "interval", Every: 1}
	if got := nextRun(i, from); got.Sub(from) != 5*time.Minute {
		t.Errorf("interval floor: %v", got.Sub(from))
	}
}

func TestCSVFormulaInjection(t *testing.T) {
	rec := httptest.NewRecorder()
	csvOut(rec, "x", [][]string{{"a"}, {"=HYPERLINK(\"http://evil\")"}, {"+1"}, {"ok"}})
	body := rec.Body.String()
	if strings.Contains(body, "\n=HYPERLINK") || strings.Contains(body, "\n+1") {
		t.Errorf("formulas must be neutralised: %q", body)
	}
}

func TestValidateEmail(t *testing.T) {
	ok := EmailSettings{Enabled: true, Host: "smtp.example.com", Security: "starttls", From: "Helm <helm@example.com>", To: "a@example.com, b@example.com"}
	if err := validateEmail(&ok); err != nil || ok.Port != 587 {
		t.Fatalf("valid settings rejected or port not defaulted: %v %d", err, ok.Port)
	}
	for name, mod := range map[string]func(*EmailSettings){
		"newline in host": func(e *EmailSettings) { e.Host = "a.com\r\nRCPT TO:x" },
		"url as host":     func(e *EmailSettings) { e.Host = "smtp://x.com" },
		"bad from":        func(e *EmailSettings) { e.From = "nope" },
		"no recipients":   func(e *EmailSettings) { e.To = "" },
		"bad security":    func(e *EmailSettings) { e.Security = "ssl3" },
	} {
		e := ok
		mod(&e)
		if validateEmail(&e) == nil {
			t.Errorf("%s was accepted", name)
		}
	}
	if got := cleanHeader("a\r\nBcc: x"); strings.ContainsAny(got, "\r\n") {
		t.Errorf("header not cleaned: %q", got)
	}
}

func TestChatFlow(t *testing.T) {
	s := newTestServer(t)
	m := s.chatAdd("d1", "admin", "hello")
	if m.Sent {
		t.Fatal("new admin message must start undelivered")
	}
	s.chatFromUser("d1", "PC", "  hi\x00 there  ")
	var got []ChatMsg
	s.db.view(func(d *dbData) { got = append(got, d.Chat["d1"]...) })
	if len(got) != 2 || got[1].Text != "hi there" || got[1].From != "user" {
		t.Fatalf("unexpected conversation: %+v", got)
	}
	for i := 0; i < 20; i++ {
		s.chatFromUser("d2", "PC2", "spam")
	}
	n := 0
	s.db.view(func(d *dbData) { n = len(d.Chat["d2"]) })
	if n != 10 {
		t.Fatalf("rate limit let %d messages through, want 10", n)
	}
	s.db.update(func(d *dbData) { d.Chat["d1"][0].At = time.Now().Add(-31 * 24 * time.Hour) })
	s.chatPurge()
	s.db.view(func(d *dbData) { n = len(d.Chat["d1"]) })
	if n != 1 {
		t.Fatalf("purge kept %d messages, want 1", n)
	}
}
