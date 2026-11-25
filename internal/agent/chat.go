package agent

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"helm/internal/proto"
)

// chatLine is one message in the conversation with whoever supports this PC. It lives in memory only:
// the administrator's console keeps the history.
type chatLine struct {
	ID   string    `json:"id"`
	From string    `json:"from"` // "admin" or "user"
	Text string    `json:"text"`
	At   time.Time `json:"at"`
}

const chatKeepLines = 100

func randToken() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func cleanText(s string, max int) string {
	s = strings.Map(func(r rune) rune {
		if r == '\n' || r == '\t' || r >= 32 && r != 127 {
			return r
		}
		return -1
	}, s)
	s = strings.TrimSpace(s)
	if r := []rune(s); len(r) > max {
		s = string(r[:max])
	}
	return s
}

func (a *Agent) chatAppend(l chatLine) {
	a.chatMu.Lock()
	a.chat = append(a.chat, l)
	if len(a.chat) > chatKeepLines {
		a.chat = a.chat[len(a.chat)-chatKeepLines:]
	}
	a.chatMu.Unlock()
}

// chatIncoming records a message from the administrator and lets the tray know.
func (a *Agent) chatIncoming(id, text string) {
	text = cleanText(text, 2000)
	if text == "" {
		return
	}
	a.chatAppend(chatLine{ID: id, From: "admin", Text: text, At: time.Now().UTC()})
	a.stMu.Lock()
	a.tray.ChatSeq++
	a.tray.ChatUnread++
	a.stMu.Unlock()
	a.writeStatus()
	if !a.chatQuiet {
		go a.chatNotifyUser(text)
	}
}

// chatRoutes serves the chat window's page and API on the loopback listener. Every path contains a random token
// that only the tray (through the status file) knows, the Host header must be the loopback address (this stops
// DNS rebinding), and writes need a custom header (this stops other web pages from posting).
func (a *Agent) chatRoutes(mux *http.ServeMux, host string) {
	guard := func(h http.HandlerFunc, write bool) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			a.stMu.Lock()
			tok := a.tray.ChatToken
			a.stMu.Unlock()
			if r.Host != host || subtle.ConstantTimeCompare([]byte(r.PathValue("tok")), []byte(tok)) != 1 || tok == "" {
				http.NotFound(w, r)
				return
			}
			if write && r.Header.Get("X-Helm-Chat") != "1" {
				http.Error(w, "forbidden", http.StatusForbidden)
				return
			}
			w.Header().Set("Cache-Control", "no-store")
			h(w, r)
		}
	}
	mux.HandleFunc("GET /chat/{tok}/{$}", guard(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; connect-src 'self'")
		w.Header().Set("X-Frame-Options", "DENY")
		_, _ = w.Write([]byte(chatPage))
	}, false))
	mux.HandleFunc("GET /chat/{tok}/m", guard(func(w http.ResponseWriter, r *http.Request) {
		a.chatMu.Lock()
		msgs := append([]chatLine{}, a.chat...)
		a.chatMu.Unlock()
		a.stMu.Lock()
		unread, online := a.tray.ChatUnread, a.tray.State == "connected"
		sup, title := a.tray.AllowSupport, a.tray.Org
		if unread != 0 {
			a.tray.ChatUnread = 0
		}
		a.stMu.Unlock()
		if unread != 0 {
			a.writeStatus()
			a.sendFrame(proto.Frame{T: proto.TChat, ID: "seen"}) // lets the console show "seen"
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"messages": msgs, "online": online, "enabled": sup, "org": title})
	}, false))
	mux.HandleFunc("POST /chat/{tok}/send", guard(func(w http.ResponseWriter, r *http.Request) {
		a.stMu.Lock()
		ok := a.tray.State == "connected" && a.tray.AllowSupport
		a.stMu.Unlock()
		if !ok {
			http.Error(w, "this PC is not connected right now", http.StatusServiceUnavailable)
			return
		}
		var req struct{ Text string }
		if json.NewDecoder(http.MaxBytesReader(w, r.Body, 8192)).Decode(&req) != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		text := cleanText(req.Text, 2000)
		if text == "" {
			http.Error(w, "empty message", http.StatusBadRequest)
			return
		}
		a.chatMu.Lock()
		tooFast := time.Since(a.chatLast) < 700*time.Millisecond
		if !tooFast {
			a.chatLast = time.Now()
		}
		a.chatMu.Unlock()
		if tooFast {
			http.Error(w, "slow down", http.StatusTooManyRequests)
			return
		}
		a.chatAppend(chatLine{ID: randToken()[:8], From: "user", Text: text, At: time.Now().UTC()})
		a.sendFrame(proto.Frame{T: proto.TChat, Msg: text})
		w.WriteHeader(http.StatusNoContent)
	}, true))
}
