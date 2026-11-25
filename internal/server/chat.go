package server

import (
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"helm/internal/proto"
)

const (
	chatKeep    = 30 * 24 * time.Hour
	chatMaxText = 2000
	chatMaxMsgs = 500
)

// ChatMsg is one line of the conversation with the person at a PC.
type ChatMsg struct {
	ID   string    `json:"id"`
	At   time.Time `json:"at"`
	From string    `json:"from"` // "admin" or "user"
	Text string    `json:"text"`
	Read bool      `json:"read,omitempty"` // a message from the user that an administrator has opened
	Sent bool      `json:"sent,omitempty"` // an administrator's message that reached the PC
}

var chatRate sync.Map // device id -> []time.Time of recent messages from the PC

func cleanChat(s string) string {
	s = strings.Map(func(r rune) rune {
		if r == '\n' || r == '\t' || r >= 32 && r != 127 {
			return r
		}
		return -1
	}, s)
	s = strings.TrimSpace(s)
	if r := []rune(s); len(r) > chatMaxText {
		s = string(r[:chatMaxText])
	}
	return s
}

func (s *Server) chatAdd(devID, from, text string) ChatMsg {
	m := ChatMsg{ID: randHex(8), At: time.Now().UTC(), From: from, Text: text}
	s.db.update(func(d *dbData) {
		if d.Chat == nil {
			d.Chat = map[string][]ChatMsg{}
		}
		l := append(d.Chat[devID], m)
		if len(l) > chatMaxMsgs {
			l = l[len(l)-chatMaxMsgs:]
		}
		d.Chat[devID] = l
	})
	return m
}

// chatFromUser stores a message typed at a PC and tells the administrator. A PC may send at most 10 a minute.
func (s *Server) chatFromUser(devID, name, text string) {
	text = cleanChat(text)
	if text == "" {
		return
	}
	now := time.Now()
	var recent []time.Time
	if v, ok := chatRate.Load(devID); ok {
		for _, t := range v.([]time.Time) {
			if now.Sub(t) < time.Minute {
				recent = append(recent, t)
			}
		}
	}
	if len(recent) >= 10 {
		return
	}
	chatRate.Store(devID, append(recent, now))
	s.chatAdd(devID, "user", text)
	if s.db.settings().Rules[RuleChat] {
		s.notify("💬 " + name + ": " + firstLine(text, 300))
	}
}

// chatFlush delivers administrator messages to PCs that are online and approved.
func (s *Server) chatFlush() {
	type pending struct {
		dev string
		id  string
		txt string
	}
	var todo []pending
	s.db.view(func(d *dbData) {
		for dev, l := range d.Chat {
			for _, m := range l {
				if m.From == "admin" && !m.Sent {
					todo = append(todo, pending{dev, m.ID, m.Text})
				}
			}
		}
	})
	if len(todo) == 0 {
		return
	}
	online := s.hub.onlineIDs()
	var done = map[string]bool{}
	for _, p := range todo {
		a := online[p.dev]
		if a == nil || !a.approved.Load() {
			continue
		}
		if a.send(proto.Frame{T: proto.TChat, ID: p.id, Msg: p.txt}) == nil {
			done[p.id] = true
		}
	}
	if len(done) == 0 {
		return
	}
	s.db.update(func(d *dbData) {
		for dev, l := range d.Chat {
			for i := range l {
				if done[l[i].ID] {
					d.Chat[dev][i].Sent = true
				}
			}
		}
	})
}

func (s *Server) chatPurge() {
	cut := time.Now().Add(-chatKeep)
	s.db.update(func(d *dbData) {
		for dev, l := range d.Chat {
			keep := l[:0:0]
			for _, m := range l {
				if m.At.After(cut) {
					keep = append(keep, m)
				}
			}
			if len(keep) == 0 {
				delete(d.Chat, dev)
			} else {
				d.Chat[dev] = keep
			}
		}
	})
}

type chatConv struct {
	DeviceID string   `json:"deviceId"`
	Name     string   `json:"name"`
	Online   bool     `json:"online"`
	Last     *ChatMsg `json:"last,omitempty"`
	Unread   int      `json:"unread"`
}

func (s *Server) handleChatInbox(w http.ResponseWriter, r *http.Request, sess *session) {
	online := s.hub.onlineIDs()
	var out []chatConv
	total := 0
	s.db.view(func(d *dbData) {
		for _, dev := range s.st.devices() {
			l := d.Chat[dev.ID]
			if len(l) == 0 {
				continue
			}
			c := chatConv{DeviceID: dev.ID, Name: dev.Name, Online: online[dev.ID] != nil}
			last := l[len(l)-1]
			c.Last = &last
			for _, m := range l {
				if m.From == "user" && !m.Read {
					c.Unread++
				}
			}
			total += c.Unread
			out = append(out, c)
		}
	})
	sort.Slice(out, func(i, j int) bool { return out[i].Last.At.After(out[j].Last.At) })
	writeJSON(w, 200, map[string]any{"conversations": out, "unread": total})
}

func (s *Server) handleChatGet(w http.ResponseWriter, r *http.Request, sess *session) {
	id := r.PathValue("id")
	if _, ok := s.st.device(id); !ok {
		writeErr(w, 404, "no such device")
		return
	}
	var msgs []ChatMsg
	s.db.update(func(d *dbData) {
		l := d.Chat[id]
		for i := range l {
			if l[i].From == "user" {
				l[i].Read = true
			}
		}
		msgs = append(msgs, l...)
	})
	if msgs == nil {
		msgs = []ChatMsg{}
	}
	writeJSON(w, 200, map[string]any{"messages": msgs, "online": s.hub.online(id) != nil})
}

func (s *Server) handleChatSend(w http.ResponseWriter, r *http.Request, sess *session) {
	id := r.PathValue("id")
	dev, ok := s.st.device(id)
	if !ok || !dev.Approved {
		writeErr(w, 404, "no such device")
		return
	}
	var req struct{ Text string }
	if !readJSON(w, r, &req) {
		return
	}
	text := cleanChat(req.Text)
	if text == "" {
		writeErr(w, 400, "write a message first")
		return
	}
	m := s.chatAdd(id, "admin", text)
	s.record(r, "chat_sent", id, "")
	go s.chatFlush()
	writeJSON(w, 200, m)
}
