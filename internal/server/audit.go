package server

import (
	"bufio"
	"encoding/json"
	"os"
	"sync"
	"time"
)

// AuditEntry is one line of the audit log.
type AuditEntry struct {
	Time   time.Time `json:"time"`
	IP     string    `json:"ip"`
	Action string    `json:"action"`
	Device string    `json:"device,omitempty"`
	Detail string    `json:"detail,omitempty"`
}

type auditLog struct {
	mu   sync.Mutex
	path string
}

func newAudit(path string) *auditLog { return &auditLog{path: path} }

const auditMax = 5 << 20

func (a *auditLog) add(e AuditEntry) {
	e.Time = time.Now().UTC()
	if len(e.Detail) > 400 {
		e.Detail = e.Detail[:400] + "…"
	}
	b, _ := json.Marshal(e)
	a.mu.Lock()
	defer a.mu.Unlock()
	if st, err := os.Stat(a.path); err == nil && st.Size() > auditMax {
		_ = os.Rename(a.path, a.path+".1")
	}
	f, err := os.OpenFile(a.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return
	}
	defer f.Close()
	_, _ = f.Write(append(b, '\n'))
}

// tail returns the last n entries, newest first.
func (a *auditLog) tail(n int) []AuditEntry {
	a.mu.Lock()
	defer a.mu.Unlock()
	f, err := os.Open(a.path)
	if err != nil {
		return []AuditEntry{}
	}
	defer f.Close()
	var all []AuditEntry
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 1<<20)
	for sc.Scan() {
		var e AuditEntry
		if json.Unmarshal(sc.Bytes(), &e) == nil {
			all = append(all, e)
		}
	}
	out := make([]AuditEntry, 0, n)
	for i := len(all) - 1; i >= 0 && len(out) < n; i-- {
		out = append(out, all[i])
	}
	return out
}
