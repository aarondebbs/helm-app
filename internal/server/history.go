package server

import (
	"sync"
	"time"
)

// HistPt is one heartbeat sample.
type HistPt struct {
	T   int64   `json:"t"`
	CPU float64 `json:"cpu"`
	Mem float64 `json:"mem"` // percent
}

const histMax = 240 // 1 hour at 15 s

type histStore struct {
	mu sync.Mutex
	m  map[string][]HistPt
}

func newHistStore() *histStore { return &histStore{m: map[string][]HistPt{}} }

func (h *histStore) add(id string, cpu float64, memUsed, memTotal uint64) {
	mem := 0.0
	if memTotal > 0 {
		mem = float64(memUsed) / float64(memTotal) * 100
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	pts := append(h.m[id], HistPt{T: time.Now().Unix(), CPU: cpu, Mem: mem})
	if len(pts) > histMax {
		pts = pts[len(pts)-histMax:]
	}
	h.m[id] = pts
}

func (h *histStore) get(id string) []HistPt {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]HistPt(nil), h.m[id]...)
}

func (h *histStore) drop(id string) {
	h.mu.Lock()
	delete(h.m, id)
	h.mu.Unlock()
}
