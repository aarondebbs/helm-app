package agent

import (
	"sync"
	"time"
)

// FlowControl is end-to-end flow control for the screen stream. The helper only talks to the agent service over
// loopback, so how long a write takes says nothing about the real link; frames pile up in socket buffers on the way to
// the viewer and the picture lags by seconds. With acknowledgements from the viewer, at most Max frames are in flight,
// and the round-trip time of a frame is the honest measure of how the link is doing.
//
// A viewer that never acknowledges (an older console page) is detected and left unthrottled, and a lost
// acknowledgement cannot stall the stream for more than a moment.
type FlowControl struct {
	mu      sync.Mutex
	Max     int
	capable bool
	seq     int
	acked   int
	sent    map[int]time.Time
}

// NewFlowControl allows two frames in flight, which keeps the link busy without building a queue.
func NewFlowControl() *FlowControl { return &FlowControl{Max: 2, sent: map[int]time.Time{}} }

// CanSend reports whether another frame may be started.
func (f *FlowControl) CanSend() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	if !f.capable || f.seq-f.acked < f.Max {
		return true
	}
	if t, ok := f.sent[f.acked+1]; ok && time.Since(t) > 3*time.Second {
		return true // an acknowledgement went missing; do not freeze the picture
	}
	return false
}

// Sent reserves the next sequence number and records when it was sent.
func (f *FlowControl) Sent() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.seq++
	f.sent[f.seq] = time.Now()
	return f.seq
}

// Ack records the viewer's acknowledgement of frame n and returns the round-trip time.
func (f *FlowControl) Ack(n int) (time.Duration, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.capable = true
	t, ok := f.sent[n]
	if n > f.acked {
		for i := f.acked + 1; i <= n; i++ {
			delete(f.sent, i)
		}
		f.acked = n
	}
	if !ok {
		return 0, false
	}
	return time.Since(t), true
}

// Capable reports whether the viewer has shown that it acknowledges frames.
func (f *FlowControl) Capable() bool { f.mu.Lock(); defer f.mu.Unlock(); return f.capable }
