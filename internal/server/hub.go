package server

import (
	"encoding/json"
	"errors"
	"sync"
	"sync/atomic"
	"time"

	"helm/internal/proto"
	"helm/internal/ws"
)

// cmdSpec describes a command the UI may send to an agent.
type cmdSpec struct {
	Danger  bool          // requires a recent 2FA step-up
	Timeout time.Duration // how long the server waits for the agent
}

var commands = map[string]cmdSpec{
	// read-only
	"inventory":     {false, 2 * time.Minute},
	"software.list": {false, 2 * time.Minute},
	"process.list":  {false, 60 * time.Second},
	"service.list":  {false, 60 * time.Second},
	"eventlog":      {false, 90 * time.Second},
	"file.list":     {false, 60 * time.Second},
	"updates.check": {false, 15 * time.Minute},
	"winget.list":   {false, 5 * time.Minute},
	"rdp.status":    {false, 60 * time.Second},
	"drives.list":   {false, 30 * time.Second},
	"msg":           {false, 30 * time.Second},
	"ping":          {false, 20 * time.Second},
	// state-changing
	"power":           {false, 60 * time.Second},
	"exec":            {true, 3*time.Hour + time.Minute},
	"process.kill":    {false, 30 * time.Second},
	"service.control": {false, 2 * time.Minute},
	"updates.install": {false, 4 * time.Hour},
	"winget.upgrade":  {false, 2 * time.Hour},
	"file.mkdir":      {false, 30 * time.Second},
	"file.delete":     {true, 2 * time.Minute},
	"file.rename":     {false, 30 * time.Second},
	"rdp.enable":      {false, 60 * time.Second},
	"rdp.disable":     {false, 60 * time.Second},
	"agent.update":    {false, 10 * time.Minute},
	"agent.uninstall": {true, 60 * time.Second},
	"wol":             {false, 30 * time.Second},
	"net.scan":        {false, 5 * time.Minute},
	"agent.push":      {true, 25 * time.Minute},
	// scanning and deployment
	"scan.software":    {false, 3 * time.Minute},
	"scan.config":      {false, 5 * time.Minute},
	"scan.ports":       {false, 2 * time.Minute},
	"winget.install":   {false, 2 * time.Hour},
	"winget.uninstall": {false, 2 * time.Hour},
	"pkg.install":      {false, 3 * time.Hour},
	"fix.apply":        {false, 10 * time.Minute},
}

// Job tracks one command sent to an agent.
type Job struct {
	ID       string          `json:"id"`
	DeviceID string          `json:"deviceId"`
	Name     string          `json:"name"`
	Args     json.RawMessage `json:"args,omitempty"`
	Created  time.Time       `json:"created"`
	Finished time.Time       `json:"finished,omitempty"`
	Status   string          `json:"status"` // running, ok, error
	Err      string          `json:"err,omitempty"`
	Data     json.RawMessage `json:"data,omitempty"`
	Progress []string        `json:"progress,omitempty"`
	Actor    string          `json:"-"`

	done  chan struct{}
	timer *time.Timer
}

// Agent is a connected control connection.
type Agent struct {
	ID       string
	conn     *ws.Conn
	approved atomic.Bool
	Since    time.Time
	IP       string
	Stats    *proto.Stats
	StatsAt  time.Time
	mu       sync.Mutex
}

type chanWait struct {
	deviceID string
	kind     string
	ch       chan *ws.Conn
}

// Hub tracks connected agents, jobs and pending data channels.
type Hub struct {
	mu     sync.Mutex
	agents map[string]*Agent
	jobs   map[string]*Job
	order  []string
	chans  map[string]*chanWait
	// refusals receives the agent's reason when it declines to open a channel.
	refusals map[string]chan string
	// onFinish is called (without locks held) with a snapshot of each finished job.
	onFinish func(Job)
	// onStart is called with a snapshot of every new job, onProgress for each progress report (pct < 0 when none).
	onStart    func(Job)
	onProgress func(id string, pct int, msg string)
}

func newHub() *Hub {
	return &Hub{agents: map[string]*Agent{}, jobs: map[string]*Job{}, chans: map[string]*chanWait{},
		refusals: map[string]chan string{}}
}

// refuse delivers an agent's refusal for a pending channel open.
func (h *Hub) refuse(sid, reason string) {
	h.mu.Lock()
	ch := h.refusals[sid]
	h.mu.Unlock()
	if ch != nil {
		select {
		case ch <- reason:
		default:
		}
	}
}

var (
	errOffline  = errors.New("device is offline")
	errPending  = errors.New("device is not approved yet")
	errUnknownC = errors.New("unknown command")
)

func (h *Hub) online(id string) *Agent {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.agents[id]
}

func (h *Hub) onlineIDs() map[string]*Agent {
	h.mu.Lock()
	defer h.mu.Unlock()
	m := make(map[string]*Agent, len(h.agents))
	for k, v := range h.agents {
		m[k] = v
	}
	return m
}

// attach registers an agent connection, replacing any previous one.
func (h *Hub) attach(a *Agent) {
	h.mu.Lock()
	old := h.agents[a.ID]
	h.agents[a.ID] = a
	h.mu.Unlock()
	if old != nil {
		old.conn.Close(ws.CloseGoingAway, "replaced by newer connection")
	}
}

// detach removes the agent (only if still current) and fails its running jobs.
func (h *Hub) detach(a *Agent) {
	h.mu.Lock()
	if h.agents[a.ID] == a {
		delete(h.agents, a.ID)
	}
	var lost []*Job
	for _, j := range h.jobs {
		if j.DeviceID == a.ID && j.Status == "running" {
			lost = append(lost, j)
		}
	}
	h.mu.Unlock()
	if h.online(a.ID) == nil {
		for _, j := range lost {
			h.finish(j.ID, "agent disconnected", nil)
		}
	}
}

func (a *Agent) send(f proto.Frame) error {
	b, err := json.Marshal(f)
	if err != nil {
		return err
	}
	return a.conn.WriteMessage(ws.OpText, b)
}

// dispatch starts a job on the device.
func (h *Hub) dispatch(deviceID, name string, args json.RawMessage, actor string) (*Job, error) {
	spec, ok := commands[name]
	if !ok {
		return nil, errUnknownC
	}
	a := h.online(deviceID)
	if a == nil {
		return nil, errOffline
	}
	if !a.approved.Load() {
		return nil, errPending
	}
	j := &Job{ID: randHex(8), DeviceID: deviceID, Name: name, Args: args, Created: time.Now().UTC(),
		Status: "running", Actor: actor, done: make(chan struct{})}
	h.mu.Lock()
	h.jobs[j.ID] = j
	h.order = append(h.order, j.ID)
	if len(h.order) > 500 {
		old := h.order[0]
		h.order = h.order[1:]
		delete(h.jobs, old)
	}
	h.mu.Unlock()
	if h.onStart != nil {
		h.onStart(*j)
	}
	j.timer = time.AfterFunc(spec.Timeout, func() { h.finish(j.ID, "timed out waiting for the agent", nil) })
	if err := a.send(proto.Frame{T: proto.TCmd, ID: j.ID, Name: name, Args: args}); err != nil {
		h.finish(j.ID, "send failed: "+err.Error(), nil)
		return h.snapshot(j.ID), nil
	}
	return h.snapshot(j.ID), nil
}

func (h *Hub) snapshot(id string) *Job {
	h.mu.Lock()
	defer h.mu.Unlock()
	j := h.jobs[id]
	if j == nil {
		return nil
	}
	c := *j
	c.Progress = append([]string(nil), j.Progress...)
	return &c
}

// finish completes a job (idempotent).
func (h *Hub) finish(id, errMsg string, data json.RawMessage) {
	h.mu.Lock()
	j := h.jobs[id]
	if j == nil || j.Status != "running" {
		h.mu.Unlock()
		return
	}
	if errMsg != "" {
		j.Status, j.Err = "error", errMsg
	} else {
		j.Status, j.Data = "ok", data
	}
	j.Finished = time.Now().UTC()
	if j.timer != nil {
		j.timer.Stop()
	}
	close(j.done)
	snap := *j
	cb := h.onFinish
	h.mu.Unlock()
	if cb != nil {
		cb(snap)
	}
}

func (h *Hub) progress(id, msg string, pct int) {
	h.mu.Lock()
	defer h.mu.Unlock()
	msg = clip(msg, 500)
	if j := h.jobs[id]; j != nil && j.Status == "running" {
		if h.onProgress != nil {
			h.onProgress(id, pct, msg)
		}
		j.Progress = append(j.Progress, msg)
		if len(j.Progress) > 60 {
			j.Progress = j.Progress[len(j.Progress)-60:]
		}
	}
}

// wait blocks until the job is done or d elapses, then returns a snapshot.
func (h *Hub) wait(id string, d time.Duration) *Job {
	h.mu.Lock()
	j := h.jobs[id]
	h.mu.Unlock()
	if j == nil {
		return nil
	}
	select {
	case <-j.done:
	case <-time.After(d):
	}
	return h.snapshot(id)
}

func (h *Hub) jobsFor(deviceID string, limit int) []*Job {
	h.mu.Lock()
	ids := append([]string(nil), h.order...)
	h.mu.Unlock()
	var out []*Job
	for i := len(ids) - 1; i >= 0 && len(out) < limit; i-- {
		if j := h.snapshot(ids[i]); j != nil && (deviceID == "" || j.DeviceID == deviceID) {
			j.Data = nil // list view stays small
			out = append(out, j)
		}
	}
	return out
}

// ---- data channels ----

// expectChannel registers a one-shot rendezvous for an agent data channel.
func (h *Hub) expectChannel(sid, deviceID, kind string) chan *ws.Conn {
	w := &chanWait{deviceID: deviceID, kind: kind, ch: make(chan *ws.Conn, 1)}
	h.mu.Lock()
	h.chans[sid] = w
	h.mu.Unlock()
	return w.ch
}

func (h *Hub) cancelChannel(sid string) {
	h.mu.Lock()
	delete(h.chans, sid)
	h.mu.Unlock()
}

// claimChannel is called when an agent dials /ws/agent/chan/<sid>.
func (h *Hub) claimChannel(sid, deviceID string) (chan *ws.Conn, bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	w := h.chans[sid]
	if w == nil || w.deviceID != deviceID {
		return nil, false
	}
	delete(h.chans, sid)
	return w.ch, true
}

// openChannel asks the agent to open a data channel and waits for it.
// The returned error describes agent-side refusals (e.g. consent denied).
func (h *Hub) openChannel(deviceID, kind string, args any, wait time.Duration) (*ws.Conn, error) {
	a := h.online(deviceID)
	if a == nil {
		return nil, errOffline
	}
	if !a.approved.Load() {
		return nil, errPending
	}
	sid := randHex(12)
	ch := h.expectChannel(sid, deviceID, kind)
	defer h.cancelChannel(sid)
	ab, _ := json.Marshal(args)
	refused := make(chan string, 1)
	h.mu.Lock()
	h.refusals[sid] = refused
	h.mu.Unlock()
	defer func() { h.mu.Lock(); delete(h.refusals, sid); h.mu.Unlock() }()
	if err := a.send(proto.Frame{T: proto.TOpen, SID: sid, Kind: kind, Args: ab}); err != nil {
		return nil, err
	}
	select {
	case c := <-ch:
		return c, nil
	case msg := <-refused:
		return nil, errors.New(msg)
	case <-time.After(wait):
		return nil, errors.New("timed out waiting for the PC (no response or consent prompt unanswered)")
	}
}

// scrubArgs removes the arguments from a running job once they have been sent (they may hold a password).
func (h *Hub) scrubArgs(id string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if j := h.jobs[id]; j != nil {
		j.Args = json.RawMessage(`{"redacted":true}`)
	}
}
