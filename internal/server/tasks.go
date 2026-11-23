package server

import (
	"encoding/json"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"
)

// A task is one piece of work the console started on a PC: installing updates, a scan, a package deployment.
// Running tasks live in memory with a live percentage and stage; finished ones are kept for a week with their stages.

const taskKeep = 7 * 24 * time.Hour

// TaskStage is one key step in a task, such as "Downloading update 2 of 5".
type TaskStage struct {
	At  time.Time `json:"at"`
	Msg string    `json:"msg"`
	Pct int       `json:"pct"` // -1 when the step has no percentage
}

type TaskRec struct {
	ID         string      `json:"id"`
	Kind       string      `json:"kind"`
	Title      string      `json:"title"`
	DeviceID   string      `json:"deviceId"`
	DeviceName string      `json:"deviceName"`
	Actor      string      `json:"actor,omitempty"`
	Started    time.Time   `json:"started"`
	Finished   time.Time   `json:"finished,omitempty"`
	Status     string      `json:"status"`  // running | ok | error
	Percent    int         `json:"percent"` // 0-100, or -1 when the task cannot say
	Stage      string      `json:"stage,omitempty"`
	Stages     []TaskStage `json:"stages,omitempty"`
	Err        string      `json:"err,omitempty"`
}

type taskBook struct {
	mu      sync.Mutex
	running map[string]*TaskRec
}

func newTaskBook() *taskBook { return &taskBook{running: map[string]*TaskRec{}} }

// jobTasks maps the commands that count as tasks to a plain title. Quick lookups (lists, pings) are not tasks.
var jobTasks = map[string]string{
	"updates.install": "Install updates", "winget.upgrade": "Update programs", "winget.install": "Install program",
	"winget.uninstall": "Remove program", "pkg.install": "Install package", "fix.apply": "Apply fix",
	"exec": "Run script", "power": "Power action", "agent.update": "Update Helm agent",
	"net.scan": "Network scan", "agent.push": "Install Helm on a PC",
}

func jobTitle(name string, args json.RawMessage) string {
	t := jobTasks[name]
	var a struct {
		IDs      []string `json:"ids"`
		ID       string   `json:"id"`
		All      bool     `json:"all"`
		Action   string   `json:"action"`
		Filename string   `json:"filename"`
	}
	_ = json.Unmarshal(args, &a)
	switch name {
	case "updates.install":
		if len(a.IDs) > 0 {
			return t + " (" + plural(len(a.IDs), "update") + ")"
		}
	case "winget.upgrade":
		if a.All {
			return "Update all programs"
		}
		if len(a.IDs) > 0 {
			return t + " (" + strings.Join(a.IDs, ", ") + ")"
		}
	case "winget.install", "winget.uninstall":
		if a.ID != "" {
			return t + " " + a.ID
		}
	case "pkg.install":
		if a.Filename != "" {
			return t + " " + a.Filename
		}
	case "fix.apply":
		if a.ID != "" {
			return t + " (" + a.ID + ")"
		}
	case "power":
		switch a.Action {
		case "restart":
			return "Restart"
		case "shutdown":
			return "Shut down"
		case "lock", "logoff", "sleep", "hibernate":
			return strings.ToUpper(a.Action[:1]) + a.Action[1:]
		}
	}
	return t
}

func plural(n int, w string) string {
	if n == 1 {
		return "1 " + w
	}
	return itoa(n) + " " + w + "s"
}

func itoa(n int) string { b, _ := json.Marshal(n); return string(b) }

func (s *Server) deviceLabel(id string) string {
	if d, ok := s.st.device(id); ok {
		if d.Name != "" {
			return d.Name
		}
	}
	return id
}

// taskStart registers a running task. Calling it twice with the same id keeps the first.
func (s *Server) taskStart(id, kind, title, deviceID, actor string) {
	s.tasks.mu.Lock()
	defer s.tasks.mu.Unlock()
	if _, ok := s.tasks.running[id]; ok {
		return
	}
	s.tasks.running[id] = &TaskRec{ID: id, Kind: kind, Title: title, DeviceID: deviceID, DeviceName: s.deviceLabel(deviceID),
		Actor: actor, Started: time.Now().UTC(), Status: "running", Percent: -1}
}

// taskUpdate records progress. pct < 0 leaves the percentage as it was; an empty msg leaves the stage as it was.
func (s *Server) taskUpdate(id string, pct int, msg string) {
	s.tasks.mu.Lock()
	defer s.tasks.mu.Unlock()
	t := s.tasks.running[id]
	if t == nil {
		return
	}
	if pct > 100 {
		pct = 100
	}
	if pct >= 0 {
		if pct < t.Percent && t.Percent >= 0 && pct != 0 {
			pct = t.Percent // a bar that goes backwards is more confusing than one that waits
		}
		t.Percent = pct
	}
	msg = strings.TrimSpace(msg)
	if len(msg) > 200 {
		msg = msg[:200]
	}
	if msg != "" && msg != t.Stage {
		t.Stage = msg
		if len(t.Stages) < 40 {
			t.Stages = append(t.Stages, TaskStage{At: time.Now().UTC(), Msg: msg, Pct: t.Percent})
		}
	}
}

// taskFinish ends a task and stores it in the history.
func (s *Server) taskFinish(id, errMsg string) {
	s.tasks.mu.Lock()
	t := s.tasks.running[id]
	delete(s.tasks.running, id)
	s.tasks.mu.Unlock()
	if t == nil {
		return
	}
	t.Finished = time.Now().UTC()
	if errMsg != "" {
		t.Status, t.Err = "error", firstLine(errMsg, 400)
	} else {
		t.Status, t.Percent = "ok", 100
	}
	cutoff := time.Now().Add(-taskKeep)
	s.db.update(func(x *dbData) {
		x.Tasks = append(x.Tasks, *t)
		keep := x.Tasks[:0]
		for _, r := range x.Tasks {
			if r.Finished.After(cutoff) {
				keep = append(keep, r)
			}
		}
		if len(keep) > 1000 {
			keep = keep[len(keep)-1000:]
		}
		x.Tasks = keep
	})
}

func firstLine(s string, max int) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	if len(s) > max {
		s = s[:max]
	}
	return s
}

// hookTasks connects the hub's jobs to the task book.
func (s *Server) hookTasks() {
	prev := s.hub.onFinish
	s.hub.onStart = func(j Job) {
		if _, ok := jobTasks[j.Name]; ok {
			s.taskStart(j.ID, j.Name, jobTitle(j.Name, j.Args), j.DeviceID, j.Actor)
		}
	}
	s.hub.onProgress = func(id string, pct int, msg string) { s.taskUpdate(id, pct, msg) }
	s.hub.onFinish = func(j Job) {
		if prev != nil {
			prev(j)
		}
		if _, ok := jobTasks[j.Name]; ok {
			s.taskFinish(j.ID, j.Err)
		}
	}
}

func (s *Server) handleTasks(w http.ResponseWriter, r *http.Request, sess *session) {
	dev := r.URL.Query().Get("device")
	s.tasks.mu.Lock()
	running := make([]TaskRec, 0, len(s.tasks.running))
	for _, t := range s.tasks.running {
		if dev == "" || t.DeviceID == dev {
			c := *t
			c.Stages = append([]TaskStage(nil), t.Stages...)
			running = append(running, c)
		}
	}
	s.tasks.mu.Unlock()
	sort.Slice(running, func(i, j int) bool { return running[i].Started.After(running[j].Started) })
	var recent []TaskRec
	s.db.view(func(x *dbData) {
		for i := len(x.Tasks) - 1; i >= 0 && len(recent) < 300; i-- {
			if dev == "" || x.Tasks[i].DeviceID == dev {
				recent = append(recent, x.Tasks[i])
			}
		}
	})
	if recent == nil {
		recent = []TaskRec{}
	}
	writeJSON(w, 200, map[string]any{"running": running, "recent": recent, "keepDays": int(taskKeep / (24 * time.Hour))})
}
