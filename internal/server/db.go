package server

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

// ---- persisted application data (everything except admin/devices/tokens, which live in Store) ----

// Settings are editable in the console.
type Settings struct {
	Telegram struct {
		Enabled bool   `json:"enabled"`
		Token   string `json:"token"`
		ChatID  string `json:"chatId"`
	} `json:"telegram"`
	NVDKey         string          `json:"nvdKey"`
	OfflineMinutes int             `json:"offlineMinutes"`
	DiskFreePct    int             `json:"diskFreePct"`
	AutoScan       bool            `json:"autoScan"`
	ScanEveryHours int             `json:"scanEveryHours"`
	Rules          map[string]bool `json:"rules"`
	// Cloud updates: GitHub "owner/repo" holding signed releases; agents are imported automatically unless manual.
	UpdateRepo         string `json:"updateRepo"`
	ManualAgentUpdates bool   `json:"manualAgentUpdates"`
	// Sign in with Google for the single administrator (see sso.go).
	Google GoogleSettings `json:"google"`
	// Patch window: when approved devices install pending updates on their own.
	Patch PatchSettings `json:"patch"`
}

// GoogleSettings holds the OAuth client of the Google Cloud project and the one address allowed to sign in.
type GoogleSettings struct {
	ClientID     string `json:"clientId"`
	ClientSecret string `json:"clientSecret"`
	Email        string `json:"email"`
}

// Alert rule identifiers.
const (
	RuleOffline   = "offline"
	RuleDiskLow   = "disk_low"
	RuleNewDevice = "new_device"
	RuleSecurity  = "security"
	RulePatches   = "patches"
	RuleSupport   = "support_request"
)

var ruleInfo = []struct{ ID, Title, Desc string }{
	{RuleOffline, "PC offline", "An approved PC has not been seen for the configured number of minutes."},
	{RuleDiskLow, "Low disk space", "A drive has less free space than the configured percentage."},
	{RuleNewDevice, "New PC waiting for approval", "A PC enrolled and is waiting for you to approve it."},
	{RuleSecurity, "Critical or high security findings", "A scan found critical/high vulnerabilities or configuration problems."},
	{RulePatches, "Security updates missing", "A scan found missing critical or important Windows updates."},
	{RuleSupport, "Support requested", "The person at a PC pressed Request support in the Helm tray menu."},
}

func defaultSettings() Settings {
	s := Settings{OfflineMinutes: 15, DiskFreePct: 10, AutoScan: true, ScanEveryHours: 24, Rules: map[string]bool{}}
	for _, r := range ruleInfo {
		s.Rules[r.ID] = true
	}
	return s
}

// Script is a saved script in the library.
type Script struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Desc      string    `json:"desc"`
	Shell     string    `json:"shell"` // powershell | cmd
	Body      string    `json:"body"`
	Timeout   int       `json:"timeout"` // seconds
	CreatedAt time.Time `json:"createdAt"`
	UpdatedAt time.Time `json:"updatedAt"`
}

// Target selects devices: everything, a group, or explicit IDs.
type Target struct {
	All     bool     `json:"all"`
	Group   string   `json:"group"`
	Tag     string   `json:"tag"`
	Devices []string `json:"devices"`
}

// Schedule runs an action on a target repeatedly.
type Schedule struct {
	ID       string    `json:"id"`
	Name     string    `json:"name"`
	Action   string    `json:"action"` // script | scan | updates.install | winget.upgrade_all | restart
	ScriptID string    `json:"scriptId"`
	Target   Target    `json:"target"`
	Kind     string    `json:"kind"`  // interval | daily | weekly
	Every    int       `json:"every"` // minutes, for interval
	At       string    `json:"at"`    // HH:MM server-local time, for daily/weekly
	Days     []int     `json:"days"`  // 0=Sunday..6, for weekly
	Enabled  bool      `json:"enabled"`
	Created  time.Time `json:"created"`
	LastRun  time.Time `json:"lastRun"`
	NextRun  time.Time `json:"nextRun"`
}

// RunResult is one device's outcome inside a Run.
type RunResult struct {
	DeviceID string `json:"deviceId"`
	Name     string `json:"name"`
	Status   string `json:"status"` // running | ok | error | skipped
	Output   string `json:"output,omitempty"`
	Err      string `json:"err,omitempty"`
	ExitCode *int   `json:"exitCode,omitempty"`
}

// Run is one execution of an action across devices (script, scan, deployment, update…).
type Run struct {
	ID         string      `json:"id"`
	Kind       string      `json:"kind"` // script | scan | deploy | update | power
	Title      string      `json:"title"`
	ScheduleID string      `json:"scheduleId,omitempty"`
	Trigger    string      `json:"trigger"` // manual | schedule
	Started    time.Time   `json:"started"`
	Finished   time.Time   `json:"finished,omitempty"`
	Status     string      `json:"status"` // running | done
	Results    []RunResult `json:"results"`
}

// Alert is a raised condition.
type Alert struct {
	ID         string    `json:"id"`
	Rule       string    `json:"rule"`
	Key        string    `json:"key"`
	DeviceID   string    `json:"deviceId"`
	DeviceName string    `json:"deviceName"`
	Severity   string    `json:"severity"` // critical | warning | info
	Title      string    `json:"title"`
	Detail     string    `json:"detail"`
	Opened     time.Time `json:"opened"`
	Resolved   time.Time `json:"resolved,omitempty"`
	Acked      bool      `json:"acked"`
}

// Package is a deployable piece of software.
type Package struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Type      string    `json:"type"`         // winget | apt | upload
	OS        string    `json:"os,omitempty"` // linux for apt packages and .deb uploads (empty = Windows)
	WingetID  string    `json:"wingetId,omitempty"`
	Version   string    `json:"version,omitempty"`
	Filename  string    `json:"filename,omitempty"`
	Kind      string    `json:"kind,omitempty"` // msi | exe
	SHA256    string    `json:"sha256,omitempty"`
	Size      int64     `json:"size,omitempty"`
	Args      string    `json:"args,omitempty"` // silent arguments
	CreatedAt time.Time `json:"createdAt"`
}

// SessionRec is one remote session (screen, terminal, file transfer, RDP tunnel).
type SessionRec struct {
	ID         string    `json:"id"`
	DeviceID   string    `json:"deviceId"`
	DeviceName string    `json:"deviceName"`
	Kind       string    `json:"kind"`
	Started    time.Time `json:"started"`
	Ended      time.Time `json:"ended,omitempty"`
	ViewOnly   bool      `json:"viewOnly,omitempty"`
	IP         string    `json:"ip"`
	Result     string    `json:"result"` // active | ended | refused
	Detail     string    `json:"detail,omitempty"`
}

type dbData struct {
	Settings  Settings             `json:"settings"`
	Scripts   map[string]*Script   `json:"scripts"`
	Schedules map[string]*Schedule `json:"schedules"`
	Runs      []*Run               `json:"runs"`
	Alerts    []*Alert             `json:"alerts"`
	Scans     map[string]*Scan     `json:"scans"`
	Packages  map[string]*Package  `json:"packages"`
	Sessions  []*SessionRec        `json:"sessions"`
	Seen      map[string]time.Time `json:"seen,omitempty"`
	Inventory map[string]*InvRec   `json:"inventory,omitempty"`
	Accepted  map[string]AcceptRec `json:"accepted,omitempty"` // finding key -> accepted risk
	NoFix     map[string]time.Time `json:"noFix,omitempty"`    // "deviceID|software" -> when an update was found to be unavailable
	Tasks     []TaskRec            `json:"tasks,omitempty"`    // finished tasks of the last week
	Patched   map[string]string    `json:"patched,omitempty"`  // device id -> date (YYYY-MM-DD) of its last window run
}

// AcceptRec records a finding the administrator has chosen to live with.
type AcceptRec struct {
	Note string    `json:"note"`
	At   time.Time `json:"at"`
}

// InvRec is the last hardware/OS inventory reported by a device, kept so it stays visible while the PC is offline.
type InvRec struct {
	At   time.Time       `json:"at"`
	Data json.RawMessage `json:"data"`
}

// DB persists the application data in db.json (debounced writes).
type DB struct {
	mu    sync.RWMutex
	path  string
	d     dbData
	dirty bool
	kick  chan struct{}
	stop  chan struct{}
	done  chan struct{}
}

const (
	maxRuns     = 300
	maxAlerts   = 600
	maxSessions = 2000
)

// OpenDB loads (or creates) db.json inside dir.
func OpenDB(dir string) (*DB, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	db := &DB{path: filepath.Join(dir, "db.json"), kick: make(chan struct{}, 1), stop: make(chan struct{}), done: make(chan struct{})}
	db.d = dbData{Settings: defaultSettings()}
	if b, err := os.ReadFile(db.path); err == nil {
		if err := json.Unmarshal(b, &db.d); err != nil {
			return nil, err
		}
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	db.d.normalize()
	go db.saver()
	return db, nil
}

func (db *DB) saver() {
	defer close(db.done)
	for {
		select {
		case <-db.kick:
			select { // debounce
			case <-time.After(2 * time.Second):
			case <-db.stop:
				return
			}
			db.flush()
		case <-db.stop:
			return
		}
	}
}

func (db *DB) flush() {
	db.mu.Lock()
	defer db.mu.Unlock()
	if !db.dirty {
		return
	}
	b, err := json.Marshal(&db.d)
	if err != nil {
		return
	}
	tmp := db.path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return
	}
	_, werr := f.Write(b)
	serr := f.Sync()
	cerr := f.Close()
	if werr != nil || serr != nil || cerr != nil {
		return
	}
	if os.Rename(tmp, db.path) == nil {
		db.dirty = false
	}
}

// Close flushes pending changes and stops the saver.
func (db *DB) Close() {
	select {
	case <-db.stop:
		return
	default:
	}
	close(db.stop)
	<-db.done
	db.flush()
}

// update runs fn under the write lock and schedules a save.
func (db *DB) update(fn func(d *dbData)) {
	db.mu.Lock()
	fn(&db.d)
	db.dirty = true
	db.mu.Unlock()
	select {
	case db.kick <- struct{}{}:
	default:
	}
}

// view runs fn under the read lock.
func (db *DB) view(fn func(d *dbData)) {
	db.mu.RLock()
	fn(&db.d)
	db.mu.RUnlock()
}

func (db *DB) settings() Settings {
	var s Settings
	db.view(func(d *dbData) {
		s = d.Settings
		s.Rules = map[string]bool{}
		for k, v := range d.Settings.Rules {
			s.Rules[k] = v
		}
	})
	return s
}

// ---- helpers over the capped slices ----

func (db *DB) addRun(r *Run) {
	db.update(func(d *dbData) {
		d.Runs = append(d.Runs, r)
		if len(d.Runs) > maxRuns {
			d.Runs = d.Runs[len(d.Runs)-maxRuns:]
		}
	})
}

func (db *DB) runs(limit int) []Run {
	var out []Run
	db.view(func(d *dbData) {
		for i := len(d.Runs) - 1; i >= 0 && len(out) < limit; i-- {
			out = append(out, *d.Runs[i])
		}
	})
	return out
}

func sortedSchedules(m map[string]*Schedule) []Schedule {
	out := make([]Schedule, 0, len(m))
	for _, s := range m {
		out = append(out, *s)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Created.Before(out[j].Created) })
	return out
}

// normalize fills defaults and nil maps (after loading or restoring).
func (d *dbData) normalize() {
	def := defaultSettings()
	if d.Settings.Rules == nil {
		d.Settings.Rules = map[string]bool{}
	}
	for k, v := range def.Rules {
		if _, ok := d.Settings.Rules[k]; !ok {
			d.Settings.Rules[k] = v
		}
	}
	if d.Settings.OfflineMinutes == 0 {
		d.Settings.OfflineMinutes = def.OfflineMinutes
	}
	if d.Settings.DiskFreePct == 0 {
		d.Settings.DiskFreePct = def.DiskFreePct
	}
	if d.Settings.ScanEveryHours == 0 {
		d.Settings.ScanEveryHours = def.ScanEveryHours
	}
	if d.Scripts == nil {
		d.Scripts = map[string]*Script{}
	}
	if d.Schedules == nil {
		d.Schedules = map[string]*Schedule{}
	}
	if d.Inventory == nil {
		d.Inventory = map[string]*InvRec{}
	}
	if d.Scans == nil {
		d.Scans = map[string]*Scan{}
	}
	if d.Packages == nil {
		d.Packages = map[string]*Package{}
	}
}
