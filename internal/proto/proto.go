// Package proto defines the wire protocol shared by the Helm server and agent.
package proto

import "encoding/json"

// Frame types sent on the agent control WebSocket.
const (
	THello    = "hello"    // agent -> server, Data = Hello
	TStats    = "stats"    // agent -> server, Data = Stats
	TResult   = "result"   // agent -> server, answers a cmd
	TProgress = "progress" // agent -> server, progress text for a cmd
	TCmd      = "cmd"      // server -> agent
	TOpen     = "open"     // server -> agent: open a data channel
	TApproved = "approved" // server -> agent
	TRevoked  = "revoked"  // server -> agent
	TOpenFail = "openfail" // agent -> server: refused a TOpen (SID, Err)
)

// Channel kinds opened with TOpen.
const (
	KindScreen   = "screen"
	KindTerminal = "term"
	KindDownload = "filedl"
	KindUpload   = "fileul"
	KindTCP      = "tcp" // tunnel to the local RDP port
)

// Frame is the JSON envelope used on control and data channels.
type Frame struct {
	T    string          `json:"t"`
	ID   string          `json:"id,omitempty"`
	Name string          `json:"name,omitempty"`
	Kind string          `json:"kind,omitempty"`
	SID  string          `json:"sid,omitempty"`
	Args json.RawMessage `json:"args,omitempty"`
	Data json.RawMessage `json:"data,omitempty"`
	Err  string          `json:"err,omitempty"`
	Msg  string          `json:"msg,omitempty"`
	Pct  int             `json:"pct,omitempty"`
}

// Hello describes an agent and its machine.
type Hello struct {
	Version     string   `json:"version"`
	Hostname    string   `json:"hostname"`
	OS          string   `json:"os"`
	OSVersion   string   `json:"osVersion"`
	Edition     string   `json:"edition"`
	Arch        string   `json:"arch"`
	User        string   `json:"user"`
	MACs        []string `json:"macs"`
	IPs         []string `json:"ips"`
	ConsentMode string   `json:"consentMode"`
	CanRDP      bool     `json:"canRdp"`
}

// Disk is one fixed drive.
type Disk struct {
	Name  string `json:"name"`
	Total uint64 `json:"total"`
	Free  uint64 `json:"free"`
}

// Stats is the periodic heartbeat payload.
type Stats struct {
	CPU         float64 `json:"cpu"`
	MemUsed     uint64  `json:"memUsed"`
	MemTotal    uint64  `json:"memTotal"`
	Disks       []Disk  `json:"disks"`
	UptimeSec   uint64  `json:"uptimeSec"`
	User        string  `json:"user"`
	UserPresent bool    `json:"userPresent"`
}

// Enrollment request / response (HTTP, before the WebSocket is used).
type EnrollRequest struct {
	Token string `json:"token"`
	Hello Hello  `json:"hello"`
}

type EnrollResponse struct {
	DeviceID string `json:"deviceId"`
	Secret   string `json:"secret"`
}

// UpdateInfo is returned by /api/agent/update.
type UpdateInfo struct {
	Version string `json:"version"`
	URL     string `json:"url"`
	SHA256  string `json:"sha256"`
	Sig     string `json:"sig"` // base64 ed25519 over SignedMessage
}

// SignedMessage is the exact byte string covered by a release signature.
func SignedMessage(version, goos, arch, sha256hex string) []byte {
	return []byte("helm-agent\n" + version + "\n" + goos + "\n" + arch + "\n" + sha256hex)
}

// Command argument types shared between UI, server and agent.

type PowerArgs struct {
	Action  string `json:"action"` // shutdown, restart, sleep, hibernate, lock, logoff, cancel
	Delay   int    `json:"delay"`  // seconds, for shutdown/restart
	Message string `json:"message"`
	Force   bool   `json:"force"`
}

type ExecArgs struct {
	Script  string `json:"script"`
	Shell   string `json:"shell"` // powershell (default) or cmd
	Timeout int    `json:"timeout"`
}

type ExecResult struct {
	Stdout   string `json:"stdout"`
	Stderr   string `json:"stderr"`
	ExitCode int    `json:"exitCode"`
	TimedOut bool   `json:"timedOut"`
}

type FileEntry struct {
	Name  string `json:"name"`
	Dir   bool   `json:"dir"`
	Size  int64  `json:"size"`
	MTime int64  `json:"mtime"`
}

// OpenArgs are the arguments of a TOpen frame (per kind).
type OpenArgs struct {
	ViewOnly  bool   `json:"viewOnly,omitempty"`  // screen
	Shell     string `json:"shell,omitempty"`     // term
	Path      string `json:"path,omitempty"`      // filedl / fileul
	Size      int64  `json:"size,omitempty"`      // fileul
	Overwrite bool   `json:"overwrite,omitempty"` // fileul
}
