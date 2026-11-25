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
	TConfig   = "config"   // server -> agent: deploy profile (Data is a Config)
	TSupport  = "support"  // agent -> server: the person at the PC asked for help (Msg)
	TChat     = "chat"     // both ways: a chat message (Msg); server -> agent carries the message ID in ID
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
	Chassis     string   `json:"chassis,omitempty"` // pi | laptop | desktop | vm | server
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

// Config is the deploy profile the server sends to an agent each time it connects.
// It only changes how the agent presents itself on the PC; it carries no secrets.
type Config struct {
	Org          string `json:"org,omitempty"`         // organisation name shown in the tray menu
	SupportText  string `json:"supportText,omitempty"` // how to reach whoever supports this PC
	ShowTray     bool   `json:"showTray"`              // show the icon in the notification area (Windows)
	AllowSupport bool   `json:"allowSupport"`          // the tray menu offers "Request support"
	PortalURL    string `json:"portalUrl,omitempty"`
	Accent       string `json:"accent,omitempty"` // brand colour as #rrggbb, used in the chat window
	Logo         string `json:"logo,omitempty"`   // PNG, base64; only on the wire, the agent keeps it in memory
}

// Sanitize bounds everything an agent reports about itself, so a misbehaving or hostile agent cannot bloat the
// server's state or smuggle control characters into logs and reports. It returns the cleaned copy.
func (h Hello) Sanitize() Hello {
	cut := func(s string, n int) string {
		r := []rune(s)
		if len(r) > n {
			r = r[:n]
		}
		out := make([]rune, 0, len(r))
		for _, c := range r {
			if c >= 0x20 && c != 0x7f {
				out = append(out, c)
			}
		}
		return string(out)
	}
	list := func(in []string, items, n int) []string {
		var out []string
		for _, s := range in {
			if len(out) >= items {
				break
			}
			if s = cut(s, n); s != "" {
				out = append(out, s)
			}
		}
		return out
	}
	h.Version, h.Hostname, h.OS, h.OSVersion = cut(h.Version, 40), cut(h.Hostname, 100), cut(h.OS, 20), cut(h.OSVersion, 80)
	h.Edition, h.Arch, h.User, h.ConsentMode = cut(h.Edition, 80), cut(h.Arch, 20), cut(h.User, 100), cut(h.ConsentMode, 30)
	if h.Chassis != "pi" && h.Chassis != "laptop" && h.Chassis != "desktop" && h.Chassis != "vm" && h.Chassis != "server" {
		h.Chassis = ""
	}
	h.MACs, h.IPs = list(h.MACs, 16, 40), list(h.IPs, 32, 64)
	return h
}
