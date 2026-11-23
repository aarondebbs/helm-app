package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
	"time"
)

// ---- scan data (raw facts collected by the agent) ----

type SoftwareItem struct {
	Name        string `json:"name"`
	Version     string `json:"version"`
	Publisher   string `json:"publisher"`
	InstallDate string `json:"installDate"`
	Scope       string `json:"scope"`
}

type ConfigCheck struct {
	ID       string `json:"id"`
	Title    string `json:"title"`
	Category string `json:"category"`
	Severity string `json:"severity"`
	Status   string `json:"status"` // pass | fail | warn | na
	Detail   string `json:"detail"`
	Fix      string `json:"fix"`
}

type PortItem struct {
	Proto   string `json:"proto"`
	Address string `json:"address"`
	Port    int    `json:"port"`
	PID     int    `json:"pid"`
	Process string `json:"process"`
}

type Patch struct {
	ID       string   `json:"id"`
	Title    string   `json:"title"`
	KB       []string `json:"kb"`
	SizeMB   float64  `json:"sizeMB"`
	Severity string   `json:"severity"`
	Cats     []string `json:"categories"`
}

// Scan holds the raw facts of the latest scan of a device. Findings are derived on demand so that
// they improve as the CVE cache fills.
type Scan struct {
	DeviceID      string         `json:"deviceId"`
	At            time.Time      `json:"at"`
	Finished      time.Time      `json:"finished,omitempty"`
	Status        string         `json:"status"` // running | done | partial | failed
	Errors        []string       `json:"errors,omitempty"`
	Build         int            `json:"build"`
	Edition       string         `json:"edition"`
	Software      []SoftwareItem `json:"software"`
	Checks        []ConfigCheck  `json:"checks"`
	Ports         []PortItem     `json:"ports"`
	Patches       []Patch        `json:"patches"`
	RebootPending bool           `json:"rebootPending"`
	HaveSoftware  bool           `json:"haveSoftware"`
	HaveChecks    bool           `json:"haveChecks"`
	HavePorts     bool           `json:"havePorts"`
	HavePatches   bool           `json:"havePatches"`
}

func (sc *Scan) hasData() bool {
	return sc.HaveSoftware || sc.HaveChecks || sc.HavePorts || sc.HavePatches
}

// Finding is a derived problem.
type Finding struct {
	Key       string  `json:"key"`  // stable across devices (CVE+software, check id, port, patch title)
	Kind      string  `json:"kind"` // cve | config | port | patch
	Severity  string  `json:"severity"`
	Title     string  `json:"title"`
	Detail    string  `json:"detail"`
	Fix       string  `json:"fix,omitempty"`
	CVE       string  `json:"cve,omitempty"`
	Score     float64 `json:"score,omitempty"`
	Software  string  `json:"software,omitempty"`
	Version   string  `json:"version,omitempty"`
	Exploited bool    `json:"exploited,omitempty"`
	Cat       string  `json:"category,omitempty"`
	Accepted  bool    `json:"accepted,omitempty"` // risk accepted by the admin: shown, but not counted or scored
	NoFix     bool    `json:"noFix,omitempty"`    // an update was tried and the vendor has not published a fix
}

// ScanView is what the API returns for a device.
type ScanView struct {
	*Scan
	Findings    []Finding      `json:"findings"`
	Score       int            `json:"score"` // 100 = nothing found
	Counts      map[string]int `json:"counts"`
	Assessed    int            `json:"assessed"`    // programs matched to a known product
	Pending     int            `json:"pending"`     // programs whose CVE data is still downloading
	Unavailable int            `json:"unavailable"` // programs whose CVE data could not be downloaded (NVD unreachable)
	Unassessed  int            `json:"unassessed"`  // programs that could not be identified
	HasData     bool           `json:"hasData"`
}

var sevRank = map[string]int{"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}

var riskyPorts = map[int]struct {
	Name string
	Sev  string
	Note string
}{
	21:    {"FTP", "high", "Unencrypted file transfer."},
	23:    {"Telnet", "critical", "Unencrypted remote shell."},
	69:    {"TFTP", "high", "Unauthenticated file transfer."},
	135:   {"RPC endpoint mapper", "low", "Normal on Windows; make sure the firewall blocks it from untrusted networks."},
	139:   {"NetBIOS session", "medium", "Legacy file sharing; block it from untrusted networks."},
	445:   {"SMB file sharing", "medium", "Reachable file sharing; block it from untrusted networks."},
	1433:  {"Microsoft SQL Server", "high", "Database listening on the network."},
	1521:  {"Oracle database", "high", "Database listening on the network."},
	3306:  {"MySQL", "high", "Database listening on the network."},
	3389:  {"Remote Desktop", "medium", "Remote Desktop is reachable; use a VPN or limit it by firewall."},
	5432:  {"PostgreSQL", "high", "Database listening on the network."},
	5900:  {"VNC", "high", "Remote control service with weak default security."},
	5985:  {"WinRM (HTTP)", "medium", "Remote management is reachable."},
	6379:  {"Redis", "high", "Database that is often unauthenticated."},
	27017: {"MongoDB", "high", "Database listening on the network."},
	2375:  {"Docker API (no TLS)", "critical", "Unauthenticated control of the Docker daemon."},
	9200:  {"Elasticsearch", "high", "Search database that is often unauthenticated."},
	11211: {"Memcached", "high", "Cache server that must not face the network."},
}

func isLoopback(addr string) bool {
	ip := net.ParseIP(strings.Trim(addr, "[]"))
	return ip != nil && ip.IsLoopback()
}

// computeFindings derives findings and the score from raw scan facts.
func (s *Server) computeFindings(sc *Scan) ScanView {
	var accepted map[string]AcceptRec
	var noFix map[string]time.Time
	if s.db != nil {
		s.db.view(func(x *dbData) { accepted, noFix = x.Accepted, x.NoFix })
	}
	isAccepted := func(key string) bool { _, ok := accepted[key]; return ok }
	// JSON null breaks list rendering in the UI; always send arrays.
	if sc.Software == nil {
		sc.Software = []SoftwareItem{}
	}
	if sc.Checks == nil {
		sc.Checks = []ConfigCheck{}
	}
	if sc.Ports == nil {
		sc.Ports = []PortItem{}
	}
	if sc.Patches == nil {
		sc.Patches = []Patch{}
	}
	if sc.Errors == nil {
		sc.Errors = []string{}
	}
	v := ScanView{Scan: sc, HasData: sc.hasData(), Counts: map[string]int{"critical": 0, "high": 0, "medium": 0, "low": 0}}
	var out []Finding
	penalty := 0.0

	// configuration
	for _, c := range sc.Checks {
		sev := ""
		switch c.Status {
		case "fail":
			sev = c.Severity
		case "warn":
			sev = "low"
			if c.Severity == "high" || c.Severity == "critical" {
				sev = "medium"
			}
		default:
			continue
		}
		prefix := "Not compliant: "
		if c.Status == "warn" {
			prefix = "Review: "
		}
		out = append(out, Finding{Key: "cfg:" + c.ID, Kind: "config", Severity: sev, Title: prefix + c.Title, Detail: c.Detail, Fix: c.Fix, Cat: c.Category})
	}
	// ports
	for _, p := range sc.Ports {
		info, ok := riskyPorts[p.Port]
		if !ok || isLoopback(p.Address) {
			continue
		}
		out = append(out, Finding{Key: fmt.Sprintf("port:%d", p.Port), Kind: "port", Severity: info.Sev,
			Title:  fmt.Sprintf("%s is listening on port %d", info.Name, p.Port),
			Detail: fmt.Sprintf("%s (process %s). %s", p.Address, orDash(p.Process), info.Note),
			Fix:    "Close the service if unused, or block the port in the firewall.", Cat: "Exposure"})
	}
	// missing patches: Windows updates are listed one by one; Linux and macOS package updates are grouped,
	// because a server can easily have dozens and one row per package buries everything else.
	var pkgNames []string
	pkgSev := "low"
	rank := map[string]int{"low": 0, "medium": 1, "high": 2, "critical": 3}
	for _, p := range sc.Patches {
		sev := map[string]string{"critical": "critical", "important": "high", "moderate": "medium", "low": "low"}[strings.ToLower(p.Severity)]
		if sev == "" {
			sev = "medium"
			secCat := false
			for _, c := range p.Cats {
				if strings.Contains(strings.ToLower(c), "security") {
					secCat = true
				}
			}
			if !secCat {
				sev = "low"
			}
		}
		if len(p.KB) == 0 { // Linux and macOS updates have no KB number
			pkgNames = append(pkgNames, p.Title)
			if rank[sev] > rank[pkgSev] {
				pkgSev = sev
			}
			continue
		}
		out = append(out, Finding{Key: "patch:" + p.Title, Kind: "patch", Severity: sev, Title: "Missing update: " + p.Title,
			Detail: "A Windows update is available but not installed.", Fix: "Install it from the Updates tab.", Cat: "Patching"})
	}
	if n := len(pkgNames); n > 0 {
		sort.Strings(pkgNames)
		shown := pkgNames
		more := ""
		if n > 6 {
			shown, more = pkgNames[:6], fmt.Sprintf(" and %d more", n-6)
		}
		title := fmt.Sprintf("%d package updates are waiting", n)
		if n == 1 {
			title = "1 package update is waiting"
		}
		out = append(out, Finding{Key: "patch:packages", Kind: "patch", Severity: pkgSev, Title: title,
			Detail: strings.Join(shown, ", ") + more + ".", Fix: "Install them from the Updates tab, or let the patch window do it.", Cat: "Patching"})
	}
	// CVEs
	if s.cve != nil {
		seenSoft := map[string]bool{}
		nvdDown := s.cve.status().LastError != ""
		for _, sw := range sc.Software {
			vendor, product, ver, pending := s.cve.resolveSoftware(sw)
			dedup := sw.Name + "|" + sw.Version
			if seenSoft[dedup] {
				continue
			}
			seenSoft[dedup] = true
			if pending {
				if nvdDown {
					v.Unavailable++
				} else {
					v.Pending++
				}
				continue
			}
			if vendor == "" {
				v.Unassessed++
				continue
			}
			recs, cached := s.cve.matchCVEs(vendor, product, ver)
			if !cached {
				if nvdDown {
					v.Unavailable++
				} else {
					v.Pending++
				}
				continue
			}
			v.Assessed++
			swPenalty := 0.0
			for i, r := range recs {
				if i >= 40 { // keep the list readable; the count is in the first finding's detail
					break
				}
				f := Finding{Key: "cve:" + r.ID + "|" + sw.Name, Kind: "cve", Severity: r.Sev, CVE: r.ID, Score: r.Score,
					Title: r.ID + " in " + sw.Name, Detail: r.Sum, Software: sw.Name, Version: sw.Version, Exploited: r.KEV, Cat: "Vulnerable software",
					Fix: "Update " + sw.Name + " to the latest version."}
				if r.KEV {
					f.Title += " (actively exploited)"
				}
				f.NoFix = !noFix[sc.DeviceID+"|"+sw.Name].IsZero()
				f.Accepted = isAccepted(f.Key)
				out = append(out, f)
				if f.Accepted {
					continue
				}
				swPenalty += sevPenalty(r.Sev)
				if r.KEV {
					swPenalty += 8
				}
			}
			if len(recs) > 40 {
				out = append(out, Finding{Key: "cve:more|" + sw.Name, Kind: "cve", Severity: "info", Software: sw.Name, Version: sw.Version,
					Title: fmt.Sprintf("%d more CVEs in %s", len(recs)-40, sw.Name), Detail: "Only the 40 most severe are listed.", Cat: "Vulnerable software"})
			}
			if swPenalty > 30 { // one old program must not zero the score on its own
				swPenalty = 30
			}
			penalty += swPenalty
		}
	}
	for i := range out {
		f := &out[i]
		if f.Kind != "cve" {
			f.Accepted = isAccepted(f.Key)
		}
		if f.Accepted {
			continue
		}
		if f.Kind != "cve" {
			penalty += sevPenalty(f.Severity)
		}
		if _, ok := v.Counts[f.Severity]; ok {
			v.Counts[f.Severity]++
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		if sevRank[out[i].Severity] != sevRank[out[j].Severity] {
			return sevRank[out[i].Severity] > sevRank[out[j].Severity]
		}
		if out[i].Exploited != out[j].Exploited {
			return out[i].Exploited
		}
		return out[i].Score > out[j].Score
	})
	sc2 := 100 - int(penalty+0.5)
	if sc2 < 0 {
		sc2 = 0
	}
	v.Score = sc2
	v.Findings = out
	if v.Findings == nil {
		v.Findings = []Finding{}
	}
	return v
}

func sevPenalty(sev string) float64 {
	switch sev {
	case "critical":
		return 12
	case "high":
		return 6
	case "medium":
		return 2
	case "low":
		return 0.5
	}
	return 0
}

func orDash(s string) string {
	if s == "" {
		return "–"
	}
	return s
}

// ---- running a scan ----

var scanMu sync.Mutex

func (s *Server) callCmd(deviceID, name string, args json.RawMessage, actor string) (json.RawMessage, error) {
	j, err := s.hub.dispatch(deviceID, name, args, actor)
	if err != nil {
		return nil, err
	}
	spec := commands[name]
	j = s.hub.wait(j.ID, spec.Timeout+15*time.Second)
	if j == nil {
		return nil, errors.New("job vanished")
	}
	if j.Status != "ok" {
		if j.Err == "" {
			j.Err = "no result"
		}
		return nil, errors.New(j.Err)
	}
	return j.Data, nil
}

// startScan launches a scan in the background. It returns an error if one is already running.
func (s *Server) startScan(deviceID, actor string) error {
	d, ok := s.st.device(deviceID)
	if !ok || !d.Approved {
		return errors.New("no such approved device")
	}
	if s.hub.online(deviceID) == nil {
		return errOffline
	}
	scanMu.Lock()
	defer scanMu.Unlock()
	busy := false
	s.db.view(func(x *dbData) {
		if sc := x.Scans[deviceID]; sc != nil && sc.Status == "running" && time.Since(sc.At) < 25*time.Minute {
			busy = true
		}
	})
	if busy {
		return errors.New("a scan is already running on this PC")
	}
	s.db.update(func(x *dbData) {
		n := &Scan{DeviceID: deviceID, At: time.Now().UTC(), Status: "running"}
		if old := x.Scans[deviceID]; old != nil && old.hasData() {
			cp := *old // keep showing the previous results while the rescan runs
			cp.At, cp.Status = n.At, "running"
			n = &cp
		}
		x.Scans[deviceID] = n
	})
	go s.collectScan(deviceID, actor)
	return nil
}

func (s *Server) collectScan(deviceID, actor string) {
	sc := &Scan{DeviceID: deviceID, At: time.Now().UTC()}
	tid := "scan-" + randHex(6)
	s.taskStart(tid, "scan", "Security scan", deviceID, actor)
	s.taskUpdate(tid, 0, "Starting scan")
	var mu sync.Mutex
	steps := 0
	var wg sync.WaitGroup
	addErr := func(what string, err error) {
		mu.Lock()
		sc.Errors = append(sc.Errors, what+": "+err.Error())
		mu.Unlock()
	}
	run := func(name string, fn func(raw json.RawMessage) error) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			raw, err := s.callCmd(deviceID, name, nil, actor)
			if err == nil {
				mu.Lock()
				err = fn(raw)
				mu.Unlock()
			}
			if err != nil {
				addErr(name, err)
			}
			mu.Lock()
			steps++
			n := steps
			mu.Unlock()
			label := map[string]string{"scan.software": "Software inventory", "scan.config": "Configuration checks", "scan.ports": "Open ports"}[name]
			msg := label + " done"
			if err != nil {
				msg = label + " failed: " + firstLine(err.Error(), 120)
			}
			s.taskUpdate(tid, n*20, msg)
		}()
	}
	run("scan.software", func(raw json.RawMessage) error {
		sc.HaveSoftware = true
		return json.Unmarshal(raw, &sc.Software)
	})
	run("scan.config", func(raw json.RawMessage) error {
		var c struct {
			Build   int           `json:"build"`
			Edition string        `json:"edition"`
			Checks  []ConfigCheck `json:"checks"`
		}
		if err := json.Unmarshal(raw, &c); err != nil {
			return err
		}
		sc.Build, sc.Edition, sc.Checks, sc.HaveChecks = c.Build, c.Edition, c.Checks, true
		return nil
	})
	run("scan.ports", func(raw json.RawMessage) error {
		sc.HavePorts = true
		return json.Unmarshal(raw, &sc.Ports)
	})
	wg.Wait()
	s.taskUpdate(tid, 60, "Checking for missing updates")
	if raw, err := s.callCmd(deviceID, "updates.check", nil, actor); err != nil {
		addErr("updates.check", err)
	} else {
		var u struct {
			Updates       []Patch `json:"updates"`
			RebootPending bool    `json:"rebootPending"`
		}
		if err := json.Unmarshal(raw, &u); err != nil {
			addErr("updates.check", err)
		} else {
			sc.Patches, sc.RebootPending, sc.HavePatches = u.Updates, u.RebootPending, true
		}
	}
	s.taskUpdate(tid, 90, "Matching known vulnerabilities")
	defer func() {
		msg := ""
		if len(sc.Errors) > 0 && !sc.HaveSoftware && !sc.HaveChecks && !sc.HavePorts && !sc.HavePatches {
			msg = sc.Errors[0]
		}
		s.taskFinish(tid, msg)
	}()
	sc.Finished = time.Now().UTC()
	switch {
	case !sc.HaveSoftware && !sc.HaveChecks && !sc.HavePorts && !sc.HavePatches:
		sc.Status = "failed"
	case len(sc.Errors) > 0:
		sc.Status = "partial"
	default:
		sc.Status = "done"
	}
	s.db.update(func(x *dbData) { x.Scans[deviceID] = sc })
	s.audit.add(AuditEntry{Time: time.Now().UTC(), Action: "scan_finished", Device: deviceID, Detail: sc.Status, IP: actor})
}

func (s *Server) scanView(deviceID string) (ScanView, bool) {
	var sc *Scan
	s.db.view(func(x *dbData) {
		if c := x.Scans[deviceID]; c != nil {
			cp := *c
			sc = &cp
		}
	})
	if sc == nil {
		return ScanView{}, false
	}
	return s.computeFindings(sc), true
}
