package server

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"helm/internal/proto"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"
)

type secSummary struct {
	Score     int            `json:"score"`
	Counts    map[string]int `json:"counts"`
	At        time.Time      `json:"at"`
	Status    string         `json:"status"`
	Pending   int            `json:"pending"`
	HasData   bool           `json:"hasData"`
	Exploited int            `json:"exploited"`
}

func (s *Server) secSummaryFor(id string) *secSummary {
	v, ok := s.scanView(id)
	if !ok {
		return nil
	}
	ex := 0
	for _, f := range v.Findings {
		if f.Exploited && !f.Accepted {
			ex++
		}
	}
	return &secSummary{HasData: v.HasData, Score: v.Score, Counts: v.Counts, At: v.At, Status: v.Status, Pending: v.Pending, Exploited: ex}
}

func (s *Server) handleDeviceScan(w http.ResponseWriter, r *http.Request, sess *session) {
	v, ok := s.scanView(r.PathValue("id"))
	if !ok {
		writeJSON(w, 200, nil)
		return
	}
	writeJSON(w, 200, v)
}

func (s *Server) handleDeviceScanStart(w http.ResponseWriter, r *http.Request, sess *session) {
	id := r.PathValue("id")
	if err := s.startScan(id, "admin"); err != nil {
		writeErr(w, 409, err.Error())
		return
	}
	s.record(r, "scan_started", id, "")
	writeJSON(w, 200, map[string]bool{"ok": true})
}

func (s *Server) handleDeviceHistory(w http.ResponseWriter, r *http.Request, sess *session) {
	writeJSON(w, 200, s.hist.get(r.PathValue("id")))
}

// ---- fleet security ----

type fleetFinding struct {
	Finding
	Devices []struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	} `json:"devices"`
}

func (s *Server) handleFleetSecurity(w http.ResponseWriter, r *http.Request, sess *session) {
	agg := map[string]*fleetFinding{}
	var order []string
	type devRow struct {
		ID, Name, Group string
		Online          bool
		*secSummary
	}
	rows := []map[string]any{}
	pend, unass, assessed, scanned, total, unavail := 0, 0, 0, 0, 0, 0
	online := s.hub.onlineIDs()
	for _, d := range s.st.devices() {
		if !d.Approved {
			continue
		}
		total++
		v, ok := s.scanView(d.ID)
		if !ok {
			rows = append(rows, map[string]any{"id": d.ID, "name": d.Name, "group": d.Group, "online": online[d.ID] != nil, "security": nil})
			continue
		}
		scanned++
		pend += v.Pending
		unavail += v.Unavailable
		unass += v.Unassessed
		assessed += v.Assessed
		rows = append(rows, map[string]any{"id": d.ID, "name": d.Name, "group": d.Group, "online": online[d.ID] != nil, "security": s.secSummaryFor(d.ID)})
		for _, f := range v.Findings {
			if f.Severity == "info" {
				continue
			}
			ff := agg[f.Key]
			if ff == nil {
				ff = &fleetFinding{Finding: f}
				agg[f.Key] = ff
				order = append(order, f.Key)
			} else if !f.NoFix {
				ff.NoFix = false // only "no update published" when that is true on every affected PC
			}
			ff.Devices = append(ff.Devices, struct {
				ID   string `json:"id"`
				Name string `json:"name"`
			}{d.ID, d.Name})
		}
	}
	list := make([]*fleetFinding, 0, len(order))
	for _, k := range order {
		list = append(list, agg[k])
	}
	sort.SliceStable(list, func(i, j int) bool {
		a, b := list[i], list[j]
		if sevRank[a.Severity] != sevRank[b.Severity] {
			return sevRank[a.Severity] > sevRank[b.Severity]
		}
		if a.Exploited != b.Exploited {
			return a.Exploited
		}
		if len(a.Devices) != len(b.Devices) {
			return len(a.Devices) > len(b.Devices)
		}
		return a.Score > b.Score
	})
	if len(list) > 500 {
		list = list[:500]
	}
	writeJSON(w, 200, map[string]any{"devices": rows, "findings": list, "total": total, "scanned": scanned,
		"pending": pend, "unavailable": unavail, "unassessed": unass, "assessed": assessed, "cve": s.cve.status()})
}

// ---- dashboard ----

func (s *Server) handleDashboard(w http.ResponseWriter, r *http.Request, sess *session) {
	online := s.hub.onlineIDs()
	var total, on, off, pending int
	var scoreSum, scored int
	counts := map[string]int{"critical": 0, "high": 0, "medium": 0, "low": 0}
	buckets := map[string]int{"good": 0, "fair": 0, "poor": 0, "unscanned": 0}
	groups := map[string]int{}
	type lowDisk struct {
		ID, Name, Drive string
		FreePct         int
	}
	var disks []lowDisk
	var cpu, mem float64
	var nstat int
	osCount := map[string]int{}
	worst := []map[string]any{}
	for _, d := range s.st.devices() {
		if !d.Approved {
			pending++
			continue
		}
		total++
		g := d.Group
		if g == "" {
			g = "Ungrouped"
		}
		groups[g]++
		if d.Hello != nil {
			osCount[osLabel(d.Hello.OSVersion, d.Hello.Edition)]++
		}
		if a := online[d.ID]; a != nil {
			on++
			if st, _ := a.stats(); st != nil {
				cpu += st.CPU
				if st.MemTotal > 0 {
					mem += float64(st.MemUsed) / float64(st.MemTotal) * 100
				}
				nstat++
				for _, dk := range st.Disks {
					if dk.Total > 0 && int(dk.Free*100/dk.Total) < 15 {
						disks = append(disks, lowDisk{d.ID, d.Name, dk.Name, int(dk.Free * 100 / dk.Total)})
					}
				}
			}
		} else {
			off++
		}
		if sm := s.secSummaryFor(d.ID); sm != nil && sm.HasData {
			scored++
			scoreSum += sm.Score
			for k, n := range sm.Counts {
				counts[k] += n
			}
			switch {
			case sm.Score >= 80:
				buckets["good"]++
			case sm.Score >= 50:
				buckets["fair"]++
			default:
				buckets["poor"]++
			}
			worst = append(worst, map[string]any{"id": d.ID, "name": d.Name, "score": sm.Score, "critical": sm.Counts["critical"], "high": sm.Counts["high"]})
		} else {
			buckets["unscanned"]++
		}
	}
	sort.Slice(worst, func(i, j int) bool { return worst[i]["score"].(int) < worst[j]["score"].(int) })
	if len(worst) > 5 {
		worst = worst[:5]
	}
	sort.Slice(disks, func(i, j int) bool { return disks[i].FreePct < disks[j].FreePct })
	if len(disks) > 6 {
		disks = disks[:6]
	}
	dl := []map[string]any{}
	for _, d := range disks {
		dl = append(dl, map[string]any{"id": d.ID, "name": d.Name, "drive": d.Drive, "freePct": d.FreePct})
	}
	avgScore := any(nil)
	if scored > 0 {
		avgScore = scoreSum / scored
	}
	avgCPU, avgMem := 0.0, 0.0
	if nstat > 0 {
		avgCPU, avgMem = cpu/float64(nstat), mem/float64(nstat)
	}
	openAlerts := []Alert{}
	s.db.view(func(d *dbData) {
		for i := len(d.Alerts) - 1; i >= 0 && len(openAlerts) < 6; i-- {
			if d.Alerts[i].Resolved.IsZero() {
				openAlerts = append(openAlerts, *d.Alerts[i])
			}
		}
	})
	recentRuns := []Run{}
	s.db.view(func(d *dbData) {
		for i := len(d.Runs) - 1; i >= 0 && len(recentRuns) < 5; i-- {
			cp := *d.Runs[i]
			cp.Results = nil
			recentRuns = append(recentRuns, cp)
		}
	})
	writeJSON(w, 200, map[string]any{
		"total": total, "online": on, "offline": off, "pending": pending,
		"avgScore": avgScore, "scored": scored, "counts": counts, "buckets": buckets,
		"groups": groups, "os": osCount, "lowDisks": dl, "worst": worst,
		"avgCpu": avgCPU, "avgMem": avgMem, "alerts": openAlerts, "runs": recentRuns,
		"cve": s.cve.status(),
	})
}

func osLabel(ver, edition string) string {
	switch {
	case strings.Contains(ver, "10.0.2"):
		return "Windows 11"
	case strings.Contains(ver, "10.0.1"):
		return "Windows 10"
	case ver == "":
		return "Unknown"
	}
	return "Windows"
}

// ---- reports ----

func csvOut(w http.ResponseWriter, name string, rows [][]string) {
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="`+name+`-`+time.Now().Format("2006-01-02")+`.csv"`)
	w.Write([]byte("\xef\xbb\xbf")) // BOM so Excel reads UTF-8
	cw := csv.NewWriter(w)
	for _, r := range rows {
		for i, c := range r { // neutralise spreadsheet formula injection
			if len(c) > 0 && strings.ContainsAny(c[:1], "=+-@\t\r") {
				r[i] = "'" + c
			}
		}
		_ = cw.Write(r)
	}
	cw.Flush()
}

func (s *Server) handleReport(w http.ResponseWriter, r *http.Request, sess *session) {
	kind := r.PathValue("kind")
	online := s.hub.onlineIDs()
	switch kind {
	case "inventory":
		rows := [][]string{{"Name", "Group", "Tags", "Status", "Last seen", "Last IP", "Hostname", "OS", "Edition", "Arch", "Agent", "User", "CPU %", "Memory %", "Notes"}}
		for _, d := range s.st.devices() {
			if !d.Approved {
				continue
			}
			h := d.Hello
			if h == nil {
				h = &helloZero
			}
			st := "offline"
			cpu, mem := "", ""
			if a := online[d.ID]; a != nil {
				st = "online"
				if x, _ := a.stats(); x != nil {
					cpu = fmt.Sprintf("%.0f", x.CPU)
					if x.MemTotal > 0 {
						mem = fmt.Sprintf("%.0f", float64(x.MemUsed)/float64(x.MemTotal)*100)
					}
				}
			}
			rows = append(rows, []string{d.Name, d.Group, strings.Join(d.Tags, ";"), st, d.LastSeen.Format(time.RFC3339), d.LastIP,
				h.Hostname, h.OSVersion, h.Edition, h.Arch, h.Version, h.User, cpu, mem, d.Notes})
		}
		csvOut(w, "helm-inventory", rows)
	case "vulnerabilities":
		rows := [][]string{{"PC", "Group", "Severity", "Type", "CVE", "CVSS", "Actively exploited", "Software", "Version", "Title", "Detail", "Fix"}}
		for _, d := range s.st.devices() {
			if !d.Approved {
				continue
			}
			v, ok := s.scanView(d.ID)
			if !ok {
				continue
			}
			for _, f := range v.Findings {
				ex := ""
				if f.Exploited {
					ex = "yes"
				}
				sc := ""
				if f.Score > 0 {
					sc = strconv.FormatFloat(f.Score, 'f', 1, 64)
				}
				rows = append(rows, []string{d.Name, d.Group, f.Severity, f.Kind, f.CVE, sc, ex, f.Software, f.Version, f.Title, f.Detail, f.Fix})
			}
		}
		csvOut(w, "helm-vulnerabilities", rows)
	case "hardware":
		rows := [][]string{{"PC", "Group", "Manufacturer", "Model", "Serial", "OS", "CPU", "Cores", "RAM (GB)", "BIOS", "Last boot", "Collected"}}
		for _, d := range s.st.devices() {
			if !d.Approved {
				continue
			}
			var rec *InvRec
			s.db.view(func(x *dbData) { rec = x.Inventory[d.ID] })
			if rec == nil {
				continue
			}
			var m map[string]any
			if json.Unmarshal(rec.Data, &m) != nil {
				continue
			}
			ram := ""
			if n, ok := m["ramBytes"].(float64); ok && n > 0 {
				ram = strconv.FormatFloat(n/(1<<30), 'f', 1, 64)
			}
			rows = append(rows, []string{d.Name, d.Group, invString(m, "manufacturer"), invString(m, "model"), invString(m, "serial"),
				invString(m, "osCaption"), invString(m, "cpu"), invString(m, "cores"), ram, invString(m, "biosVersion"), invString(m, "lastBoot"), rec.At.Format(time.RFC3339)})
		}
		csvOut(w, "helm-hardware", rows)
	case "software":
		rows := [][]string{{"PC", "Software", "Version", "Publisher", "Install date"}}
		for _, d := range s.st.devices() {
			if !d.Approved {
				continue
			}
			v, ok := s.scanView(d.ID)
			if !ok {
				continue
			}
			for _, sw := range v.Software {
				rows = append(rows, []string{d.Name, sw.Name, sw.Version, sw.Publisher, sw.InstallDate})
			}
		}
		csvOut(w, "helm-software", rows)
	case "sessions":
		rows := [][]string{{"Started", "Ended", "PC", "Type", "View only", "From IP", "Result", "Detail"}}
		s.db.view(func(d *dbData) {
			for i := len(d.Sessions) - 1; i >= 0; i-- {
				x := d.Sessions[i]
				end := ""
				if !x.Ended.IsZero() {
					end = x.Ended.Format(time.RFC3339)
				}
				rows = append(rows, []string{x.Started.Format(time.RFC3339), end, x.DeviceName, x.Kind, fmt.Sprint(x.ViewOnly), x.IP, x.Result, x.Detail})
			}
		})
		csvOut(w, "helm-sessions", rows)
	case "audit":
		rows := [][]string{{"Time", "IP", "Action", "Device", "Detail"}}
		for _, e := range s.audit.tail(1000) {
			rows = append(rows, []string{e.Time.Format(time.RFC3339), e.IP, e.Action, e.Device, e.Detail})
		}
		csvOut(w, "helm-audit", rows)
	default:
		writeErr(w, 404, "unknown report")
	}
}

var helloZero proto.Hello

// ---- software inventory across the fleet ----

type swRow struct {
	Name      string `json:"name"`
	Version   string `json:"version"`
	Publisher string `json:"publisher"`
	Devices   []struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	} `json:"devices"`
	CVEs      int    `json:"cves"`
	Worst     string `json:"worst"`
	Exploited bool   `json:"exploited"`
}

func (s *Server) handleSoftware(w http.ResponseWriter, r *http.Request, sess *session) {
	rows := map[string]*swRow{}
	var order []string
	for _, d := range s.st.devices() {
		if !d.Approved {
			continue
		}
		v, ok := s.scanView(d.ID)
		if !ok || !v.HaveSoftware {
			continue
		}
		vuln := map[string][]Finding{}
		for _, f := range v.Findings {
			if f.Kind == "cve" && f.Software != "" {
				vuln[f.Software+"|"+f.Version] = append(vuln[f.Software+"|"+f.Version], f)
			}
		}
		seen := map[string]bool{}
		for _, sw := range v.Software {
			k := strings.ToLower(sw.Name) + "|" + sw.Version
			if seen[k] {
				continue
			}
			seen[k] = true
			row := rows[k]
			if row == nil {
				row = &swRow{Name: sw.Name, Version: sw.Version, Publisher: sw.Publisher, Worst: ""}
				rows[k] = row
				order = append(order, k)
			}
			row.Devices = append(row.Devices, struct {
				ID   string `json:"id"`
				Name string `json:"name"`
			}{d.ID, d.Name})
			if fs := vuln[sw.Name+"|"+sw.Version]; len(fs) > row.CVEs {
				row.CVEs = len(fs)
				for _, f := range fs {
					if sevRank[f.Severity] > sevRank[row.Worst] || row.Worst == "" {
						row.Worst = f.Severity
					}
					if f.Exploited {
						row.Exploited = true
					}
				}
			}
		}
	}
	out := make([]*swRow, 0, len(order))
	for _, k := range order {
		out = append(out, rows[k])
	}
	sort.Slice(out, func(i, j int) bool { return strings.ToLower(out[i].Name) < strings.ToLower(out[j].Name) })
	writeJSON(w, 200, out)
}

// storeInventory keeps the newest successful inventory of each device.
func (s *Server) storeInventory(j Job) {
	if j.Name != "inventory" || j.Status != "ok" || len(j.Data) == 0 || len(j.Data) > 512<<10 {
		return
	}
	s.db.update(func(d *dbData) {
		d.Inventory[j.DeviceID] = &InvRec{At: j.Finished, Data: append(json.RawMessage(nil), j.Data...)}
	})
}

// autoInventory refreshes inventories older than a day for online, approved devices.
func (s *Server) autoInventory() {
	online := s.hub.onlineIDs()
	for _, d := range s.st.devices() {
		if !d.Approved || online[d.ID] == nil {
			continue
		}
		var at time.Time
		s.db.view(func(x *dbData) {
			if r := x.Inventory[d.ID]; r != nil {
				at = r.At
			}
		})
		if time.Since(at) > 24*time.Hour {
			_, _ = s.hub.dispatch(d.ID, "inventory", json.RawMessage(`{}`), "auto-inventory")
		}
	}
}

func (s *Server) handleDeviceInventory(w http.ResponseWriter, r *http.Request, sess *session) {
	id := r.PathValue("id")
	if _, ok := s.st.device(id); !ok {
		writeErr(w, 404, "no such device")
		return
	}
	var rec *InvRec
	s.db.view(func(d *dbData) {
		if x := d.Inventory[id]; x != nil {
			c := *x
			rec = &c
		}
	})
	if rec == nil {
		writeJSON(w, 200, map[string]any{"at": nil, "data": nil})
		return
	}
	writeJSON(w, 200, rec)
}

func invString(m map[string]any, k string) string {
	if v, ok := m[k]; ok && v != nil {
		return fmt.Sprint(v)
	}
	return ""
}
