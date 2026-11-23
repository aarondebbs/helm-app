package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"
)

// ---- Telegram ----

var telegramBase = "https://api.telegram.org"

func sendTelegram(ctx context.Context, token, chat, text string) error {
	body, _ := json.Marshal(map[string]any{"chat_id": chat, "text": text, "disable_web_page_preview": true})
	req, err := http.NewRequestWithContext(ctx, "POST", telegramBase+"/bot"+token+"/sendMessage", bytes.NewReader(body))
	if err != nil {
		return errors.New("invalid bot token")
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := (&http.Client{Timeout: 15 * time.Second}).Do(req)
	if err != nil {
		return errors.New("could not reach Telegram")
	}
	defer resp.Body.Close()
	var r struct {
		OK          bool   `json:"ok"`
		Description string `json:"description"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&r)
	if !r.OK {
		if r.Description == "" {
			r.Description = fmt.Sprintf("HTTP %d", resp.StatusCode)
		}
		return errors.New("Telegram: " + r.Description)
	}
	return nil
}

// notify sends a message to Telegram if configured. It never blocks the caller.
func (s *Server) notify(text string) {
	set := s.db.settings()
	if !set.Telegram.Enabled || set.Telegram.Token == "" || set.Telegram.ChatID == "" {
		return
	}
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		if err := sendTelegram(ctx, set.Telegram.Token, set.Telegram.ChatID, text); err != nil {
			s.log.Printf("telegram: %v", err)
		}
	}()
}

// ---- alert evaluation ----

type cond struct {
	rule, key, devID, devName, sev, title, detail string
}

func (s *Server) alertConditions(set Settings) []cond {
	var out []cond
	devs := s.st.devices()
	online := s.hub.onlineIDs()
	now := time.Now()
	for _, d := range devs {
		if !d.Approved {
			out = append(out, cond{RuleNewDevice, "new:" + d.ID, d.ID, d.Name, "info", "New PC waiting for approval: " + d.Name,
				"Enrolled via \"" + d.Via + "\" from " + d.LastIP + ". Open the console to approve or reject it."})
			continue
		}
		a := online[d.ID]
		if a == nil {
			if set.OfflineMinutes > 0 && now.Sub(d.LastSeen) > time.Duration(set.OfflineMinutes)*time.Minute {
				out = append(out, cond{RuleOffline, "offline:" + d.ID, d.ID, d.Name, "warning", d.Name + " is offline",
					"Last seen " + humanAgo(now.Sub(d.LastSeen)) + " ago."})
			}
		} else if st, _ := a.stats(); st != nil && set.DiskFreePct > 0 {
			for _, dk := range st.Disks {
				if dk.Total > 0 && int(dk.Free*100/dk.Total) < set.DiskFreePct {
					out = append(out, cond{RuleDiskLow, "disk:" + d.ID + ":" + dk.Name, d.ID, d.Name, "warning", fmt.Sprintf("Low disk space on %s (%s)", d.Name, dk.Name),
						fmt.Sprintf("%d%% free (%s of %s).", dk.Free*100/dk.Total, fmtBytes(dk.Free), fmtBytes(dk.Total))})
				}
			}
		}
		if v, ok := s.scanView(d.ID); ok && v.HasData {
			crit, high := v.Counts["critical"], v.Counts["high"]
			if crit+high > 0 {
				sev := "warning"
				if crit > 0 {
					sev = "critical"
				}
				top := ""
				for _, f := range v.Findings {
					if f.Severity == "critical" || f.Severity == "high" {
						top = f.Title
						break
					}
				}
				out = append(out, cond{RuleSecurity, "security:" + d.ID, d.ID, d.Name, sev, fmt.Sprintf("%s has %d critical and %d high security findings", d.Name, crit, high),
					"Most severe: " + top})
			}
			missing := 0
			for _, f := range v.Findings {
				if f.Kind == "patch" && (f.Severity == "critical" || f.Severity == "high") {
					missing++
				}
			}
			if missing > 0 {
				out = append(out, cond{RulePatches, "patches:" + d.ID, d.ID, d.Name, "warning", fmt.Sprintf("%s is missing %d important security update(s)", d.Name, missing), ""})
			}
		}
	}
	return out
}

func fmtBytes(n uint64) string {
	u := []string{"B", "KB", "MB", "GB", "TB"}
	f := float64(n)
	i := 0
	for f >= 1024 && i < len(u)-1 {
		f /= 1024
		i++
	}
	if i == 0 {
		return fmt.Sprintf("%d B", n)
	}
	return fmt.Sprintf("%.1f %s", f, u[i])
}

func humanAgo(d time.Duration) string {
	switch {
	case d < time.Hour:
		return fmt.Sprintf("%d min", int(d.Minutes()))
	case d < 48*time.Hour:
		return fmt.Sprintf("%d h", int(d.Hours()))
	}
	return fmt.Sprintf("%d days", int(d.Hours()/24))
}

var sevEmoji = map[string]string{"critical": "🔴", "warning": "🟠", "info": "🔵"}

// evalAlerts opens alerts for new conditions and resolves the ones that cleared.
func (s *Server) evalAlerts() {
	set := s.db.settings()
	var active []cond
	for _, c := range s.alertConditions(set) {
		if set.Rules[c.rule] {
			active = append(active, c)
		}
	}
	keys := map[string]bool{}
	for _, c := range active {
		keys[c.key] = true
	}
	var opened []*Alert
	var cleared []Alert
	now := time.Now().UTC()
	s.db.update(func(d *dbData) {
		open := map[string]*Alert{}
		for _, a := range d.Alerts {
			if a.Resolved.IsZero() {
				open[a.Key] = a
			}
		}
		for _, c := range active {
			if open[c.key] != nil {
				open[c.key].Detail, open[c.key].Title, open[c.key].Severity = c.detail, c.title, c.sev
				continue
			}
			a := &Alert{ID: randHex(6), Rule: c.rule, Key: c.key, DeviceID: c.devID, DeviceName: c.devName, Severity: c.sev, Title: c.title, Detail: c.detail, Opened: now}
			d.Alerts = append(d.Alerts, a)
			opened = append(opened, a)
		}
		for k, a := range open {
			if !keys[k] {
				a.Resolved = now
				cleared = append(cleared, *a)
			}
		}
		if len(d.Alerts) > maxAlerts {
			d.Alerts = d.Alerts[len(d.Alerts)-maxAlerts:]
		}
	})
	for _, a := range opened {
		msg := sevEmoji[a.Severity] + " " + a.Title
		if a.Detail != "" {
			msg += "\n" + a.Detail
		}
		s.notify("Helm: " + msg)
	}
	for _, a := range cleared {
		if a.Rule == RuleOffline || a.Rule == RuleDiskLow {
			s.notify("Helm: ✅ Resolved: " + a.Title)
		}
	}
}

// ---- API ----

func (s *Server) handleAlerts(w http.ResponseWriter, r *http.Request, sess *session) {
	out := []Alert{}
	s.db.view(func(d *dbData) {
		var open, closed []Alert
		for i := len(d.Alerts) - 1; i >= 0; i-- {
			a := *d.Alerts[i]
			if a.Resolved.IsZero() {
				open = append(open, a)
			} else if len(closed) < 200 {
				closed = append(closed, a)
			}
		}
		sort.SliceStable(open, func(i, j int) bool { return sevAlertRank(open[i].Severity) > sevAlertRank(open[j].Severity) })
		out = append(append([]Alert{}, open...), closed...)
	})
	writeJSON(w, 200, out)
}

func sevAlertRank(s string) int { return map[string]int{"critical": 3, "warning": 2, "info": 1}[s] }

func (s *Server) handleAlertAck(w http.ResponseWriter, r *http.Request, sess *session) {
	id := r.PathValue("id")
	s.db.update(func(d *dbData) {
		for _, a := range d.Alerts {
			if a.ID == id {
				a.Acked = true
			}
		}
	})
	writeJSON(w, 200, map[string]bool{"ok": true})
}

func (s *Server) handleAlertsClear(w http.ResponseWriter, r *http.Request, sess *session) {
	s.db.update(func(d *dbData) {
		keep := d.Alerts[:0]
		for _, a := range d.Alerts {
			if a.Resolved.IsZero() {
				keep = append(keep, a)
			}
		}
		d.Alerts = keep
	})
	writeJSON(w, 200, map[string]bool{"ok": true})
}

type settingsView struct {
	Telegram struct {
		Enabled  bool   `json:"enabled"`
		ChatID   string `json:"chatId"`
		TokenSet bool   `json:"tokenSet"`
	} `json:"telegram"`
	NVDKeySet          bool            `json:"nvdKeySet"`
	OfflineMinutes     int             `json:"offlineMinutes"`
	DiskFreePct        int             `json:"diskFreePct"`
	AutoScan           bool            `json:"autoScan"`
	ScanEveryHours     int             `json:"scanEveryHours"`
	Rules              map[string]bool `json:"rules"`
	RuleInfo           []ruleDesc      `json:"ruleInfo"`
	CVE                CVEStatus       `json:"cve"`
	UpdateRepo         string          `json:"updateRepo"`
	ManualAgentUpdates bool            `json:"manualAgentUpdates"`
}

type ruleDesc struct {
	ID    string `json:"id"`
	Title string `json:"title"`
	Desc  string `json:"desc"`
}

func (s *Server) settingsView() settingsView {
	set := s.db.settings()
	v := settingsView{NVDKeySet: set.NVDKey != "", OfflineMinutes: set.OfflineMinutes, DiskFreePct: set.DiskFreePct,
		AutoScan: set.AutoScan, ScanEveryHours: set.ScanEveryHours, Rules: set.Rules, CVE: s.cve.status(), UpdateRepo: set.UpdateRepo, ManualAgentUpdates: set.ManualAgentUpdates}
	v.Telegram.Enabled, v.Telegram.ChatID, v.Telegram.TokenSet = set.Telegram.Enabled, set.Telegram.ChatID, set.Telegram.Token != ""
	for _, r := range ruleInfo {
		v.RuleInfo = append(v.RuleInfo, ruleDesc{r.ID, r.Title, r.Desc})
	}
	return v
}

func (s *Server) handleSettingsGet(w http.ResponseWriter, r *http.Request, sess *session) {
	writeJSON(w, 200, s.settingsView())
}

func (s *Server) handleSettingsPut(w http.ResponseWriter, r *http.Request, sess *session) {
	if !s.needStepUp(w, sess) {
		return
	}
	var req struct {
		Telegram struct {
			Enabled    bool   `json:"enabled"`
			ChatID     string `json:"chatId"`
			Token      string `json:"token"`
			ClearToken bool   `json:"clearToken"`
		} `json:"telegram"`
		NVDKey             *string         `json:"nvdKey"`
		OfflineMinutes     int             `json:"offlineMinutes"`
		DiskFreePct        int             `json:"diskFreePct"`
		AutoScan           bool            `json:"autoScan"`
		ScanEveryHours     int             `json:"scanEveryHours"`
		Rules              map[string]bool `json:"rules"`
		UpdateRepo         *string         `json:"updateRepo"`
		ManualAgentUpdates *bool           `json:"manualAgentUpdates"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	if req.UpdateRepo != nil {
		*req.UpdateRepo = strings.TrimSpace(*req.UpdateRepo)
		if *req.UpdateRepo != "" && !reRepo.MatchString(*req.UpdateRepo) {
			writeErr(w, 400, "the repository must look like owner/name")
			return
		}
	}
	tok := strings.TrimSpace(req.Telegram.Token)
	chat := strings.TrimSpace(req.Telegram.ChatID)
	if len(tok) > 200 || len(chat) > 100 || strings.ContainsAny(tok+chat, " \r\n\t/") {
		writeErr(w, 400, "bad Telegram token or chat id")
		return
	}
	if req.OfflineMinutes < 0 || req.OfflineMinutes > 10080 || req.DiskFreePct < 0 || req.DiskFreePct > 90 || req.ScanEveryHours < 1 || req.ScanEveryHours > 24*30 {
		writeErr(w, 400, "a setting is out of range")
		return
	}
	s.db.update(func(d *dbData) {
		set := &d.Settings
		set.Telegram.Enabled, set.Telegram.ChatID = req.Telegram.Enabled, chat
		if tok != "" {
			set.Telegram.Token = tok
		}
		if req.Telegram.ClearToken {
			set.Telegram.Token = ""
		}
		if req.NVDKey != nil {
			set.NVDKey = strings.TrimSpace(*req.NVDKey)
		}
		if req.UpdateRepo != nil {
			set.UpdateRepo = *req.UpdateRepo
		}
		if req.ManualAgentUpdates != nil {
			set.ManualAgentUpdates = *req.ManualAgentUpdates
		}
		set.OfflineMinutes, set.DiskFreePct, set.AutoScan, set.ScanEveryHours = req.OfflineMinutes, req.DiskFreePct, req.AutoScan, req.ScanEveryHours
		for _, ri := range ruleInfo {
			if v, ok := req.Rules[ri.ID]; ok {
				set.Rules[ri.ID] = v
			}
		}
	})
	s.record(r, "settings_changed", "", "")
	writeJSON(w, 200, s.settingsView())
}

func (s *Server) handleTelegramTest(w http.ResponseWriter, r *http.Request, sess *session) {
	set := s.db.settings()
	if set.Telegram.Token == "" || set.Telegram.ChatID == "" {
		writeErr(w, 400, "save a bot token and chat id first")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	if err := sendTelegram(ctx, set.Telegram.Token, set.Telegram.ChatID, "✅ Helm: test notification. Alerts will arrive here."); err != nil {
		writeErr(w, 502, err.Error())
		return
	}
	writeJSON(w, 200, map[string]bool{"ok": true})
}
