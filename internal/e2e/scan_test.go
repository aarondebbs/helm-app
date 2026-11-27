package e2e

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"helm/internal/server"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func (e *env) json(method, path string, body any, out any) int {
	e.t.Helper()
	st, b := e.do(method, path, body)
	if out != nil && len(b) > 0 {
		if err := json.Unmarshal(b, out); err != nil {
			e.t.Fatalf("%s %s: bad JSON %q: %v", method, path, b, err)
		}
	}
	if st >= 400 {
		var er struct{ Error string }
		_ = json.Unmarshal(b, &er)
		e.t.Logf("%s %s -> %d %s", method, path, st, er.Error)
	}
	return st
}

func (e *env) waitRun(id string) map[string]any {
	e.t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		var r map[string]any
		e.json("GET", "/api/runs/"+id, nil, &r)
		if r["status"] == "done" {
			return r
		}
		time.Sleep(150 * time.Millisecond)
	}
	e.t.Fatal("run did not finish")
	return nil
}

func TestScanAndAutomation(t *testing.T) {
	e := newEnv(t)
	e.login()
	id := e.enrolled(t)

	// group + tags
	if st := e.json("POST", "/api/devices/"+id+"/edit", map[string]any{"name": "Front desk", "notes": "", "group": "Reception", "tags": []string{"VIP", " laptop ", "vip"}}, nil); st != 200 {
		t.Fatalf("edit: %d", st)
	}
	var dv struct {
		Group string
		Tags  []string
	}
	e.json("GET", "/api/devices/"+id, nil, &dv)
	if dv.Group != "Reception" || len(dv.Tags) != 2 || dv.Tags[0] != "vip" || dv.Tags[1] != "laptop" {
		t.Fatalf("group/tags not normalised: %+v", dv)
	}

	// scan
	if st := e.json("POST", "/api/devices/"+id+"/scan", nil, nil); st != 200 {
		t.Fatalf("scan start: %d", st)
	}
	var sc struct {
		Status   string
		Score    int
		Counts   map[string]int
		Findings []struct{ Kind, Severity, Title string }
		Software []struct{ Name string }
		Errors   []string
	}
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		e.json("GET", "/api/devices/"+id+"/scan", nil, &sc)
		if sc.Status == "done" || sc.Status == "partial" || sc.Status == "failed" {
			break
		}
		time.Sleep(150 * time.Millisecond)
	}
	if sc.Status != "done" {
		t.Fatalf("scan status %q errors %v", sc.Status, sc.Errors)
	}
	kinds := map[string]bool{}
	for _, f := range sc.Findings {
		kinds[f.Kind] = true
	}
	for _, k := range []string{"config", "port", "patch"} {
		if !kinds[k] {
			t.Errorf("no %s finding in %+v", k, sc.Findings)
		}
	}
	if sc.Score <= 0 || sc.Score >= 100 || len(sc.Software) < 3 {
		t.Errorf("score %d software %d", sc.Score, len(sc.Software))
	}
	// a rescan keeps the previous results visible, and a second concurrent scan is refused
	if st := e.json("POST", "/api/devices/"+id+"/scan", nil, nil); st != 200 {
		t.Fatalf("rescan: %d", st)
	}
	// The rescan can already have finished on a fast machine; then a new scan is legitimately accepted. While one is
	// still running it must be refused.
	if st := e.json("POST", "/api/devices/"+id+"/scan", nil, nil); st != 409 && st != 200 {
		t.Errorf("a second scan should be refused (409) or, if the first already finished, accepted (200); got %d", st)
	}
	var during struct {
		Status  string
		HasData bool
		Score   int
	}
	e.json("GET", "/api/devices/"+id+"/scan", nil, &during)
	if during.Status == "running" && (!during.HasData || during.Score != sc.Score) {
		t.Errorf("previous results must stay visible while rescanning: %+v", during)
	}
	for time.Now().Before(deadline.Add(10 * time.Second)) {
		e.json("GET", "/api/devices/"+id+"/scan", nil, &during)
		if during.Status != "running" {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}

	// fleet views
	var fleet struct {
		Findings []struct {
			Kind    string
			Devices []struct{ ID string }
		}
		Scanned, Total int
	}
	e.json("GET", "/api/security", nil, &fleet)
	if fleet.Scanned != 1 || fleet.Total != 1 || len(fleet.Findings) == 0 || len(fleet.Findings[0].Devices) != 1 {
		t.Errorf("fleet security: %+v", fleet)
	}
	var dash map[string]any
	e.json("GET", "/api/dashboard", nil, &dash)
	for _, k := range []string{"total", "online", "avgScore", "counts", "buckets", "alerts", "runs", "worst", "lowDisks"} {
		if dash[k] == nil && k != "avgScore" {
			t.Errorf("dashboard missing %s (null would break the UI)", k)
		}
	}
	var sw []struct{ Name string }
	e.json("GET", "/api/software", nil, &sw)
	if len(sw) < 3 {
		t.Errorf("software inventory: %+v", sw)
	}
	_, csv := e.do("GET", "/api/reports/vulnerabilities", nil)
	if !strings.Contains(string(csv), "PC,Group,Severity") || !strings.Contains(string(csv), "Front desk") {
		t.Errorf("vulnerability CSV: %.200s", csv)
	}
	if st, _ := e.do("GET", "/api/reports/nope", nil); st != 404 {
		t.Errorf("unknown report: %d", st)
	}

	// script library + run on a group
	var scr struct{ ID string }
	if st := e.json("POST", "/api/scripts", map[string]any{"name": "Hello", "shell": "powershell", "body": "# helm:ping\nWrite-Output hi", "timeout": 30}, &scr); st != 200 || scr.ID == "" {
		t.Fatalf("script save: %d", st)
	}
	if st := e.json("POST", "/api/scripts", map[string]any{"name": "", "body": ""}, nil); st != 400 {
		t.Errorf("empty script accepted: %d", st)
	}
	var run struct {
		ID      string
		Results []struct{ Status string }
	}
	if st := e.json("POST", "/api/run/script", map[string]any{"scriptId": scr.ID, "target": map[string]any{"group": "Reception"}}, &run); st != 200 || len(run.Results) != 1 {
		t.Fatalf("run script: %d %+v", st, run)
	}
	done := e.waitRun(run.ID)
	if done["kind"] != "script" || done["trigger"] != "manual" {
		t.Errorf("run: %+v", done)
	}
	if st := e.json("POST", "/api/run/script", map[string]any{"body": "x", "target": map[string]any{"group": "Nowhere"}}, nil); st != 400 {
		t.Errorf("empty target should be refused: %d", st)
	}

	// schedules
	bad := map[string]any{"name": "x", "action": "scan", "kind": "daily", "at": "25:99", "enabled": true, "target": map[string]any{"all": true}}
	if st := e.json("POST", "/api/schedules", bad, nil); st != 400 {
		t.Errorf("bad time accepted: %d", st)
	}
	var sch struct {
		ID      string
		NextRun time.Time
	}
	good := map[string]any{"name": "Nightly scan", "action": "scan", "kind": "daily", "at": "03:00", "enabled": true, "target": map[string]any{"all": true}}
	if st := e.json("POST", "/api/schedules", good, &sch); st != 200 || sch.NextRun.Before(time.Now()) {
		t.Fatalf("schedule save: %d %+v", st, sch)
	}
	var srun struct{ ID string }
	if st := e.json("POST", "/api/schedules/"+sch.ID+"/run", nil, &srun); st != 200 {
		t.Fatalf("schedule run: %d", st)
	}
	if r := e.waitRun(srun.ID); r["kind"] != "scan" {
		t.Errorf("schedule run kind: %+v", r)
	}

	// packages: winget + upload, deploy
	var pk struct{ ID string }
	if st := e.json("POST", "/api/packages", map[string]any{"name": "7-Zip", "wingetId": "7zip.7zip"}, &pk); st != 200 {
		t.Fatalf("add package: %d", st)
	}
	if st := e.json("POST", "/api/packages", map[string]any{"name": "Evil", "wingetId": "a; rm -rf /"}, nil); st != 400 {
		t.Errorf("unsafe winget id accepted: %d", st)
	}
	var drun struct{ ID string }
	if st := e.json("POST", "/api/deploy", map[string]any{"packageId": pk.ID, "action": "install", "target": map[string]any{"devices": []string{id}}}, &drun); st != 200 {
		t.Fatalf("deploy: %d", st)
	}
	e.waitRun(drun.ID)

	payload := []byte("MZ fake installer")
	req, _ := http.NewRequest("POST", e.ts.URL+"/api/packages/upload?name=Tool&filename=tool.exe&args=%2FS", bytes.NewReader(payload))
	req.Header.Set("X-CSRF-Token", e.csrf)
	resp, err := e.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	var up struct {
		ID, SHA256 string
		Size       int64
	}
	_ = json.NewDecoder(resp.Body).Decode(&up)
	resp.Body.Close()
	sum := sha256.Sum256(payload)
	if resp.StatusCode != 200 || up.SHA256 != hex.EncodeToString(sum[:]) || up.Size != int64(len(payload)) {
		t.Fatalf("upload: %d %+v", resp.StatusCode, up)
	}
	req2, _ := http.NewRequest("POST", e.ts.URL+"/api/packages/upload?name=Bad&filename=run.bat&args=", bytes.NewReader(payload))
	req2.Header.Set("X-CSRF-Token", e.csrf)
	if r2, _ := e.client.Do(req2); r2.StatusCode != 400 {
		t.Errorf(".bat upload accepted: %d", r2.StatusCode)
	}
	// the agent download endpoint must reject anonymous callers
	anon, _ := http.Get(e.ts.URL + "/api/agent/package/" + up.ID)
	if anon.StatusCode != 401 {
		t.Errorf("anonymous package download: %d", anon.StatusCode)
	}

	// personalised installer: token validation, then a (fake) template gets the token injected
	var tk struct{ Token string }
	if st := e.json("POST", "/api/tokens", map[string]any{"label": "Dad's laptop", "hours": 1, "maxUses": 1}, &tk); st != 200 {
		t.Fatalf("token: %d", st)
	}
	if st, _ := e.do("POST", "/api/installer", map[string]string{"token": "nonsense"}); st != 400 {
		t.Errorf("bad token accepted: %d", st)
	}
	if st, _ := e.do("POST", "/api/installer", map[string]string{"token": tk.Token}); st != 404 {
		t.Errorf("missing template should be 404, got %d", st)
	}
	tpl := []byte("MSI:" + strings.Repeat("S", 146) + "")
	_ = tpl
	fake := append([]byte("HELMPH_SERVER_"+strings.Repeat("S", 146)), []byte("|HELMPH_TOKEN_"+strings.Repeat("T", 83)+"|HELMPH_CONSENT_"+strings.Repeat("C", 17))...)
	os.MkdirAll(filepath.Join(e.dataDir, "dist"), 0o755)
	os.WriteFile(filepath.Join(e.dataDir, "dist", "Helm-Agent.template.msi"), fake, 0o644)
	if st, b := e.do("POST", "/api/installer", map[string]string{"token": tk.Token, "consent": "unattended"}); st != 200 || !strings.Contains(string(b), tk.Token) || !strings.Contains(string(b), "unattended") || strings.Contains(string(b), "HELMPH_") {
		t.Errorf("installer download: %d %.120s", st, b)
	}
	// cloud updates: repository validation and status (no release key is built into test servers)
	if st, _ := e.do("PUT", "/api/settings", map[string]any{"offlineMinutes": 15, "diskFreePct": 10, "scanEveryHours": 24, "updateRepo": "not a repo"}); st != 400 {
		t.Errorf("bad update repo accepted: %d", st)
	}
	var upd struct {
		KeyConfigured bool   `json:"keyConfigured"`
		Current       string `json:"current"`
	}
	if st := e.json("GET", "/api/update", nil, &upd); st != 200 || upd.KeyConfigured {
		t.Errorf("update status: %d %+v", st, upd)
	}
	if st, _ := e.do("POST", "/api/update/check", map[string]any{}); st != 502 {
		t.Errorf("update check without repo/key should fail cleanly: %d", st)
	}
	// personalised install scripts (Linux and macOS) and the macOS enrolment file
	os.WriteFile(filepath.Join(e.dataDir, "dist", "install-linux.sh"), []byte("#!/usr/bin/env bash\nset -e\necho linux\n"), 0o755)
	os.WriteFile(filepath.Join(e.dataDir, "dist", "install-macos.sh"), []byte("#!/usr/bin/env bash\nset -e\necho mac\n"), 0o755)
	for _, osName := range []string{"linux", "macos"} {
		st, b := e.do("POST", "/api/installer", map[string]string{"token": tk.Token, "consent": "unattended", "os": osName})
		sc := string(b)
		if st != 200 || !strings.HasPrefix(sc, "#!/usr/bin/env bash\nset -- --server '") || !strings.Contains(sc, "--token '"+tk.Token+"'") || !strings.Contains(sc, "--consent 'unattended' \"$@\"\n") || !strings.Contains(sc, "\necho ") {
			t.Errorf("%s install script: %d %.200s", osName, st, sc)
		}
	}
	if st, b := e.do("POST", "/api/installer", map[string]string{"token": tk.Token, "os": "macos-conf"}); st != 200 || !strings.Contains(string(b), "TOKEN="+tk.Token+"\n") || !strings.Contains(string(b), "CONSENT=prompt_if_present") {
		t.Errorf("macos conf: %d %.200s", st, b)
	}
	if st, _ := e.do("POST", "/api/installer", map[string]string{"token": "hlm_" + strings.Repeat("0", 40), "os": "linux"}); st != 400 {
		t.Errorf("script for an unknown token: %d", st)
	}
	// the inventory a device reports is stored and served while it is offline
	inv := e.cmd(id, "inventory", map[string]any{})
	if inv.Status != "ok" {
		t.Fatalf("inventory job: %+v", inv)
	}
	time.Sleep(300 * time.Millisecond)
	var stored struct{ Data map[string]any }
	if st := e.json("GET", "/api/devices/"+id+"/inventory", nil, &stored); st != 200 || stored.Data == nil {
		_, raw := e.do("GET", "/api/devices/"+id+"/inventory", nil)
		t.Errorf("stored inventory: %d %+v raw=%.200s job=%+v", st, stored, raw, inv)
	}
	if st, b := e.do("GET", "/api/reports/hardware", nil); st != 200 || !strings.Contains(string(b), "Manufacturer") {
		t.Errorf("hardware report: %d %.100s", st, b)
	}
	// authenticator replacement and removal from the portal
	var beg struct {
		Secret string
		QR     struct{ Size int }
	}
	if st := e.json("POST", "/api/account/2fa/begin", map[string]string{"password": "wrong"}, nil); st != 403 {
		t.Errorf("2fa begin with wrong password: %d", st)
	}
	if st := e.json("POST", "/api/account/2fa/begin", map[string]string{"password": adminPW, "code": server.TOTPNow(e.secret, time.Now())}, &beg); st != 200 || beg.Secret == "" || beg.QR.Size < 21 {
		t.Fatalf("2fa begin: %d %+v", st, beg)
	}
	if st := e.json("POST", "/api/account/2fa/confirm", map[string]string{"code": "000000"}, nil); st != 400 {
		t.Errorf("wrong code accepted: %d", st)
	}
	if st := e.json("POST", "/api/account/2fa/confirm", map[string]string{"code": server.TOTPNow(beg.Secret, time.Now())}, nil); st != 200 {
		t.Fatalf("2fa confirm: %d", st)
	}
	e.secret = beg.Secret // the old authenticator no longer works
	if st := e.json("POST", "/api/account/2fa/disable", map[string]string{"password": adminPW, "code": "000000"}, nil); st != 403 {
		t.Errorf("disable with a wrong code: %d", st)
	}
	if st := e.json("POST", "/api/account/2fa/disable", map[string]string{"password": adminPW, "code": server.TOTPNow(beg.Secret, time.Now().Add(30*time.Second))}, nil); st != 200 {
		t.Fatalf("2fa disable: %d", st)
	}
	if st, b := e.do("GET", "/api/auth/config", nil); st != 200 || !strings.Contains(string(b), `"totp":false`) {
		t.Errorf("auth config after disable: %d %s", st, b)
	}
	// turn it on again, then replacing the authenticator needs the current code
	var beg2 struct{ Secret string }
	if st := e.json("POST", "/api/account/2fa/begin", map[string]string{"password": adminPW}, &beg2); st != 200 {
		t.Fatalf("2fa begin again: %d", st)
	}
	if st := e.json("POST", "/api/account/2fa/confirm", map[string]string{"code": server.TOTPNow(beg2.Secret, time.Now())}, nil); st != 200 {
		t.Fatalf("2fa confirm again: %d", st)
	}
	e.secret = beg2.Secret
	if st := e.json("POST", "/api/account/2fa/begin", map[string]string{"password": adminPW}, nil); st != 403 {
		t.Errorf("replace without the current code: %d", st)
	}
	if st := e.json("POST", "/api/account/2fa/disable", map[string]string{"password": adminPW, "code": server.TOTPNow(beg2.Secret, time.Now().Add(30*time.Second))}, nil); st != 200 {
		t.Fatalf("2fa disable again: %d", st)
	}
	// renaming the administrator needs the current password
	if st := e.json("POST", "/api/account/username", map[string]string{"newUser": "boss", "password": "wrong-password"}, nil); st != 401 {
		t.Errorf("rename with wrong password: %d", st)
	}
	if st := e.json("POST", "/api/account/username", map[string]string{"newUser": "x", "password": adminPW}, nil); st != 400 {
		t.Errorf("too-short username accepted: %d", st)
	}
	if st := e.json("POST", "/api/account/username", map[string]string{"newUser": "boss", "password": adminPW}, nil); st != 200 {
		t.Fatalf("rename: %d", st)
	}
	if _, b := e.do("GET", "/api/me", nil); !strings.Contains(string(b), `"user":"boss"`) {
		t.Errorf("/api/me after rename: %s", b)
	}
	if st := e.json("POST", "/api/account/password", map[string]string{"current": "nope", "new": "a-brand-new-passphrase-77"}, nil); st != 401 {
		t.Errorf("password change with wrong current password: %d", st)
	}
	if st := e.json("POST", "/api/account/password", map[string]string{"current": adminPW, "new": "short"}, nil); st != 400 {
		t.Errorf("weak new password accepted: %d", st)
	}
	if st := e.json("POST", "/api/account/password", map[string]string{"current": adminPW, "new": "a-brand-new-passphrase-77"}, nil); st != 200 {
		t.Fatalf("password change: %d", st)
	}
	if st, _ := e.do("GET", "/api/me", nil); st != 200 {
		t.Errorf("the current session must stay signed in: %d", st)
	}
	// settings never echo secrets
	if st := e.json("PUT", "/api/settings", map[string]any{"telegram": map[string]any{"enabled": false, "chatId": "1", "token": "SECRET-TOKEN"}, "nvdKey": "KEY123",
		"offlineMinutes": 10, "diskFreePct": 10, "autoScan": true, "scanEveryHours": 24, "rules": map[string]bool{}}, nil); st != 200 {
		t.Fatalf("settings put: %d", st)
	}
	_, sb := e.do("GET", "/api/settings", nil)
	if strings.Contains(string(sb), "SECRET-TOKEN") || strings.Contains(string(sb), "KEY123") || !strings.Contains(string(sb), `"tokenSet":true`) {
		t.Errorf("settings leak or lost the token: %s", sb)
	}
	if st := e.json("PUT", "/api/settings", map[string]any{"offlineMinutes": -5, "diskFreePct": 10, "scanEveryHours": 24}, nil); st != 400 {
		t.Errorf("out-of-range setting accepted: %d", st)
	}

	// alerts and sessions endpoints return arrays
	for _, p := range []string{"/api/alerts", "/api/sessions", "/api/runs", "/api/schedules", "/api/scripts", "/api/packages"} {
		_, b := e.do("GET", p, nil)
		if !strings.HasPrefix(strings.TrimSpace(string(b)), "[") {
			t.Errorf("%s must return a JSON array, got %.60s", p, b)
		}
	}
	// deleting a device removes its scan
	e.do("DELETE", "/api/devices/"+id, nil)
	var gone any
	e.json("GET", "/api/devices/"+id+"/scan", nil, &gone)
	if gone != nil {
		t.Errorf("scan data should be removed with the device: %v", gone)
	}
}
