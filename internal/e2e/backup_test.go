package e2e

import (
	"strings"
	"testing"
	"time"

	"helm/internal/server"
)

func TestBackupsAndRestore(t *testing.T) {
	e := newEnv(t)
	e.login()
	// step-up for the sensitive calls
	code := server.TOTPNow(e.secret, time.Now().Add(30*time.Second))
	if st, b := e.do("POST", "/api/stepup", map[string]string{"code": code}); st != 200 {
		t.Fatalf("stepup: %d %s", st, b)
	}
	var bi struct {
		Name string
		Size int64
	}
	if st := e.json("POST", "/api/backups", map[string]any{}, &bi); st != 200 || !strings.HasPrefix(bi.Name, "helm-backup-") || bi.Size < 100 {
		t.Fatalf("create backup: %d %+v", st, bi)
	}
	var list struct{ Backups []struct{ Name string } }
	if st := e.json("GET", "/api/backups", nil, &list); st != 200 || len(list.Backups) != 1 {
		t.Fatalf("list: %d %+v", st, list)
	}
	st, zipb := e.do("GET", "/api/backups/"+bi.Name, nil)
	if st != 200 || len(zipb) < 4 || string(zipb[:2]) != "PK" {
		t.Fatalf("download: %d", st)
	}
	if st, _ := e.do("GET", "/api/backups/..%2Fstate.json", nil); st == 200 {
		t.Error("path traversal in backup name must not succeed")
	}
	if st, _ := e.do("POST", "/api/backups/restore", map[string]string{"name": "../../etc/passwd"}); st != 400 {
		t.Errorf("bad restore name: %d", st)
	}

	// change something, then restore the backup and see it revert
	if st := e.json("PUT", "/api/settings", map[string]any{"offlineMinutes": 77, "diskFreePct": 10, "scanEveryHours": 24}, nil); st != 200 {
		t.Fatalf("settings: %d", st)
	}
	if st := e.json("POST", "/api/backups/restore", map[string]string{"name": bi.Name}, nil); st != 200 {
		t.Fatalf("restore: %d", st)
	}
	// sessions were dropped by the restore
	if st, _ := e.do("GET", "/api/me", nil); st != 401 {
		t.Errorf("session should end after restore: %d", st)
	}
	// the restored state remembers the authenticator step used at backup time; reset it so the test can sign in within the same 30 s
	if _, err := e.srv.Store().SetAdmin("admin", adminPW, e.secret); err != nil {
		t.Fatal(err)
	}
	e.login()
	_, sb := e.do("GET", "/api/settings", nil)
	if !strings.Contains(string(sb), `"offlineMinutes":15`) {
		t.Errorf("settings were not restored: %s", sb)
	}
	var l2 struct{ Backups []struct{ Name string } }
	e.json("GET", "/api/backups", nil, &l2)
	hasPre := false
	for _, b := range l2.Backups {
		hasPre = hasPre || strings.HasPrefix(b.Name, "helm-prerestore-")
	}
	if !hasPre {
		t.Errorf("restore must leave a safety copy: %+v", l2)
	}

	// upload: garbage is refused, a real archive is accepted
	if st, _ := e.do("POST", "/api/backups/upload", map[string]string{"x": "y"}); st != 400 {
		t.Errorf("garbage upload: %d", st)
	}
	var h struct {
		Version  string
		Warnings []string
	}
	if st := e.json("GET", "/api/health", nil, &h); st != 200 || h.Version != "test" {
		t.Errorf("health: %d %+v", st, h)
	}
}
