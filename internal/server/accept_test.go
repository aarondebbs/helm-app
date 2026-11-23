package server

import (
	"testing"
	"time"
)

func TestAcceptedRiskAndNoFix(t *testing.T) {
	db, err := OpenDB(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	s := &Server{db: db, cve: newCVEEngine(t.TempDir(), nil)}
	s.cve.products["7-zip:7-zip"] = &cveProduct{Fetched: time.Now(), CVEs: []CVERec{{ID: "CVE-1", Score: 9.8, Sev: "critical", R: []CPERange{{Ver: "*", EE: "23.0"}}}}}
	sc := &Scan{DeviceID: "d1", Status: "done", Software: []SoftwareItem{{Name: "7-Zip 22.01 (x64)", Version: "22.01"}},
		Checks: []ConfigCheck{{ID: "fw", Title: "Firewall off", Severity: "high", Status: "fail"}}}
	before := s.computeFindings(sc)
	if before.Counts["critical"] != 1 || before.Counts["high"] != 1 {
		t.Fatalf("expected one critical and one high, got %+v", before.Counts)
	}
	db.update(func(x *dbData) {
		x.Accepted = map[string]AcceptRec{"cfg:fw": {Note: "managed elsewhere", At: time.Now()}, "cve:CVE-1|7-Zip 22.01 (x64)": {At: time.Now()}}
		x.NoFix = map[string]time.Time{"d1|7-Zip 22.01 (x64)": time.Now()}
	})
	after := s.computeFindings(sc)
	if after.Counts["critical"] != 0 || after.Counts["high"] != 0 {
		t.Errorf("accepted findings must not be counted: %+v", after.Counts)
	}
	if after.Score <= before.Score {
		t.Errorf("score should rise when risks are accepted: %d -> %d", before.Score, after.Score)
	}
	var acc, nofix int
	for _, f := range after.Findings {
		if f.Accepted {
			acc++
		}
		if f.NoFix {
			nofix++
		}
	}
	if acc != 2 || nofix != 1 {
		t.Errorf("flags: accepted=%d noFix=%d findings=%+v", acc, nofix, after.Findings)
	}
}
