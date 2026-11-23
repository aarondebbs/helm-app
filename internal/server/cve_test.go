package server

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestCmpVer(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"1.2.3", "1.2.3", 0}, {"1.2.3", "1.10.0", -1}, {"22.01", "23.01", -1}, {"120.0.1", "120.0", 1},
		{"2.0", "2.0.0", 0}, {"10.0.19045", "10.0.2", 1}, {"1.0-beta", "1.0", -1},
	}
	for _, c := range cases {
		if got := cmpVer(c.a, c.b); got != c.want {
			t.Errorf("cmpVer(%q,%q)=%d want %d", c.a, c.b, got, c.want)
		}
	}
}

func TestVersionInRange(t *testing.T) {
	r := CPERange{Ver: "*", SI: "1.0", EE: "2.0"}
	for v, want := range map[string]bool{"0.9": false, "1.0": true, "1.5": true, "2.0": false, "2.1": false} {
		if got := versionInRange(v, r); got != want {
			t.Errorf("version %s in [1.0,2.0) = %v want %v", v, got, want)
		}
	}
	exact := CPERange{Ver: "3.1"}
	if !versionInRange("3.1", exact) || versionInRange("3.2", exact) {
		t.Error("exact version match broken")
	}
	// unbounded wildcard matches everything
	if !versionInRange("9.9", CPERange{Ver: "*"}) {
		t.Error("wildcard should match")
	}
}

const nvdFixture = `{"totalResults":2,"vulnerabilities":[
 {"cve":{"id":"CVE-2023-0001","published":"2023-01-01T00:00:00","vulnStatus":"Analyzed","cisaExploitAdd":"2023-02-01",
   "descriptions":[{"lang":"en","value":"Old 7-Zip bug"}],
   "metrics":{"cvssMetricV31":[{"cvssData":{"baseScore":9.8,"baseSeverity":"CRITICAL"}}]},
   "configurations":[{"nodes":[{"cpeMatch":[{"vulnerable":true,"criteria":"cpe:2.3:a:7-zip:7-zip:*:*:*:*:*:*:*:*","versionEndExcluding":"23.00"}]}]}]}},
 {"cve":{"id":"CVE-2024-0002","published":"2024-01-01T00:00:00","vulnStatus":"Analyzed",
   "descriptions":[{"lang":"en","value":"Newer bug"}],
   "metrics":{"cvssMetricV31":[{"cvssData":{"baseScore":5.0,"baseSeverity":"MEDIUM"}}]},
   "configurations":[{"nodes":[{"cpeMatch":[{"vulnerable":true,"criteria":"cpe:2.3:a:7-zip:7-zip:*:*:*:*:*:*:*:*","versionStartIncluding":"24.0","versionEndExcluding":"24.5"}]}]}]}}]}`

func TestCVEEngineMatching(t *testing.T) {
	hits := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		if !strings.HasSuffix(r.URL.Path, "/cves/2.0") || !strings.HasPrefix(r.URL.Query().Get("virtualMatchString"), "cpe:2.3:a:7-zip:7-zip") {
			t.Errorf("unexpected request %s", r.URL)
		}
		fmt.Fprint(w, nvdFixture)
	}))
	defer srv.Close()
	e := newCVEEngine(t.TempDir(), nil)
	e.base = srv.URL
	e.minGap = func() time.Duration { return time.Millisecond }
	e.start()
	defer e.close()

	vendor, product, ver, pending := e.resolveSoftware(SoftwareItem{Name: "7-Zip 22.01 (x64)", Version: "22.01"})
	if pending || vendor != "7-zip" || product != "7-zip" {
		t.Fatalf("alias resolve failed: %q %q pending=%v", vendor, product, pending)
	}
	if _, cached := e.matchCVEs(vendor, product, ver); cached {
		t.Fatal("first call should be uncached")
	}
	deadline := time.Now().Add(5 * time.Second)
	var recs []CVERec
	for time.Now().Before(deadline) {
		var cached bool
		if recs, cached = e.matchCVEs(vendor, product, ver); cached {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if len(recs) != 1 || recs[0].ID != "CVE-2023-0001" || !recs[0].KEV || recs[0].Sev != "critical" {
		t.Fatalf("22.01 should match only CVE-2023-0001 (KEV): %+v", recs)
	}
	if r2, _ := e.matchCVEs(vendor, product, "24.2"); len(r2) != 1 || r2[0].ID != "CVE-2024-0002" {
		t.Fatalf("24.2 should match only CVE-2024-0002: %+v", r2)
	}
	if r3, _ := e.matchCVEs(vendor, product, "24.9"); len(r3) != 0 {
		t.Fatalf("24.9 is fixed: %+v", r3)
	}
	if hits != 1 {
		t.Errorf("product should be downloaded once, got %d requests", hits)
	}
}

func TestCVEFailureBackoff(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits.Add(1); http.Error(w, "no", 503) }))
	defer srv.Close()
	e := newCVEEngine(t.TempDir(), nil)
	e.base = srv.URL
	e.minGap = func() time.Duration { return time.Millisecond }
	e.start()
	defer e.close()
	for i := 0; i < 20; i++ {
		e.matchCVEs("7-zip", "7-zip", "1.0")
		time.Sleep(15 * time.Millisecond)
	}
	if n := hits.Load(); n > 2 {
		t.Errorf("failed downloads must back off, saw %d requests", n)
	}
}

func TestFindingsAndScore(t *testing.T) {
	s := &Server{cve: newCVEEngine(t.TempDir(), nil)}
	s.cve.products["7-zip:7-zip"] = &cveProduct{Fetched: time.Now(), CVEs: []CVERec{{ID: "CVE-1", Score: 9.8, Sev: "critical", KEV: true, R: []CPERange{{Ver: "*", EE: "23.0"}}}}}
	sc := &Scan{Status: "done",
		Software: []SoftwareItem{{Name: "7-Zip 22.01 (x64)", Version: "22.01"}},
		Checks:   []ConfigCheck{{ID: "fw", Title: "Firewall off", Severity: "high", Status: "fail"}, {ID: "ok", Status: "pass"}, {ID: "reb", Title: "Reboot", Severity: "low", Status: "warn"}},
		Ports:    []PortItem{{Port: 3389, Address: "0.0.0.0"}, {Port: 5432, Address: "127.0.0.1"}, {Port: 23, Address: "::"}},
		Patches:  []Patch{{Title: "KB1", Severity: "Critical"}}}
	v := s.computeFindings(sc)
	kinds := map[string]int{}
	for _, f := range v.Findings {
		kinds[f.Kind]++
		if f.Kind == "port" && strings.Contains(f.Key, "5432") {
			t.Error("loopback-only port must not be reported")
		}
	}
	if kinds["cve"] != 1 || kinds["config"] != 2 || kinds["port"] != 2 || kinds["patch"] != 1 {
		t.Fatalf("unexpected finding mix: %v", kinds)
	}
	if v.Findings[0].Severity != "critical" {
		t.Errorf("findings must be sorted by severity, first is %s", v.Findings[0].Severity)
	}
	if v.Score >= 100 || v.Score < 0 {
		t.Errorf("score out of range: %d", v.Score)
	}
	clean := s.computeFindings(&Scan{Status: "done"})
	if clean.Score != 100 || len(clean.Findings) != 0 {
		t.Errorf("clean scan should score 100: %d", clean.Score)
	}
}
