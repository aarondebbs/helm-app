package server

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// The CVE engine maps installed software to NVD products (vendor:product), downloads each
// product's CVEs once (cached for a week) and evaluates the installed version against the version
// ranges locally. It is deliberately conservative: software it cannot identify is reported as
// "not assessed" instead of guessed. NVD "AND" configurations (software that is only vulnerable on a
// given platform) are not evaluated, so matches are "potentially affected".

// CPERange is one vulnerable version constraint of a CVE for a product.
type CPERange struct {
	Ver string `json:"v,omitempty"` // exact version; "" = use the range fields; "*" = all versions
	SI  string `json:"si,omitempty"`
	SE  string `json:"se,omitempty"`
	EI  string `json:"ei,omitempty"`
	EE  string `json:"ee,omitempty"`
}

// CVERec is a cached vulnerability.
type CVERec struct {
	ID    string     `json:"id"`
	Score float64    `json:"score"`
	Sev   string     `json:"sev"`
	Sum   string     `json:"sum"`
	Pub   string     `json:"pub"`
	KEV   bool       `json:"kev,omitempty"` // known exploited (CISA KEV)
	R     []CPERange `json:"r"`
}

type cveProduct struct {
	Fetched time.Time `json:"fetched"`
	CVEs    []CVERec  `json:"cves"`
}

type cpeMapEntry struct {
	Vendor  string    `json:"vendor,omitempty"`
	Product string    `json:"product,omitempty"`
	Tried   time.Time `json:"tried"`
}

// CVEStatus describes the engine for the UI.
type CVEStatus struct {
	Products  int       `json:"products"`
	Queue     int       `json:"queue"`
	LastOK    time.Time `json:"lastOk,omitempty"`
	LastError string    `json:"lastError,omitempty"`
	HasKey    bool      `json:"hasKey"`
}

type cveEngine struct {
	mu       sync.Mutex
	path     string
	products map[string]*cveProduct
	cpemap   map[string]*cpeMapEntry
	fetchQ   []string // vendor:product awaiting download
	resolveQ []resolveReq
	queued   map[string]bool
	lastOK   time.Time
	lastErr  string
	dirty    bool
	base     string
	key      func() string
	client   *http.Client
	wake     chan struct{}
	stop     chan struct{}
	wg       sync.WaitGroup
	minGap   func() time.Duration
	failed   map[string]time.Time // key -> last failure (avoids hammering NVD)
}

type resolveReq struct{ Key, Name, Publisher string }

const (
	cveTTL         = 7 * 24 * time.Hour
	cpeMapRetry    = 14 * 24 * time.Hour
	maxCVEsProduct = 6000
)

func newCVEEngine(dir string, key func() string) *cveEngine {
	e := &cveEngine{path: filepath.Join(dir, "cve-cache.json"), products: map[string]*cveProduct{}, cpemap: map[string]*cpeMapEntry{},
		queued: map[string]bool{}, failed: map[string]time.Time{}, base: "https://services.nvd.nist.gov/rest/json", key: key,
		client: &http.Client{Timeout: 60 * time.Second}, wake: make(chan struct{}, 1), stop: make(chan struct{})}
	e.minGap = func() time.Duration {
		if e.key != nil && e.key() != "" {
			return 800 * time.Millisecond
		}
		return 6500 * time.Millisecond
	}
	if b, err := os.ReadFile(e.path); err == nil {
		var f struct {
			Products map[string]*cveProduct  `json:"products"`
			Map      map[string]*cpeMapEntry `json:"map"`
		}
		if json.Unmarshal(b, &f) == nil {
			if f.Products != nil {
				e.products = f.Products
			}
			if f.Map != nil {
				e.cpemap = f.Map
			}
		}
	}
	return e
}

func (e *cveEngine) start() {
	e.wg.Add(1)
	go e.worker()
}

func (e *cveEngine) close() {
	select {
	case <-e.stop:
		return
	default:
	}
	close(e.stop)
	e.wg.Wait()
	e.mu.Lock()
	e.saveLocked()
	e.mu.Unlock()
}

func (e *cveEngine) saveLocked() {
	if !e.dirty || e.path == "" {
		return
	}
	b, err := json.Marshal(map[string]any{"products": e.products, "map": e.cpemap})
	if err != nil {
		return
	}
	tmp := e.path + ".tmp"
	if os.WriteFile(tmp, b, 0o600) == nil && os.Rename(tmp, e.path) == nil {
		e.dirty = false
	}
}

func (e *cveEngine) status() CVEStatus {
	e.mu.Lock()
	defer e.mu.Unlock()
	return CVEStatus{Products: len(e.products), Queue: len(e.fetchQ) + len(e.resolveQ), LastOK: e.lastOK, LastError: e.lastErr, HasKey: e.key != nil && e.key() != ""}
}

// ---- software → product ----

type alias struct {
	re      *regexp.Regexp
	vendor  string
	product string
	nameVer *regexp.Regexp // when the registry DisplayVersion is unreliable, read the version from the name
}

func al(pat, vendor, product string, nameVer string) alias {
	a := alias{re: regexp.MustCompile("(?i)" + pat), vendor: vendor, product: product}
	if nameVer != "" {
		a.nameVer = regexp.MustCompile(nameVer)
	}
	return a
}

// Products whose NVD vendor:product names are well known.
var aliases = []alias{
	al(`^google chrome`, "google", "chrome", ""),
	al(`^microsoft edge$`, "microsoft", "edge_chromium", ""),
	al(`^mozilla firefox esr`, "mozilla", "firefox_esr", ""),
	al(`^mozilla firefox`, "mozilla", "firefox", ""),
	al(`^mozilla thunderbird`, "mozilla", "thunderbird", ""),
	al(`^7-zip`, "7-zip", "7-zip", ""),
	al(`^vlc media player`, "videolan", "vlc_media_player", ""),
	al(`^python \d+\.\d+`, "python", "python", `(\d+\.\d+\.\d+)`),
	al(`^git(\s|$)`, "git-scm", "git", ""),
	al(`^putty`, "putty", "putty", ""),
	al(`^winscp`, "winscp", "winscp", ""),
	al(`^filezilla`, "filezilla-project", "filezilla_client", ""),
	al(`^wireshark`, "wireshark", "wireshark", ""),
	al(`^teamviewer`, "teamviewer", "teamviewer", ""),
	al(`^anydesk`, "anydesk", "anydesk", ""),
	al(`^winrar`, "rarlab", "winrar", ""),
	al(`^libreoffice`, "libreoffice", "libreoffice", ""),
	al(`^gimp`, "gimp", "gimp", ""),
	al(`^node\.?js`, "nodejs", "node.js", ""),
	al(`^docker desktop`, "docker", "desktop", ""),
	al(`^(oracle )?vm ?virtualbox`, "oracle", "vm_virtualbox", ""),
	al(`^vmware workstation`, "vmware", "workstation", ""),
	al(`^openvpn`, "openvpn", "openvpn", ""),
	al(`^microsoft visual studio code`, "microsoft", "visual_studio_code", ""),
}

var (
	reParen    = regexp.MustCompile(`\([^)]*\)`)
	reNonWord  = regexp.MustCompile(`[^a-z0-9+#.]+`)
	reVerToken = regexp.MustCompile(`^v?\d[\d.]*$`)
	noiseWords = map[string]bool{"x64": true, "x86": true, "64-bit": true, "32-bit": true, "64bit": true, "32bit": true, "setup": true,
		"installer": true, "version": true, "update": true, "edition": true, "the": true, "for": true, "windows": true, "and": true}
	pubNoise = map[string]bool{"inc": true, "inc.": true, "ltd": true, "ltd.": true, "llc": true, "corporation": true, "corp": true, "corp.": true,
		"foundation": true, "project": true, "the": true, "software": true, "co": true, "gmbh": true, "limited": true}
)

func nameTokens(name string) []string {
	n := strings.ToLower(reParen.ReplaceAllString(name, " "))
	var out []string
	for _, t := range strings.Fields(reNonWord.ReplaceAllString(n, " ")) {
		t = strings.Trim(t, ".")
		if t == "" || noiseWords[t] || reVerToken.MatchString(t) {
			continue
		}
		out = append(out, t)
	}
	return out
}

func pubTokens(pub string) []string {
	var out []string
	for _, t := range strings.Fields(reNonWord.ReplaceAllString(strings.ToLower(pub), " ")) {
		t = strings.Trim(t, ".,")
		if t != "" && !pubNoise[t] {
			out = append(out, t)
		}
	}
	return out
}

func softwareKey(name string) string { return strings.Join(nameTokens(name), " ") }

// resolveSoftware returns the NVD product for an installed program if known; otherwise it queues
// a lookup and returns pending=true.
func (e *cveEngine) resolveSoftware(sw SoftwareItem) (vendor, product, version string, pending bool) {
	version = sw.Version
	for _, a := range aliases {
		if a.re.MatchString(sw.Name) {
			if a.nameVer != nil {
				if m := a.nameVer.FindString(sw.Name); m != "" {
					version = m
				}
			}
			return a.vendor, a.product, version, false
		}
	}
	key := softwareKey(sw.Name)
	if key == "" || len(strings.Fields(key)) == 0 || isMicrosoftNoise(sw) {
		return "", "", version, false
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	m := e.cpemap[key]
	if m != nil && time.Since(m.Tried) < cpeMapRetry {
		return m.Vendor, m.Product, version, false
	}
	if !e.queued["r:"+key] && time.Since(e.failed["r:"+key]) > 15*time.Minute {
		e.queued["r:"+key] = true
		e.resolveQ = append(e.resolveQ, resolveReq{Key: key, Name: sw.Name, Publisher: sw.Publisher})
		e.nudge()
	}
	return "", "", version, true
}

func isMicrosoftNoise(sw SoftwareItem) bool {
	n := strings.ToLower(sw.Name)
	return strings.HasPrefix(n, "microsoft visual c++") || strings.HasPrefix(n, "microsoft .net") ||
		strings.HasPrefix(n, "microsoft update health") || strings.HasPrefix(n, "windows driver package") ||
		strings.HasPrefix(n, "update for windows") || strings.HasPrefix(n, "security update for")
}

func (e *cveEngine) nudge() {
	select {
	case e.wake <- struct{}{}:
	default:
	}
}

// matchCVEs returns the CVEs affecting vendor:product at version. cached=false means the product's
// data has not been downloaded yet (a download has been queued).
func (e *cveEngine) matchCVEs(vendor, product, version string) (recs []CVERec, cached bool) {
	key := vendor + ":" + product
	e.mu.Lock()
	p := e.products[key]
	if p == nil || time.Since(p.Fetched) > cveTTL {
		if !e.queued["f:"+key] && time.Since(e.failed["f:"+key]) > 15*time.Minute {
			e.queued["f:"+key] = true
			e.fetchQ = append(e.fetchQ, key)
			e.nudge()
		}
	}
	if p == nil {
		e.mu.Unlock()
		return nil, false
	}
	cves := p.CVEs
	e.mu.Unlock()
	for _, c := range cves {
		for _, r := range c.R {
			if versionInRange(version, r) {
				recs = append(recs, c)
				break
			}
		}
	}
	sort.Slice(recs, func(i, j int) bool {
		if recs[i].KEV != recs[j].KEV {
			return recs[i].KEV
		}
		return recs[i].Score > recs[j].Score
	})
	return recs, true
}

// ---- version comparison ----

var reSeg = regexp.MustCompile(`\d+|[a-zA-Z]+`)

// cmpVer compares dotted versions numerically (1.10 > 1.9). Non-numeric tags sort below numbers.
func cmpVer(a, b string) int {
	sa, sb := reSeg.FindAllString(a, -1), reSeg.FindAllString(b, -1)
	n := len(sa)
	if len(sb) > n {
		n = len(sb)
	}
	for i := 0; i < n; i++ {
		var x, y string
		if i < len(sa) {
			x = sa[i]
		} else {
			x = "0"
		}
		if i < len(sb) {
			y = sb[i]
		} else {
			y = "0"
		}
		xn, xe := strconv.ParseUint(x, 10, 64)
		yn, ye := strconv.ParseUint(y, 10, 64)
		switch {
		case xe == nil && ye == nil:
			if xn != yn {
				if xn < yn {
					return -1
				}
				return 1
			}
		case xe == nil: // number > tag
			return 1
		case ye == nil:
			return -1
		default:
			if c := strings.Compare(strings.ToLower(x), strings.ToLower(y)); c != 0 {
				return c
			}
		}
	}
	return 0
}

func versionInRange(ver string, r CPERange) bool {
	ver = strings.TrimSpace(ver)
	if ver == "" {
		return false
	}
	if r.Ver == "*" && r.SI == "" && r.SE == "" && r.EI == "" && r.EE == "" {
		return true
	}
	if r.Ver != "" && r.Ver != "*" {
		return cmpVer(ver, r.Ver) == 0
	}
	if r.SI != "" && cmpVer(ver, r.SI) < 0 {
		return false
	}
	if r.SE != "" && cmpVer(ver, r.SE) <= 0 {
		return false
	}
	if r.EI != "" && cmpVer(ver, r.EI) > 0 {
		return false
	}
	if r.EE != "" && cmpVer(ver, r.EE) >= 0 {
		return false
	}
	return true
}

// ---- NVD client ----

type nvdCVEPage struct {
	TotalResults    int `json:"totalResults"`
	ResultsPerPage  int `json:"resultsPerPage"`
	StartIndex      int `json:"startIndex"`
	Vulnerabilities []struct {
		CVE struct {
			ID             string `json:"id"`
			Published      string `json:"published"`
			VulnStatus     string `json:"vulnStatus"`
			CisaExploitAdd string `json:"cisaExploitAdd"`
			Descriptions   []struct {
				Lang  string `json:"lang"`
				Value string `json:"value"`
			} `json:"descriptions"`
			Metrics struct {
				V31 []nvdMetric `json:"cvssMetricV31"`
				V30 []nvdMetric `json:"cvssMetricV30"`
				V2  []nvdMetric `json:"cvssMetricV2"`
			} `json:"metrics"`
			Configurations []struct {
				Nodes []struct {
					CPEMatch []struct {
						Vulnerable bool   `json:"vulnerable"`
						Criteria   string `json:"criteria"`
						SI         string `json:"versionStartIncluding"`
						SE         string `json:"versionStartExcluding"`
						EI         string `json:"versionEndIncluding"`
						EE         string `json:"versionEndExcluding"`
					} `json:"cpeMatch"`
				} `json:"nodes"`
			} `json:"configurations"`
		} `json:"cve"`
	} `json:"vulnerabilities"`
}

type nvdMetric struct {
	CVSSData struct {
		BaseScore    float64 `json:"baseScore"`
		BaseSeverity string  `json:"baseSeverity"`
	} `json:"cvssData"`
	BaseSeverity string `json:"baseSeverity"`
}

func severityFromScore(s float64) string {
	switch {
	case s >= 9:
		return "critical"
	case s >= 7:
		return "high"
	case s >= 4:
		return "medium"
	}
	return "low"
}

// splitCPE splits a CPE 2.3 formatted string honouring backslash-escaped colons.
func splitCPE(s string) []string {
	var parts []string
	var cur strings.Builder
	for i := 0; i < len(s); i++ {
		switch {
		case s[i] == '\\' && i+1 < len(s):
			cur.WriteByte(s[i+1])
			i++
		case s[i] == ':':
			parts = append(parts, cur.String())
			cur.Reset()
		default:
			cur.WriteByte(s[i])
		}
	}
	return append(parts, cur.String())
}

// parseCVEPage converts an NVD response into cache records for vendor:product.
func parseCVEPage(body []byte, vendor, product string) (recs []CVERec, total int, err error) {
	var pg nvdCVEPage
	if err = json.Unmarshal(body, &pg); err != nil {
		return nil, 0, err
	}
	for _, v := range pg.Vulnerabilities {
		c := v.CVE
		if strings.EqualFold(c.VulnStatus, "Rejected") {
			continue
		}
		var rs []CPERange
		for _, cfg := range c.Configurations {
			for _, n := range cfg.Nodes {
				for _, m := range n.CPEMatch {
					if !m.Vulnerable {
						continue
					}
					f := splitCPE(m.Criteria)
					if len(f) < 6 || f[2] != "a" || !strings.EqualFold(f[3], vendor) || !strings.EqualFold(f[4], product) {
						continue
					}
					r := CPERange{SI: m.SI, SE: m.SE, EI: m.EI, EE: m.EE}
					switch ver := f[5]; {
					case ver == "-":
						continue
					case ver == "*" || ver == "":
						r.Ver = "*"
					default:
						r.Ver = ver
					}
					rs = append(rs, r)
				}
			}
		}
		if len(rs) == 0 {
			continue
		}
		rec := CVERec{ID: c.ID, Pub: c.Published, KEV: c.CisaExploitAdd != "", R: rs}
		for _, d := range c.Descriptions {
			if d.Lang == "en" {
				rec.Sum = d.Value
				break
			}
		}
		if len(rec.Sum) > 220 {
			rec.Sum = rec.Sum[:217] + "…"
		}
		for _, ms := range [][]nvdMetric{c.Metrics.V31, c.Metrics.V30, c.Metrics.V2} {
			if len(ms) > 0 {
				rec.Score = ms[0].CVSSData.BaseScore
				rec.Sev = strings.ToLower(ms[0].CVSSData.BaseSeverity)
				if rec.Sev == "" {
					rec.Sev = strings.ToLower(ms[0].BaseSeverity)
				}
				break
			}
		}
		if rec.Sev == "" || rec.Sev == "none" {
			rec.Sev = severityFromScore(rec.Score)
		}
		recs = append(recs, rec)
	}
	return recs, pg.TotalResults, nil
}

func (e *cveEngine) get(ctx context.Context, path string, q url.Values) ([]byte, error) {
	var lastErr error
	for attempt := 0; attempt < 3; attempt++ {
		req, _ := http.NewRequestWithContext(ctx, "GET", e.base+path+"?"+q.Encode(), nil)
		req.Header.Set("User-Agent", "helm-server")
		if e.key != nil && e.key() != "" {
			req.Header.Set("apiKey", e.key())
		}
		resp, err := e.client.Do(req)
		if err != nil {
			lastErr = err
		} else {
			b, rerr := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
			resp.Body.Close()
			switch {
			case rerr != nil:
				lastErr = rerr
			case resp.StatusCode == 200:
				return b, nil
			case resp.StatusCode == 403 || resp.StatusCode == 429 || resp.StatusCode == 503:
				lastErr = fmt.Errorf("NVD is rate limiting (HTTP %d)", resp.StatusCode)
			default:
				return nil, fmt.Errorf("NVD returned HTTP %d", resp.StatusCode)
			}
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(time.Duration(attempt+1) * 20 * time.Second):
		}
	}
	return nil, lastErr
}

func (e *cveEngine) fetchProduct(ctx context.Context, key string) error {
	vendor, product, _ := strings.Cut(key, ":")
	var all []CVERec
	start := 0
	for {
		q := url.Values{}
		q.Set("virtualMatchString", "cpe:2.3:a:"+vendor+":"+product)
		q.Set("resultsPerPage", "2000")
		q.Set("startIndex", strconv.Itoa(start))
		b, err := e.get(ctx, "/cves/2.0", q)
		if err != nil {
			return err
		}
		recs, total, err := parseCVEPage(b, vendor, product)
		if err != nil {
			return err
		}
		all = append(all, recs...)
		start += 2000
		if start >= total || start >= maxCVEsProduct {
			break
		}
		if err := e.sleep(ctx); err != nil {
			return err
		}
	}
	e.mu.Lock()
	e.products[key] = &cveProduct{Fetched: time.Now().UTC(), CVEs: all}
	e.lastOK, e.lastErr, e.dirty = time.Now().UTC(), "", true
	e.mu.Unlock()
	return nil
}

func (e *cveEngine) sleep(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(e.minGap()):
		return nil
	}
}

// pickProduct chooses the NVD product that matches the installed program, or "" if unsure.
func pickProduct(body []byte, name, publisher string) (vendor, product string) {
	var r struct {
		Products []struct {
			CPE struct {
				Name string `json:"cpeName"`
			} `json:"cpe"`
		} `json:"products"`
	}
	if json.Unmarshal(body, &r) != nil {
		return "", ""
	}
	nt := map[string]bool{}
	for _, t := range nameTokens(name) {
		nt[t] = true
	}
	pt := map[string]bool{}
	for _, t := range pubTokens(publisher) {
		pt[t] = true
	}
	tokensIn := func(s string, sets ...map[string]bool) bool {
		toks := strings.FieldsFunc(strings.ToLower(s), func(r rune) bool { return r == '_' || r == '-' || r == '.' })
		if len(toks) == 0 {
			return false
		}
		for _, t := range toks {
			ok := false
			for _, set := range sets {
				if set[t] {
					ok = true
				}
			}
			if !ok {
				return false
			}
		}
		return true
	}
	best := ""
	for _, p := range r.Products {
		f := splitCPE(p.CPE.Name)
		if len(f) < 5 || f[2] != "a" {
			continue
		}
		if tokensIn(f[4], nt) && tokensIn(f[3], nt, pt) && len(f[4]) > len(best) {
			vendor, product, best = f[3], f[4], f[4]
		}
	}
	return vendor, product
}

func (e *cveEngine) resolveOne(ctx context.Context, rq resolveReq) error {
	words := nameTokens(rq.Name)
	if len(words) > 4 {
		words = words[:4]
	}
	q := url.Values{}
	q.Set("keywordSearch", strings.Join(words, " "))
	q.Set("resultsPerPage", "40")
	b, err := e.get(ctx, "/cpes/2.0", q)
	if err != nil {
		return err
	}
	v, p := pickProduct(b, rq.Name, rq.Publisher)
	e.mu.Lock()
	e.cpemap[rq.Key] = &cpeMapEntry{Vendor: v, Product: p, Tried: time.Now().UTC()}
	e.lastOK, e.lastErr, e.dirty = time.Now().UTC(), "", true
	e.mu.Unlock()
	if p != "" {
		e.mu.Lock()
		key := v + ":" + p
		if e.products[key] == nil && !e.queued["f:"+key] {
			e.queued["f:"+key] = true
			e.fetchQ = append(e.fetchQ, key)
		}
		e.mu.Unlock()
	}
	return nil
}

func (e *cveEngine) worker() {
	defer e.wg.Done()
	ctx, cancel := context.WithCancel(context.Background())
	go func() { <-e.stop; cancel() }()
	saveT := time.NewTicker(30 * time.Second)
	defer saveT.Stop()
	for {
		e.mu.Lock()
		var job string
		var rq resolveReq
		switch {
		case len(e.resolveQ) > 0:
			rq = e.resolveQ[0]
			e.resolveQ = e.resolveQ[1:]
			job = "r"
		case len(e.fetchQ) > 0:
			job = e.fetchQ[0]
			e.fetchQ = e.fetchQ[1:]
		}
		e.mu.Unlock()
		if job == "" {
			select {
			case <-e.wake:
			case <-saveT.C:
				e.mu.Lock()
				e.saveLocked()
				e.mu.Unlock()
			case <-e.stop:
				return
			}
			continue
		}
		var err error
		if job == "r" {
			err = e.resolveOne(ctx, rq)
			e.mu.Lock()
			delete(e.queued, "r:"+rq.Key)
			e.mu.Unlock()
		} else {
			err = e.fetchProduct(ctx, job)
			e.mu.Lock()
			delete(e.queued, "f:"+job)
			e.mu.Unlock()
		}
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			e.mu.Lock()
			e.lastErr = err.Error()
			if job == "r" {
				e.failed["r:"+rq.Key] = time.Now()
			} else {
				e.failed["f:"+job] = time.Now()
			}
			e.mu.Unlock()
		}
		if e.sleep(ctx) != nil {
			return
		}
	}
}
