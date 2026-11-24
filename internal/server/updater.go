package server

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"time"

	"helm/internal/proto"
)

// Cloud updates. A release published on GitHub carries a signed manifest (helm-release.json)
// plus the binaries. Every file is signed with the same ed25519 release key that agents already
// trust, so GitHub (or anyone who can edit a release) cannot push code: a file whose signature
// does not verify is never installed. The key is compiled into this binary (Config.UpdatePubKey).

const manifestAsset = "helm-release.json"

var reRepo = regexp.MustCompile(`^[A-Za-z0-9._-]{1,80}/[A-Za-z0-9._-]{1,100}$`)

// reTag is what a release tag may look like (v1.2.3 or 1.2.3, optionally with a suffix such as -rc1).
var reTag = regexp.MustCompile(`^v?[0-9]{1,4}\.[0-9]{1,4}\.[0-9]{1,4}(-[A-Za-z0-9.]{1,20})?$`)

type relFile struct {
	Name   string `json:"name"`
	Kind   string `json:"kind"` // agent | server | dist
	OS     string `json:"os"`
	Arch   string `json:"arch"`
	SHA256 string `json:"sha256"`
	Sig    string `json:"sig"`
}

type relManifest struct {
	Version string    `json:"version"`
	Notes   string    `json:"notes,omitempty"`
	Files   []relFile `json:"files"`
}

// signedFields returns the (os, arch) strings the signature covers for a manifest entry.
func (f relFile) signedFields() (string, string) {
	switch f.Kind {
	case "server":
		return "server-" + f.OS, f.Arch
	case "dist":
		return "dist", f.Name
	}
	return f.OS, f.Arch
}

// UpdateStatus is what the portal shows.
type UpdateStatus struct {
	Repo          string            `json:"repo"`
	Current       string            `json:"current"`
	Latest        string            `json:"latest"`
	Notes         string            `json:"notes,omitempty"`
	ServerNewer   bool              `json:"serverNewer"`
	CanApply      bool              `json:"canApply"`
	Checked       time.Time         `json:"checked"`
	Error         string            `json:"error,omitempty"`
	AgentReleases map[string]string `json:"agentReleases"`
	KeyConfigured bool              `json:"keyConfigured"`
	Manual        bool              `json:"manualAgents"`
	Imported      string            `json:"imported,omitempty"`
	Platform      string            `json:"platform"`
}

// canSelfUpdate says whether this build can replace its own binary and restart.
func canSelfUpdate() bool { return runtime.GOOS == "linux" || runtime.GOOS == "windows" }

// ReleaseInfo is one entry of the version picker.
type ReleaseInfo struct {
	Tag        string    `json:"tag"`
	Version    string    `json:"version"`
	Published  time.Time `json:"published"`
	Prerelease bool      `json:"prerelease"`
	Notes      string    `json:"notes,omitempty"`
	HasServer  bool      `json:"hasServer"` // the release carries a signed build for this platform
	Current    bool      `json:"current"`
	Newer      bool      `json:"newer"`
}

type updater struct {
	mu      sync.Mutex
	st      UpdateStatus
	man     *relManifest
	busy    bool
	api     string // GitHub API base
	exe     string // path of the running binary (overridable for tests)
	exit    func() // called after a server update was installed
	client  *http.Client
	pub     ed25519.PublicKey
	rootHst string
}

func newUpdater(cfg Config) *updater {
	u := &updater{api: "https://api.github.com", client: &http.Client{Timeout: 15 * time.Minute}}
	if cfg.GitHubAPI != "" {
		u.api = strings.TrimRight(cfg.GitHubAPI, "/")
	}
	if b, err := hex.DecodeString(strings.TrimSpace(cfg.UpdatePubKey)); err == nil && len(b) == ed25519.PublicKeySize {
		u.pub = ed25519.PublicKey(b)
	}
	if pu, err := url.Parse(u.api); err == nil {
		u.rootHst = pu.Host
	}
	u.exe, _ = os.Executable()
	return u
}

// hostOK limits where assets may come from: GitHub itself, or (tests) the configured API host.
func (u *updater) hostOK(raw string) bool {
	pu, err := url.Parse(raw)
	if err != nil {
		return false
	}
	h := strings.ToLower(pu.Host)
	if h == u.rootHst {
		return true
	}
	if pu.Scheme != "https" {
		return false
	}
	return h == "github.com" || strings.HasSuffix(h, ".github.com") || strings.HasSuffix(h, ".githubusercontent.com")
}

func (u *updater) get(ctx context.Context, raw string, max int64) ([]byte, error) {
	if !u.hostOK(raw) {
		return nil, fmt.Errorf("refusing to download from %s", raw)
	}
	req, _ := http.NewRequestWithContext(ctx, "GET", raw, nil)
	req.Header.Set("User-Agent", "helm-updater")
	req.Header.Set("Accept", "application/octet-stream, application/vnd.github+json")
	resp, err := u.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("download failed: HTTP %d", resp.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > max {
		return nil, errors.New("download is larger than allowed")
	}
	return b, nil
}

type ghRelease struct {
	TagName string `json:"tag_name"`
	Assets  []struct {
		Name string `json:"name"`
		URL  string `json:"browser_download_url"`
	} `json:"assets"`
}

func (u *updater) verify(f relFile, version string, data []byte) error {
	if u.pub == nil {
		return errors.New("this server build has no release public key; updates are disabled")
	}
	sum := sha256.Sum256(data)
	got := hex.EncodeToString(sum[:])
	if !strings.EqualFold(got, f.SHA256) {
		return fmt.Errorf("%s: checksum mismatch", f.Name)
	}
	sig, err := base64.StdEncoding.DecodeString(f.Sig)
	if err != nil {
		return fmt.Errorf("%s: bad signature encoding", f.Name)
	}
	o, a := f.signedFields()
	if !ed25519.Verify(u.pub, proto.SignedMessage(version, o, a, got), sig) {
		return fmt.Errorf("%s: signature is not valid for this installation", f.Name)
	}
	return nil
}

// fetch downloads the manifest of a release (the latest one when tag is empty) and keeps the asset URLs.
func (u *updater) fetch(ctx context.Context, repo, tag string) (*relManifest, map[string]string, error) {
	path := "/releases/latest"
	if tag != "" {
		if !reTag.MatchString(tag) {
			return nil, nil, errors.New("that is not a valid version")
		}
		if !strings.HasPrefix(tag, "v") {
			tag = "v" + tag
		}
		path = "/releases/tags/" + tag
	}
	b, err := u.get(ctx, u.api+"/repos/"+repo+path, 4<<20)
	if err != nil {
		return nil, nil, err
	}
	var rel ghRelease
	if json.Unmarshal(b, &rel) != nil {
		return nil, nil, errors.New("unexpected answer from GitHub")
	}
	urls := map[string]string{}
	for _, a := range rel.Assets {
		urls[a.Name] = a.URL
	}
	mu, ok := urls[manifestAsset]
	if !ok {
		return nil, nil, fmt.Errorf("that release has no %s asset (it was not built by Helm's release workflow)", manifestAsset)
	}
	mb, err := u.get(ctx, mu, 1<<20)
	if err != nil {
		return nil, nil, err
	}
	var m relManifest
	if json.Unmarshal(mb, &m) != nil || m.Version == "" {
		return nil, nil, errors.New("release manifest is unreadable")
	}
	for _, f := range m.Files {
		if !reFile.MatchString(f.Name) || !reDir.MatchString(f.OS+"-"+f.Arch) && f.Kind != "dist" {
			return nil, nil, errors.New("release manifest contains an invalid file entry")
		}
	}
	return &m, urls, nil
}

func (s *Server) updateStatus() UpdateStatus {
	u := s.upd
	u.mu.Lock()
	st := u.st
	u.mu.Unlock()
	set := s.db.settings()
	st.Repo, st.Current, st.Manual = set.UpdateRepo, s.cfg.Version, set.ManualAgentUpdates
	st.AgentReleases, st.KeyConfigured = s.listReleases(), u.pub != nil
	st.ServerNewer = st.Latest != "" && s.cfg.Version != "dev" && semverNewer(st.Latest, s.cfg.Version)
	st.CanApply = u.pub != nil && canSelfUpdate()
	st.Platform = runtime.GOOS + "/" + runtime.GOARCH
	return st
}

// checkUpdates looks at GitHub and, unless disabled, imports newer agent releases.
func (s *Server) checkUpdates(ctx context.Context, importNow bool) error {
	u := s.upd
	repo := s.db.settings().UpdateRepo
	if repo == "" {
		return errors.New("set the GitHub repository first")
	}
	if u.pub == nil {
		return errors.New("this server build has no release public key; updates are disabled")
	}
	m, urls, err := u.fetch(ctx, repo, "")
	u.mu.Lock()
	u.st.Checked = time.Now().UTC()
	if err != nil {
		u.st.Error = err.Error()
		u.mu.Unlock()
		return err
	}
	u.st.Error, u.st.Latest, u.st.Notes, u.man = "", m.Version, m.Notes, m
	u.mu.Unlock()
	if importNow {
		n, err := s.importAgents(ctx, m, urls)
		u.mu.Lock()
		if err != nil {
			u.st.Error = err.Error()
		} else if n > 0 {
			u.st.Imported = fmt.Sprintf("%d file(s) from %s", n, m.Version)
		}
		u.mu.Unlock()
		return err
	}
	return nil
}

// importAgents verifies and installs the agent and installer files of a release.
func (s *Server) importAgents(ctx context.Context, m *relManifest, urls map[string]string) (int, error) {
	n := 0
	for _, f := range m.Files {
		if f.Kind != "agent" && f.Kind != "dist" {
			continue
		}
		dir := ""
		if f.Kind == "agent" {
			dir = f.OS + "-" + f.Arch
			if rf, ok := s.readRelease(dir); ok && !semverNewer(m.Version, rf.Version) {
				continue
			}
		} else if st, err := os.Stat(filepath.Join(s.cfg.DataDir, "dist", f.Name)); err == nil && st.Size() > 0 {
			if cur, ok := s.readDistVersion(f.Name); ok && !semverNewer(m.Version, cur) {
				continue
			}
		}
		raw, ok := urls[f.Name]
		if !ok {
			return n, fmt.Errorf("release asset %s is missing", f.Name)
		}
		data, err := s.upd.get(ctx, raw, 300<<20)
		if err != nil {
			return n, err
		}
		if err := s.upd.verify(f, m.Version, data); err != nil {
			return n, err
		}
		if f.Kind == "agent" {
			err = s.installAgentRelease(m.Version, f, dir, data)
		} else {
			err = s.installDist(m.Version, f, data)
		}
		if err != nil {
			return n, err
		}
		n++
	}
	if n > 0 {
		s.log.Printf("updates: imported %d file(s) from release %s", n, m.Version)
	}
	return n, nil
}

func writeAtomic(path string, data []byte, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, mode); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// installAgentRelease lays the file out exactly like helm-sign does, so agents keep working unchanged.
func (s *Server) installAgentRelease(version string, f relFile, dir string, data []byte) error {
	name := fmt.Sprintf("helm-agent-%s-%s-%s.exe", version, f.OS, f.Arch)
	base := filepath.Join(s.cfg.DataDir, "releases", dir)
	if err := writeAtomic(filepath.Join(base, name), data, 0o644); err != nil {
		return err
	}
	if f.OS != "windows" { // the install scripts fetch the raw binary from /dl/
		if err := writeAtomic(filepath.Join(s.cfg.DataDir, "dist", "helm-agent-"+f.OS+"-"+f.Arch), data, 0o755); err != nil {
			return err
		}
	}
	meta, _ := json.MarshalIndent(releaseFile{Version: version, File: name, SHA256: strings.ToLower(f.SHA256), Sig: f.Sig}, "", "  ")
	return writeAtomic(filepath.Join(base, "latest.json"), meta, 0o644)
}

func (s *Server) installDist(version string, f relFile, data []byte) error {
	mode := os.FileMode(0o644)
	if strings.HasSuffix(f.Name, ".sh") {
		mode = 0o755
	}
	p := filepath.Join(s.cfg.DataDir, "dist", f.Name)
	if err := writeAtomic(p, data, mode); err != nil {
		return err
	}
	return writeAtomic(p+".version", []byte(version), 0o644)
}

func (s *Server) readDistVersion(name string) (string, bool) {
	b, err := os.ReadFile(filepath.Join(s.cfg.DataDir, "dist", name+".version"))
	return strings.TrimSpace(string(b)), err == nil && len(b) > 0
}

// applyServerUpdate downloads, verifies and installs the new server binary, then restarts.
func (s *Server) applyServerUpdate(ctx context.Context, want string) (string, error) {
	u := s.upd
	u.mu.Lock()
	if u.busy {
		u.mu.Unlock()
		return "", errors.New("an update is already running")
	}
	u.busy = true
	u.mu.Unlock()
	defer func() { u.mu.Lock(); u.busy = false; u.mu.Unlock() }()

	if !canSelfUpdate() || u.exe == "" {
		return "", errors.New("in-place server updates are supported on Linux and Windows only")
	}
	if s.cfg.Version == "dev" {
		return "", errors.New("this is a development build; it is not updated from releases")
	}
	repo := s.db.settings().UpdateRepo
	if repo == "" {
		return "", errors.New("set the GitHub repository first")
	}
	m, urls, err := u.fetch(ctx, repo, want)
	if err != nil {
		return "", err
	}
	if want == "" && !semverNewer(m.Version, s.cfg.Version) {
		return "", errors.New("this server is already up to date")
	}
	if want != "" && parseVer(m.Version) == parseVer(s.cfg.Version) && strings.TrimPrefix(m.Version, "v") == strings.TrimPrefix(s.cfg.Version, "v") {
		return "", errors.New("this server already runs that version")
	}
	var f *relFile
	for i := range m.Files {
		if m.Files[i].Kind == "server" && m.Files[i].OS == runtime.GOOS && m.Files[i].Arch == runtime.GOARCH {
			f = &m.Files[i]
		}
	}
	if f == nil {
		return "", fmt.Errorf("the release has no server build for %s/%s", runtime.GOOS, runtime.GOARCH)
	}
	raw, ok := urls[f.Name]
	if !ok {
		return "", fmt.Errorf("release asset %s is missing", f.Name)
	}
	data, err := u.get(ctx, raw, 200<<20)
	if err != nil {
		return "", err
	}
	if err := u.verify(*f, m.Version, data); err != nil {
		return "", err
	}
	if len(data) < 1<<20 || !looksExecutable(data) {
		return "", fmt.Errorf("downloaded file is not a %s executable", runtime.GOOS)
	}
	// A restore point first: an older version may not understand data a newer one wrote.
	if _, err := s.makeBackup("pre-update"); err != nil {
		s.log.Printf("updates: could not take a backup before updating: %v", err)
	}
	if err := swapBinary(u.exe, data); err != nil {
		return "", fmt.Errorf("could not replace the server binary: %w", err)
	}
	// Bring the agents along while we are here (best effort; verified the same way).
	_, _ = s.importAgents(ctx, m, urls)
	s.log.Printf("updates: installed server %s (previous kept as %s.prev); restarting", m.Version, filepath.Base(u.exe))
	if u.exit != nil {
		go func() { time.Sleep(1500 * time.Millisecond); u.exit() }()
	}
	return m.Version, nil
}

func looksExecutable(b []byte) bool {
	if runtime.GOOS == "windows" {
		return len(b) > 2 && b[0] == 'M' && b[1] == 'Z'
	}
	return len(b) > 4 && string(b[:4]) == "\x7fELF"
}

// swapBinary installs data as the running executable and keeps the old one as <exe>.prev.
// Windows will not overwrite a running .exe but does allow renaming it, so the old file is moved aside first.
func swapBinary(exe string, data []byte) error {
	prev := exe + ".prev"
	_ = os.Remove(prev)
	if err := os.Rename(exe, prev); err != nil {
		return err
	}
	if err := writeAtomic(exe, data, 0o755); err != nil {
		_ = os.Rename(prev, exe) // put the old one back
		return err
	}
	return nil
}

// listGitHubReleases returns the releases of the repository that Helm's workflow built, newest first.
func (s *Server) listGitHubReleases(ctx context.Context) ([]ReleaseInfo, error) {
	repo := s.db.settings().UpdateRepo
	if repo == "" {
		return nil, errors.New("set the GitHub repository first")
	}
	b, err := s.upd.get(ctx, s.upd.api+"/repos/"+repo+"/releases?per_page=30", 8<<20)
	if err != nil {
		return nil, err
	}
	var raw []struct {
		TagName    string    `json:"tag_name"`
		Prerelease bool      `json:"prerelease"`
		Draft      bool      `json:"draft"`
		Published  time.Time `json:"published_at"`
		Body       string    `json:"body"`
		Assets     []struct {
			Name string `json:"name"`
		} `json:"assets"`
	}
	if json.Unmarshal(b, &raw) != nil {
		return nil, errors.New("unexpected answer from GitHub")
	}
	want := "helm-server-" + runtime.GOOS + "-" + runtime.GOARCH
	if runtime.GOOS == "windows" {
		want += ".exe"
	}
	out := []ReleaseInfo{}
	for _, r := range raw {
		if r.Draft || !reTag.MatchString(r.TagName) {
			continue
		}
		ri := ReleaseInfo{Tag: r.TagName, Version: strings.TrimPrefix(r.TagName, "v"), Published: r.Published, Prerelease: r.Prerelease, Notes: clip(r.Body, 6000)}
		hasManifest := false
		for _, a := range r.Assets {
			if a.Name == want {
				ri.HasServer = true
			}
			if a.Name == manifestAsset {
				hasManifest = true
			}
		}
		if !hasManifest {
			continue
		}
		ri.Current = ri.Version == strings.TrimPrefix(s.cfg.Version, "v")
		ri.Newer = semverNewer(ri.Version, s.cfg.Version)
		out = append(out, ri)
	}
	return out, nil
}

// autoUpdateCheck runs periodically.
func (s *Server) autoUpdateCheck() {
	if s.db.settings().UpdateRepo == "" || s.upd.pub == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Minute)
	defer cancel()
	if err := s.checkUpdates(ctx, !s.db.settings().ManualAgentUpdates); err != nil {
		s.log.Printf("updates: %v", err)
	}
}

func (s *Server) handleUpdateGet(w http.ResponseWriter, r *http.Request, sess *session) {
	writeJSON(w, 200, s.updateStatus())
}

func (s *Server) handleUpdateCheck(w http.ResponseWriter, r *http.Request, sess *session) {
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Minute)
	defer cancel()
	if err := s.checkUpdates(ctx, false); err != nil {
		writeErr(w, 502, err.Error())
		return
	}
	writeJSON(w, 200, s.updateStatus())
}

// handleUpdateAgents imports the agent releases now.
func (s *Server) handleUpdateAgents(w http.ResponseWriter, r *http.Request, sess *session) {
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Minute)
	defer cancel()
	if err := s.checkUpdates(ctx, true); err != nil {
		writeErr(w, 502, err.Error())
		return
	}
	s.record(r, "agents_updated", "", s.updateStatus().Latest)
	writeJSON(w, 200, s.updateStatus())
}

func (s *Server) handleUpdateReleases(w http.ResponseWriter, r *http.Request, sess *session) {
	ctx, cancel := context.WithTimeout(r.Context(), time.Minute)
	defer cancel()
	list, err := s.listGitHubReleases(ctx)
	if err != nil {
		writeErr(w, 502, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"releases": list, "current": s.cfg.Version, "platform": runtime.GOOS + "/" + runtime.GOARCH})
}

func (s *Server) handleUpdateServer(w http.ResponseWriter, r *http.Request, sess *session) {
	if !s.needStepUp(w, sess) {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Minute)
	defer cancel()
	var req struct {
		Version string `json:"version"`
	}
	if r.ContentLength > 0 {
		if !readJSON(w, r, &req) {
			return
		}
	}
	v, err := s.applyServerUpdate(ctx, strings.TrimSpace(req.Version))
	if err != nil {
		writeErr(w, 502, err.Error())
		return
	}
	s.record(r, "server_updated", "", v)
	writeJSON(w, 200, map[string]any{"ok": true, "version": v, "restarting": s.upd.exit != nil})
}
