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

// fetch downloads the manifest of the latest release and keeps the asset URLs.
func (u *updater) fetch(ctx context.Context, repo string) (*relManifest, map[string]string, error) {
	b, err := u.get(ctx, u.api+"/repos/"+repo+"/releases/latest", 4<<20)
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
		return nil, nil, fmt.Errorf("the latest release has no %s asset", manifestAsset)
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
	st.CanApply = st.ServerNewer && u.pub != nil && (runtime.GOOS == "linux")
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
	m, urls, err := u.fetch(ctx, repo)
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
func (s *Server) applyServerUpdate(ctx context.Context) (string, error) {
	u := s.upd
	u.mu.Lock()
	if u.busy {
		u.mu.Unlock()
		return "", errors.New("an update is already running")
	}
	u.busy = true
	u.mu.Unlock()
	defer func() { u.mu.Lock(); u.busy = false; u.mu.Unlock() }()

	if runtime.GOOS != "linux" || u.exe == "" {
		return "", errors.New("in-place server updates are supported on Linux only")
	}
	if s.cfg.Version == "dev" {
		return "", errors.New("this is a development build; it is not updated from releases")
	}
	repo := s.db.settings().UpdateRepo
	if repo == "" {
		return "", errors.New("set the GitHub repository first")
	}
	m, urls, err := u.fetch(ctx, repo)
	if err != nil {
		return "", err
	}
	if !semverNewer(m.Version, s.cfg.Version) {
		return "", errors.New("this server is already up to date")
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
	if len(data) < 1<<20 || string(data[:4]) != "\x7fELF" {
		return "", errors.New("downloaded file is not a Linux executable")
	}
	// Keep the old binary for rollback, then swap atomically.
	if old, err := os.ReadFile(u.exe); err == nil {
		_ = os.WriteFile(u.exe+".prev", old, 0o755)
	}
	if err := writeAtomic(u.exe, data, 0o755); err != nil {
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

func (s *Server) handleUpdateServer(w http.ResponseWriter, r *http.Request, sess *session) {
	if !s.needStepUp(w, sess) {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Minute)
	defer cancel()
	v, err := s.applyServerUpdate(ctx)
	if err != nil {
		writeErr(w, 502, err.Error())
		return
	}
	s.record(r, "server_updated", "", v)
	writeJSON(w, 200, map[string]any{"ok": true, "version": v, "restarting": s.upd.exit != nil})
}
