package server

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type fakeRelease struct {
	version string
	files   map[string][]byte
	man     relManifest
}

func buildFakeRelease(t *testing.T, priv ed25519.PrivateKey, version string, tamper bool) *fakeRelease {
	t.Helper()
	big := append([]byte("\x7fELF"), bytes.Repeat([]byte{1}, 1<<20+10)...)
	big = append(big, []byte(version)...)
	r := &fakeRelease{version: version, files: map[string][]byte{
		"helm-agent-windows-amd64.exe": []byte("MZ-agent-" + version),
		"helm-agent-linux-arm64":       []byte("ELF-agent-" + version),
		"Helm-Agent.template.msi":      []byte("msi-" + version),
		"install-linux.sh":             []byte("#!/bin/sh\necho hi\n"),
	}}
	r.files[fmt.Sprintf("helm-server-%s-%s", runtime.GOOS, runtime.GOARCH)] = big
	r.man = relManifest{Version: version, Notes: "notes"}
	for name, data := range r.files {
		f := relFile{Name: name, Kind: "dist"}
		switch {
		case strings.HasPrefix(name, "helm-agent-"):
			p := strings.Split(strings.TrimSuffix(name, ".exe"), "-")
			f.Kind, f.OS, f.Arch = "agent", p[2], p[3]
		case strings.HasPrefix(name, "helm-server-"):
			p := strings.Split(name, "-")
			f.Kind, f.OS, f.Arch = "server", p[2], p[3]
		}
		sum := sha256.Sum256(data)
		f.SHA256 = hex.EncodeToString(sum[:])
		so, sa := f.signedFields()
		f.Sig = base64.StdEncoding.EncodeToString(ed25519.Sign(priv, []byte("helm-agent\n"+version+"\n"+so+"\n"+sa+"\n"+f.SHA256)))
		if tamper && f.Kind == "agent" && f.OS == "windows" {
			r.files[name] = []byte("MZ-evil") // content no longer matches the signed hash
		}
		r.man.Files = append(r.man.Files, f)
	}
	return r
}

func serveRelease(t *testing.T, r *fakeRelease) *httptest.Server {
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		switch {
		case req.URL.Path == "/repos/me/helm/releases/latest":
			assets := []map[string]string{{"name": manifestAsset, "browser_download_url": srv.URL + "/a/" + manifestAsset}}
			for n := range r.files {
				assets = append(assets, map[string]string{"name": n, "browser_download_url": srv.URL + "/a/" + n})
			}
			json.NewEncoder(w).Encode(map[string]any{"tag_name": "v" + r.version, "assets": assets})
		case strings.HasPrefix(req.URL.Path, "/a/"+manifestAsset):
			json.NewEncoder(w).Encode(r.man)
		case strings.HasPrefix(req.URL.Path, "/a/"):
			if b, ok := r.files[strings.TrimPrefix(req.URL.Path, "/a/")]; ok {
				w.Write(b)
				return
			}
			http.NotFound(w, req)
		default:
			http.NotFound(w, req)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func updServer(t *testing.T, api string, pub ed25519.PublicKey, version string) *Server {
	t.Helper()
	s, err := New(Config{DataDir: t.TempDir(), Listen: "127.0.0.1:0", Dev: true, Version: version,
		UpdatePubKey: hex.EncodeToString(pub), GitHubAPI: api})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	s.db.update(func(d *dbData) { d.Settings.UpdateRepo = "me/helm" })
	return s
}

func TestCloudUpdateImportsAgents(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	srv := serveRelease(t, buildFakeRelease(t, priv, "0.4.0", false))
	s := updServer(t, srv.URL, pub, "0.3.1")
	if err := s.checkUpdates(t.Context(), true); err != nil {
		t.Fatal(err)
	}
	st := s.updateStatus()
	if st.Latest != "0.4.0" || !st.ServerNewer {
		t.Fatalf("status: %+v", st)
	}
	rf, ok := s.readRelease("windows-amd64")
	if !ok || rf.Version != "0.4.0" {
		t.Fatalf("windows release not imported: %+v %v", rf, ok)
	}
	if b, _ := os.ReadFile(filepath.Join(s.cfg.DataDir, "releases", "windows-amd64", rf.File)); string(b) != "MZ-agent-0.4.0" {
		t.Errorf("agent file content %q", b)
	}
	if _, ok := s.readRelease("linux-arm64"); !ok {
		t.Error("linux release not imported")
	}
	if b, _ := os.ReadFile(filepath.Join(s.cfg.DataDir, "dist", "Helm-Agent.template.msi")); string(b) != "msi-0.4.0" {
		t.Errorf("template msi %q", b)
	}
	if fi, err := os.Stat(filepath.Join(s.cfg.DataDir, "dist", "install-linux.sh")); err != nil || fi.Mode()&0o100 == 0 {
		t.Errorf("install script missing or not executable: %v", err)
	}
	// A second run changes nothing and a stale release is never imported over a newer one.
	if err := s.checkUpdates(t.Context(), true); err != nil {
		t.Fatal(err)
	}
}

func TestCloudUpdateRejectsBadSignatures(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	srv := serveRelease(t, buildFakeRelease(t, priv, "0.4.0", true)) // windows file tampered
	s := updServer(t, srv.URL, pub, "0.3.1")
	err := s.checkUpdates(t.Context(), true)
	if err == nil || !strings.Contains(err.Error(), "checksum") {
		t.Fatalf("tampered file accepted: %v", err)
	}
	if _, ok := s.readRelease("windows-amd64"); ok {
		t.Error("tampered release was installed")
	}
	// A release signed by a different key is refused as well.
	_, other, _ := ed25519.GenerateKey(rand.Reader)
	srv2 := serveRelease(t, buildFakeRelease(t, other, "0.4.0", false))
	s2 := updServer(t, srv2.URL, pub, "0.3.1")
	if err := s2.checkUpdates(t.Context(), true); err == nil || !strings.Contains(err.Error(), "signature") {
		t.Fatalf("foreign signature accepted: %v", err)
	}
	// No key compiled in means updates are off.
	s3 := updServer(t, srv.URL, nil, "0.3.1")
	if err := s3.checkUpdates(t.Context(), true); err == nil {
		t.Error("update ran without a public key")
	}
}

func TestCloudUpdateServerBinary(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("linux only")
	}
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	srv := serveRelease(t, buildFakeRelease(t, priv, "0.4.0", false))
	s := updServer(t, srv.URL, pub, "0.3.1")
	exe := filepath.Join(t.TempDir(), "helm-server")
	os.WriteFile(exe, []byte("old-binary"), 0o755)
	s.upd.exe = exe
	var exited atomic.Bool
	s.upd.exit = func() { exited.Store(true) }
	v, err := s.applyServerUpdate(t.Context())
	if err != nil || v != "0.4.0" {
		t.Fatalf("apply: %v %v", v, err)
	}
	if b, _ := os.ReadFile(exe); len(b) < 1<<20 || string(b[:4]) != "\x7fELF" {
		t.Error("binary not replaced")
	}
	if b, _ := os.ReadFile(exe + ".prev"); string(b) != "old-binary" {
		t.Error("previous binary not kept for rollback")
	}
	if _, ok := s.readRelease("windows-amd64"); !ok {
		t.Error("agents were not imported with the server update")
	}
	// Up-to-date servers and dev builds refuse.
	s.cfg.Version = "0.4.0"
	if _, err := s.applyServerUpdate(t.Context()); err == nil {
		t.Error("updated to the same version")
	}
	s.cfg.Version = "dev"
	if _, err := s.applyServerUpdate(t.Context()); err == nil {
		t.Error("dev build accepted an update")
	}
	for i := 0; i < 40 && !exited.Load(); i++ {
		sleep50()
	}
	if !exited.Load() {
		t.Error("restart hook not called")
	}
}

func sleep50() { time.Sleep(50 * time.Millisecond) }
