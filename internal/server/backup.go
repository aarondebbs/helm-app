package server

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

// Backups: a zip of the administrator/device store, the database and the audit log. Created daily (kept: the
// newest 14), on demand, and before any restore. Downloading or restoring needs a fresh authenticator check
// because the archive contains secrets (password hash, authenticator secret, agent credentials).

const (
	backupKeep    = 14
	backupMaxZip  = 64 << 20
	backupMaxFile = 256 << 20
)

var reBackupName = regexp.MustCompile(`^helm-(backup|prerestore|upload)-[0-9]{8}-[0-9]{6}\.zip$`)

type backupInfo struct {
	Name    string    `json:"name"`
	Size    int64     `json:"size"`
	Created time.Time `json:"created"`
}

func (s *Server) backupDir() string { return filepath.Join(s.cfg.DataDir, "backups") }

func (st *Store) snapshot() ([]byte, error) {
	st.mu.RLock()
	defer st.mu.RUnlock()
	return json.MarshalIndent(&st.d, "", "  ")
}

func (db *DB) snapshot() ([]byte, error) {
	db.mu.RLock()
	defer db.mu.RUnlock()
	return json.Marshal(&db.d)
}

// makeBackup writes a new archive; kind is "backup" or "prerestore".
func (s *Server) makeBackup(kind string) (backupInfo, error) {
	stb, err := s.st.snapshot()
	if err != nil {
		return backupInfo{}, err
	}
	dbb, err := s.db.snapshot()
	if err != nil {
		return backupInfo{}, err
	}
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	add := func(name string, b []byte) error {
		w, err := zw.Create(name)
		if err != nil {
			return err
		}
		_, err = w.Write(b)
		return err
	}
	now := time.Now().UTC()
	man, _ := json.Marshal(map[string]any{"version": s.cfg.Version, "created": now, "kind": kind})
	if err := add("manifest.json", man); err != nil {
		return backupInfo{}, err
	}
	if err := add("state.json", stb); err != nil {
		return backupInfo{}, err
	}
	if err := add("db.json", dbb); err != nil {
		return backupInfo{}, err
	}
	if ab, err := os.ReadFile(filepath.Join(s.cfg.DataDir, "audit.jsonl")); err == nil {
		if err := add("audit.jsonl", ab); err != nil {
			return backupInfo{}, err
		}
	}
	if err := zw.Close(); err != nil {
		return backupInfo{}, err
	}
	if err := os.MkdirAll(s.backupDir(), 0o700); err != nil {
		return backupInfo{}, err
	}
	name := fmt.Sprintf("helm-%s-%s.zip", kind, now.Format("20060102-150405"))
	path := filepath.Join(s.backupDir(), name)
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, buf.Bytes(), 0o600); err != nil {
		return backupInfo{}, err
	}
	if err := os.Rename(tmp, path); err != nil {
		return backupInfo{}, err
	}
	s.pruneBackups()
	return backupInfo{Name: name, Size: int64(buf.Len()), Created: now}, nil
}

func (s *Server) listBackups() []backupInfo {
	out := []backupInfo{}
	ents, _ := os.ReadDir(s.backupDir())
	for _, e := range ents {
		if !reBackupName.MatchString(e.Name()) {
			continue
		}
		fi, err := e.Info()
		if err != nil {
			continue
		}
		out = append(out, backupInfo{Name: e.Name(), Size: fi.Size(), Created: fi.ModTime().UTC()})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Created.After(out[j].Created) })
	return out
}

// pruneBackups keeps the newest backupKeep scheduled/manual archives; restore safety copies are kept too but pruned the same way.
func (s *Server) pruneBackups() {
	l := s.listBackups()
	for i := backupKeep; i < len(l); i++ {
		_ = os.Remove(filepath.Join(s.backupDir(), l[i].Name))
	}
}

func (s *Server) autoBackup() {
	l := s.listBackups()
	if len(l) > 0 && time.Since(l[0].Created) < 23*time.Hour {
		return
	}
	if _, err := s.makeBackup("backup"); err != nil {
		s.log.Printf("backup failed: %v", err)
	}
}

// readBackup validates an archive and returns its parts.
func readBackup(b []byte) (stateJSON, dbJSON []byte, err error) {
	zr, err := zip.NewReader(bytes.NewReader(b), int64(len(b)))
	if err != nil {
		return nil, nil, errors.New("not a valid backup archive")
	}
	read := func(f *zip.File) ([]byte, error) {
		if f.UncompressedSize64 > backupMaxFile {
			return nil, errors.New("backup file too large")
		}
		rc, err := f.Open()
		if err != nil {
			return nil, err
		}
		defer rc.Close()
		return io.ReadAll(io.LimitReader(rc, backupMaxFile+1))
	}
	for _, f := range zr.File {
		switch f.Name {
		case "state.json":
			stateJSON, err = read(f)
		case "db.json":
			dbJSON, err = read(f)
		}
		if err != nil {
			return nil, nil, err
		}
	}
	if stateJSON == nil || dbJSON == nil {
		return nil, nil, errors.New("the archive does not contain state.json and db.json")
	}
	var d data
	if err := json.Unmarshal(stateJSON, &d); err != nil || d.Admin.User == "" {
		return nil, nil, errors.New("state.json in the archive is not a valid Helm state file")
	}
	var dd dbData
	if err := json.Unmarshal(dbJSON, &dd); err != nil {
		return nil, nil, errors.New("db.json in the archive is not valid")
	}
	return stateJSON, dbJSON, nil
}

// restoreBackup replaces the live state with an archive's content.
func (s *Server) restoreBackup(b []byte) error {
	stateJSON, dbJSON, err := readBackup(b)
	if err != nil {
		return err
	}
	var d data
	if err := json.Unmarshal(stateJSON, &d); err != nil {
		return err
	}
	var dd dbData
	if err := json.Unmarshal(dbJSON, &dd); err != nil {
		return err
	}
	if _, err := s.makeBackup("prerestore"); err != nil {
		return fmt.Errorf("could not save a safety copy first: %w", err)
	}
	s.st.mu.Lock()
	s.st.d = d
	err = s.st.saveLocked()
	s.st.mu.Unlock()
	if err != nil {
		return err
	}
	s.db.update(func(cur *dbData) {
		dd.normalize()
		*cur = dd
	})
	s.db.flush()
	s.sess.destroyAll()
	return nil
}

// ---- HTTP ----

func (s *Server) handleBackupsList(w http.ResponseWriter, r *http.Request, sess *session) {
	writeJSON(w, 200, map[string]any{"backups": s.listBackups(), "keep": backupKeep})
}

func (s *Server) handleBackupCreate(w http.ResponseWriter, r *http.Request, sess *session) {
	if !s.needStepUp(w, sess) {
		return
	}
	bi, err := s.makeBackup("backup")
	if err != nil {
		writeErr(w, 500, "backup failed: "+err.Error())
		return
	}
	s.record(r, "backup_created", bi.Name, "")
	writeJSON(w, 200, bi)
}

func (s *Server) backupPath(name string) (string, bool) {
	if !reBackupName.MatchString(name) {
		return "", false
	}
	return filepath.Join(s.backupDir(), name), true
}

func (s *Server) handleBackupDownload(w http.ResponseWriter, r *http.Request, sess *session) {
	if !s.needStepUp(w, sess) {
		return
	}
	p, ok := s.backupPath(r.PathValue("name"))
	if !ok {
		writeErr(w, 400, "bad backup name")
		return
	}
	f, err := os.Open(p)
	if err != nil {
		writeErr(w, 404, "no such backup")
		return
	}
	defer f.Close()
	s.record(r, "backup_downloaded", r.PathValue("name"), "")
	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", `attachment; filename="`+r.PathValue("name")+`"`)
	w.Header().Set("Cache-Control", "no-store")
	_, _ = io.Copy(w, f)
}

func (s *Server) handleBackupRestore(w http.ResponseWriter, r *http.Request, sess *session) {
	if !s.needStepUp(w, sess) {
		return
	}
	var req struct{ Name string }
	if !readJSON(w, r, &req) {
		return
	}
	p, ok := s.backupPath(req.Name)
	if !ok {
		writeErr(w, 400, "bad backup name")
		return
	}
	b, err := os.ReadFile(p)
	if err != nil {
		writeErr(w, 404, "no such backup")
		return
	}
	s.record(r, "backup_restore", req.Name, "")
	if err := s.restoreBackup(b); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	writeJSON(w, 200, map[string]bool{"ok": true})
}

// handleBackupUpload stores an archive from another server so it can be restored by name.
func (s *Server) handleBackupUpload(w http.ResponseWriter, r *http.Request, sess *session) {
	if !s.needStepUp(w, sess) {
		return
	}
	b, err := io.ReadAll(http.MaxBytesReader(w, r.Body, backupMaxZip))
	if err != nil {
		writeErr(w, 413, "archive too large (limit 64 MB)")
		return
	}
	if _, _, err := readBackup(b); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	name := "helm-upload-" + time.Now().UTC().Format("20060102-150405") + ".zip"
	if err := os.MkdirAll(s.backupDir(), 0o700); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	if err := os.WriteFile(filepath.Join(s.backupDir(), name), b, 0o600); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	s.pruneBackups()
	s.record(r, "backup_uploaded", name, "")
	writeJSON(w, 200, map[string]string{"name": name})
}

func (s *Server) handleBackupDelete(w http.ResponseWriter, r *http.Request, sess *session) {
	if !s.needStepUp(w, sess) {
		return
	}
	p, ok := s.backupPath(r.PathValue("name"))
	if !ok {
		writeErr(w, 400, "bad backup name")
		return
	}
	_ = os.Remove(p)
	s.record(r, "backup_deleted", r.PathValue("name"), "")
	writeJSON(w, 200, map[string]bool{"ok": true})
}

// ---- health ----

var startedAt = time.Now()

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request, sess *session) {
	total, free := diskSpace(s.cfg.DataDir)
	devs := s.st.devices()
	online, approved := 0, 0
	for _, d := range devs {
		if !d.Approved {
			continue
		}
		approved++
		if s.hub.online(d.ID) != nil {
			online++
		}
	}
	bl := s.listBackups()
	var last any
	if len(bl) > 0 {
		last = bl[0]
	}
	size := func(n string) int64 {
		if fi, err := os.Stat(filepath.Join(s.cfg.DataDir, n)); err == nil {
			return fi.Size()
		}
		return 0
	}
	cs := s.cve.status()
	warnings := []string{}
	if total > 0 && float64(free)/float64(total) < 0.1 {
		warnings = append(warnings, "The disk holding Helm's data is almost full.")
	}
	if len(bl) == 0 || time.Since(bl[0].Created) > 49*time.Hour {
		warnings = append(warnings, "No recent backup. Create one now.")
	}
	if strings.TrimSpace(s.cfg.UpdatePubKey) == "" {
		warnings = append(warnings, "This server has no release key, so cloud updates are off.")
	}
	writeJSON(w, 200, map[string]any{
		"version": s.cfg.Version, "uptimeSec": int64(time.Since(startedAt).Seconds()), "time": time.Now().UTC(),
		"devices": map[string]int{"approved": approved, "online": online},
		"disk":    map[string]int64{"total": total, "free": free},
		"data":    map[string]int64{"state": size("state.json"), "db": size("db.json"), "audit": size("audit.jsonl")},
		"backups": map[string]any{"count": len(bl), "last": last, "keep": backupKeep},
		"cve":     cs, "warnings": warnings,
	})
}
