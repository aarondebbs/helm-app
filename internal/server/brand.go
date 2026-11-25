package server

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"net/http"
	"regexp"
	"strings"
	"unicode/utf8"
)

// Brand is the name and logo shown in the console itself (sign-in page and menu).
type Brand struct {
	Name string `json:"name,omitempty"`
	Logo string `json:"logo,omitempty"` // PNG as a data URL, at most 64 KB
}

// checkPNGLogo validates a PNG data URL; an empty string is fine (no logo).
func checkPNGLogo(logo string) error {
	if logo == "" {
		return nil
	}
	raw, ok := strings.CutPrefix(logo, logoPrefix)
	if !ok || len(logo) > 90000 {
		return errors.New("the logo must be a PNG of at most 64 KB")
	}
	b, err := base64.StdEncoding.DecodeString(raw)
	if err != nil || len(b) < 8 || string(b[:8]) != "\x89PNG\r\n\x1a\n" {
		return errors.New("the logo must be a PNG of at most 64 KB")
	}
	return nil
}

func (s *Server) handleBrandPut(w http.ResponseWriter, r *http.Request, sess *session) {
	if sess.Role == "viewer" {
		writeErr(w, 403, "not allowed")
		return
	}
	var req Brand
	if !readJSON(w, r, &req) {
		return
	}
	req.Name = strings.TrimSpace(req.Name)
	if utf8.RuneCountInString(req.Name) > 40 || strings.ContainsAny(req.Name, "\x00\r\n") {
		writeErr(w, 400, "the name can be up to 40 characters")
		return
	}
	if err := checkPNGLogo(req.Logo); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	s.db.update(func(d *dbData) { d.Settings.Brand = req })
	writeJSON(w, 200, map[string]any{"name": req.Name, "logo": req.Logo != ""})
}

// handleBrandLogo serves the logo to the sign-in page, which has no session yet.
func (s *Server) handleBrandLogo(w http.ResponseWriter, r *http.Request) {
	raw, ok := strings.CutPrefix(s.db.settings().Brand.Logo, logoPrefix)
	if !ok {
		http.NotFound(w, r)
		return
	}
	b, err := base64.StdEncoding.DecodeString(raw)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	sum := sha256.Sum256(b)
	etag := `"` + hex.EncodeToString(sum[:8]) + `"`
	w.Header().Set("ETag", etag)
	w.Header().Set("Content-Type", "image/png")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Security-Policy", "default-src 'none'")
	w.Header().Set("Cache-Control", "no-cache")
	if r.Header.Get("If-None-Match") == etag {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	_, _ = w.Write(b)
}

var reMakerKey = regexp.MustCompile(`^[a-z0-9][a-z0-9 .+-]{0,29}$`)

// handleMakerLogos returns the logos you uploaded for PC makers (Dell, Lenovo, Raspberry Pi...) and systems (Windows...).
func (s *Server) handleMakerLogos(w http.ResponseWriter, r *http.Request, sess *session) {
	m := s.db.settings().MakerLogos
	if m == nil {
		m = map[string]string{}
	}
	writeJSON(w, 200, m)
}

// handleMakerLogoPut sets or (with an empty logo) removes one logo. Helm ships no third-party logos; these are yours.
func (s *Server) handleMakerLogoPut(w http.ResponseWriter, r *http.Request, sess *session) {
	if sess.Role == "viewer" {
		writeErr(w, 403, "not allowed")
		return
	}
	var req struct{ Key, Logo string }
	if !readJSON(w, r, &req) {
		return
	}
	req.Key = strings.ToLower(strings.TrimSpace(req.Key))
	if !reMakerKey.MatchString(req.Key) {
		writeErr(w, 400, "the name must be 1 to 30 letters, numbers or spaces")
		return
	}
	if err := checkPNGLogo(req.Logo); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	full := false
	s.db.update(func(d *dbData) {
		if d.Settings.MakerLogos == nil {
			d.Settings.MakerLogos = map[string]string{}
		}
		if req.Logo == "" {
			delete(d.Settings.MakerLogos, req.Key)
		} else if _, had := d.Settings.MakerLogos[req.Key]; had || len(d.Settings.MakerLogos) < 40 {
			d.Settings.MakerLogos[req.Key] = req.Logo
		} else {
			full = true
		}
	})
	if full {
		writeErr(w, 400, "up to 40 logos can be stored")
		return
	}
	writeJSON(w, 200, map[string]bool{"ok": true})
}
