package server

import (
	"bytes"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// A ready-to-run installer: dist/Helm-Agent.template.msi carries fixed-width placeholder strings as the default
// values of the SERVER, TOKEN and CONSENT properties. Windows Installer stores those strings verbatim in the
// package's string pool, so overwriting them in place (same length, padded with spaces) yields a valid MSI that
// installs and enrolls by itself. The agent trims the padding. The lengths must match installer/build-msi.sh.
const (
	phServerLen  = 160
	phTokenLen   = 96
	phConsentLen = 32
)

func placeholder(prefix string, ch byte, total int) []byte {
	return append([]byte(prefix), bytes.Repeat([]byte{ch}, total-len(prefix))...)
}

var (
	phServer  = placeholder("HELMPH_SERVER_", 'S', phServerLen)
	phToken   = placeholder("HELMPH_TOKEN_", 'T', phTokenLen)
	phConsent = placeholder("HELMPH_CONSENT_", 'C', phConsentLen)
)

func fill(b, ph []byte, val string) error {
	if len(val) > len(ph) || strings.ContainsAny(val, "\x00") {
		return errors.New("value too long for the installer")
	}
	if n := bytes.Count(b, ph); n != 1 {
		return fmt.Errorf("installer template is damaged (placeholder found %d times)", n)
	}
	rep := append([]byte(val), bytes.Repeat([]byte{' '}, len(ph)-len(val))...)
	copy(b[bytes.Index(b, ph):], rep)
	return nil
}

// personalizeMSI returns a copy of the template with the settings filled in.
func personalizeMSI(tpl []byte, server, token, consent string) ([]byte, error) {
	out := append([]byte(nil), tpl...)
	for _, f := range []struct {
		ph  []byte
		val string
	}{{phServer, server}, {phToken, token}, {phConsent, consent}} {
		if err := fill(out, f.ph, f.val); err != nil {
			return nil, err
		}
	}
	return out, nil
}

var (
	reTokenPlain = regexp.MustCompile(`^hlm_[0-9a-f]{40}$`)
	reLabelFile  = regexp.MustCompile(`[^A-Za-z0-9._-]+`)
)

// handleInstaller returns Helm-Agent.msi with the given (still valid) enrollment token built in.
func (s *Server) handleInstaller(w http.ResponseWriter, r *http.Request, sess *session) {
	var req struct{ Token, Consent, OS string }
	if !readJSON(w, r, &req) {
		return
	}
	if req.Consent == "" {
		req.Consent = "prompt_if_present"
	}
	if req.Consent != "prompt_if_present" && req.Consent != "always_prompt" && req.Consent != "unattended" {
		writeErr(w, 400, "bad consent mode")
		return
	}
	if !reTokenPlain.MatchString(req.Token) {
		writeErr(w, 400, "that is not an enrollment token")
		return
	}
	label, ok := s.st.TokenUsable(req.Token)
	if !ok {
		writeErr(w, 400, "that token is expired, used up or revoked: create a new one")
		return
	}
	if req.OS == "macos-conf" {
		// Companion file for the .pkg: drop it next to the package and the installer enrols the Mac.
		body := "SERVER=" + s.baseURL(r) + "\nTOKEN=" + req.Token + "\nCONSENT=" + req.Consent + "\n"
		s.record(r, "installer_downloaded", "", label+" (macos-conf)")
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="helm-enroll.conf"`)
		w.Header().Set("Cache-Control", "no-store")
		_, _ = w.Write([]byte(body))
		return
	}
	if req.OS == "linux" || req.OS == "macos" {
		s.serveInstallScript(w, r, req.OS, req.Token, req.Consent, label)
		return
	}
	tpl, err := os.ReadFile(filepath.Join(s.cfg.DataDir, "dist", "Helm-Agent.template.msi"))
	if err != nil {
		writeErr(w, 404, "the installer template is not on this server (copy dist/Helm-Agent.template.msi from the build)")
		return
	}
	out, err := personalizeMSI(tpl, s.baseURL(r), req.Token, req.Consent)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	name := "Helm-Agent"
	if l := strings.Trim(reLabelFile.ReplaceAllString(label, "-"), "-"); l != "" {
		if len(l) > 40 {
			l = l[:40]
		}
		name += "-" + l
	}
	s.record(r, "installer_downloaded", "", label)
	w.Header().Set("Content-Type", "application/x-msi")
	w.Header().Set("Content-Disposition", `attachment; filename="`+name+`.msi"`)
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Length", fmt.Sprint(len(out)))
	_, _ = w.Write(out)
}

// TokenUsable reports whether a plaintext enrollment token could still be used, without consuming it.
func (s *Store) TokenUsable(plain string) (label string, ok bool) {
	hash := sha256hex(plain)
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, t := range s.d.Tokens {
		if ctEq(t.Hash, hash) {
			if t.Revoked || time.Now().After(t.ExpiresAt) || (t.MaxUses > 0 && t.Uses >= t.MaxUses) {
				return "", false
			}
			return t.Label, true
		}
	}
	return "", false
}

// serveInstallScript returns the Linux or macOS install script with this server and the enrollment token
// already filled in, so the person at the machine only has to run it.
func (s *Server) serveInstallScript(w http.ResponseWriter, r *http.Request, goos, token, consent, label string) {
	file := map[string]string{"linux": "install-linux.sh", "macos": "install-macos.sh"}[goos]
	body, err := os.ReadFile(filepath.Join(s.cfg.DataDir, "dist", file))
	if err != nil {
		writeErr(w, 404, "the install script is not on this server (copy dist/"+file+" from the build)")
		return
	}
	server := s.baseURL(r)
	if !regexp.MustCompile(`^https://[A-Za-z0-9.:-]+$`).MatchString(server) && !s.cfg.Dev {
		writeErr(w, 400, "the server address is not a plain https:// address")
		return
	}
	// Values are validated above (token pattern, fixed consent set) and quoted for the shell.
	q := func(v string) string { return "'" + strings.ReplaceAll(v, "'", `'\''`) + "'" }
	lines := strings.SplitN(string(body), "\n", 2)
	if len(lines) != 2 || !strings.HasPrefix(lines[0], "#!") {
		writeErr(w, 500, "install script is malformed")
		return
	}
	pre := "set -- --server " + q(server) + " --token " + q(token) + " --consent " + q(consent) + ` "$@"` + "\n"
	out := lines[0] + "\n" + pre + lines[1]
	name := "install-" + goos
	if l := strings.Trim(reLabelFile.ReplaceAllString(label, "-"), "-"); l != "" {
		if len(l) > 40 {
			l = l[:40]
		}
		name += "-" + l
	}
	s.record(r, "installer_downloaded", "", label+" ("+goos+")")
	w.Header().Set("Content-Type", "text/x-shellscript")
	w.Header().Set("Content-Disposition", `attachment; filename="`+name+`.sh"`)
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write([]byte(out))
}
