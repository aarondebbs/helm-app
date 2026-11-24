package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// handleUpdateSoftware updates one program on one PC so that the CVEs found in it go away. It never takes a command
// from the browser: Windows looks the program up in winget's own list of available upgrades, Linux looks it up in the
// pending package updates. If the vendor has not published a newer version the answer says so plainly.
func (s *Server) handleUpdateSoftware(w http.ResponseWriter, r *http.Request, sess *session) {
	id := r.PathValue("id")
	var req struct {
		Software string `json:"software"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	if strings.TrimSpace(req.Software) == "" {
		writeErr(w, 400, "software is required")
		return
	}
	d, ok := s.st.device(id)
	if !ok || !d.Approved {
		writeErr(w, 404, "no such device")
		return
	}
	err := s.updateSoftware(d, req.Software)
	if err != nil {
		if errors.Is(err, errNoUpdate) {
			s.db.update(func(x *dbData) {
				if x.NoFix == nil {
					x.NoFix = map[string]time.Time{}
				}
				x.NoFix[id+"|"+req.Software] = time.Now().UTC()
			})
		}
		writeErr(w, 409, err.Error())
		return
	}
	s.db.update(func(x *dbData) { delete(x.NoFix, id+"|"+req.Software) })
	s.record(r, "update_software", id, req.Software)
	remaining, rescanned := s.recheck(id, req.Software)
	writeJSON(w, 200, map[string]any{"ok": true, "rescanned": rescanned, "remaining": remaining})
}

var errNoUpdate = errors.New("no update published")

// recheck rescans the PC and waits (up to four minutes) so the answer can say whether the vulnerabilities in the
// program are really gone, not just that an installer ran.
func (s *Server) recheck(id, software string) (remaining int, rescanned bool) {
	started := time.Now().UTC()
	if s.startScan(id, "recheck") != nil {
		return 0, false
	}
	for i := 0; i < 80; i++ {
		time.Sleep(3 * time.Second)
		var st string
		var at time.Time
		s.db.view(func(x *dbData) {
			if sc := x.Scans[id]; sc != nil {
				st, at = sc.Status, sc.At
			}
		})
		if st != "running" && !at.Before(started) {
			break
		}
	}
	v, ok := s.scanView(id)
	if !ok {
		return 0, false
	}
	for _, f := range v.Findings {
		if f.Kind == "cve" && f.Software == software && !f.Accepted {
			remaining++
		}
	}
	return remaining, true
}

// matchingUpdates returns the pending updates that belong to the named program: the package itself and its
// sub-packages (openssl, openssl-libs, ...). Comparison ignores case.
func matchingUpdates(ups []Patch, name string) []Patch {
	want := strings.ToLower(strings.TrimSpace(name))
	if want == "" {
		return nil
	}
	var out []Patch
	for _, u := range ups {
		id, title := strings.ToLower(u.ID), strings.ToLower(u.Title)
		switch {
		case id == want, strings.HasPrefix(id, want+"-"), strings.HasPrefix(id, want+"."), strings.HasPrefix(id, want+":"):
			out = append(out, u)
		case strings.HasPrefix(title, want+" "):
			out = append(out, u)
		}
	}
	return out
}

func (s *Server) installMatching(id, name, who string) (bool, error) {
	raw, err := s.callCmd(id, "updates.check", nil, who)
	if err != nil {
		return false, err
	}
	var res struct {
		Updates []Patch `json:"updates"`
	}
	if json.Unmarshal(raw, &res) != nil {
		return false, errors.New("unexpected answer from the update check")
	}
	m := matchingUpdates(res.Updates, name)
	if len(m) == 0 {
		return false, nil
	}
	ids := make([]string, 0, len(m))
	for _, u := range m {
		ids = append(ids, u.ID)
	}
	args, _ := json.Marshal(map[string]any{"ids": ids, "reboot": false})
	_, err = s.callCmd(id, "updates.install", args, who)
	return err == nil, err
}

func (s *Server) updateLinuxPackage(id, pkg string) error {
	ok, err := s.installMatching(id, pkg, "admin")
	if err != nil || ok {
		return err
	}
	return fmt.Errorf("%w: no newer version of %s is available from this system's package sources; the fix may need a different repository or a newer OS release", errNoUpdate, pkg)
}

// updateMacProgram fixes a program on a Mac: through Homebrew when the program came from there, otherwise through
// Apple's own updates (Safari, macOS itself and other Apple software). Apps installed by other means update themselves.
func (s *Server) updateMacProgram(id, name string) error {
	err := s.updateWingetProgram(id, name) // on a Mac this slot is Homebrew
	if err == nil {
		return nil
	}
	brewMissing := strings.Contains(err.Error(), "Homebrew is not installed")
	if !errors.Is(err, errNoUpdate) && !brewMissing {
		return err
	}
	lookup := name
	if l := strings.ToLower(name); l == "macos" || l == "mac os x" || l == "os x" {
		lookup = "macOS"
	}
	if ok, aerr := s.installMatching(id, lookup, "admin"); aerr != nil {
		return aerr
	} else if ok {
		return nil
	}
	return fmt.Errorf("%w: %s is not managed by Homebrew and Apple has no update for it. Update it with its own updater or the App Store, or remove it", errNoUpdate, name)
}

func (s *Server) updateWingetProgram(id, name string) error {
	raw, err := s.callCmd(id, "winget.list", nil, "admin")
	if err != nil {
		return err
	}
	var list struct {
		Packages []struct {
			Name      string `json:"name"`
			ID        string `json:"id"`
			Available string `json:"available"`
		} `json:"packages"`
	}
	if json.Unmarshal(raw, &list) != nil {
		var plain []struct {
			Name      string `json:"name"`
			ID        string `json:"id"`
			Available string `json:"available"`
		}
		if json.Unmarshal(raw, &plain) != nil {
			return errors.New("unexpected answer from winget")
		}
		for _, p := range plain {
			list.Packages = append(list.Packages, struct {
				Name      string `json:"name"`
				ID        string `json:"id"`
				Available string `json:"available"`
			}(p))
		}
	}
	want := strings.ToLower(strings.TrimSpace(name))
	for _, p := range list.Packages {
		n := strings.ToLower(p.Name)
		if p.Available == "" || p.ID == "" {
			continue
		}
		if n == want || strings.HasPrefix(want, n+" ") || strings.HasPrefix(n, want+" ") {
			args, _ := json.Marshal(map[string]any{"ids": []string{p.ID}})
			_, err = s.callCmd(id, "winget.upgrade", args, "admin")
			return err
		}
	}
	return fmt.Errorf("%w: winget has no newer version of %s. The vendor may not publish updates through it; update the program by hand or uninstall it", errNoUpdate, name)
}

// updateSoftware updates one program on a PC by the route that suits its operating system.
func (s *Server) updateSoftware(d Device, software string) error {
	os := ""
	if d.Hello != nil {
		os = d.Hello.OS
	}
	switch os {
	case "linux":
		return s.updateLinuxPackage(d.ID, software)
	case "darwin":
		return s.updateMacProgram(d.ID, software)
	}
	return s.updateWingetProgram(d.ID, software)
}

// patchVulnerablePrograms updates every program with an open, fixable vulnerability on a PC. Programs already known
// to have no published update are skipped, and a run is capped so one PC cannot hold the window for hours.
func (s *Server) patchVulnerablePrograms(d Device) (done int, notes []string) {
	v, ok := s.scanView(d.ID)
	if !ok {
		return 0, nil
	}
	seen := map[string]bool{}
	for _, f := range v.Findings {
		if f.Kind != "cve" || f.Software == "" || f.Accepted || f.NoFix || seen[f.Software] {
			continue
		}
		seen[f.Software] = true
		if len(seen) > 8 {
			break
		}
		err := s.updateSoftware(d, f.Software)
		switch {
		case err == nil:
			done++
		case errors.Is(err, errNoUpdate):
			s.db.update(func(x *dbData) {
				if x.NoFix == nil {
					x.NoFix = map[string]time.Time{}
				}
				x.NoFix[d.ID+"|"+f.Software] = time.Now().UTC()
			})
			notes = append(notes, f.Software+": no update published")
		default:
			notes = append(notes, f.Software+": "+err.Error())
		}
	}
	return done, notes
}
