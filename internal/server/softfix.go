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

func (s *Server) updateLinuxPackage(id, pkg string) error {
	raw, err := s.callCmd(id, "updates.check", nil, "admin")
	if err != nil {
		return err
	}
	var res struct {
		Updates []Patch `json:"updates"`
	}
	if json.Unmarshal(raw, &res) != nil {
		return errors.New("unexpected answer from the update check")
	}
	for _, u := range res.Updates {
		if u.ID == pkg {
			args, _ := json.Marshal(map[string]any{"ids": []string{u.ID}, "reboot": false})
			_, err = s.callCmd(id, "updates.install", args, "admin")
			return err
		}
	}
	return fmt.Errorf("%w: no newer version of %s is available from this system's package sources; the fix may need a different repository or a newer OS release", errNoUpdate, pkg)
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
		return errors.New("macOS programs are updated by their own updater or the App Store; Helm cannot do it for you")
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
