package server

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
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
	if !s.needStepUp(w, sess) {
		return
	}
	d, ok := s.st.device(id)
	if !ok || !d.Approved {
		writeErr(w, 404, "no such device")
		return
	}
	os := ""
	if d.Hello != nil {
		os = d.Hello.OS
	}
	var err error
	switch os {
	case "linux":
		err = s.updateLinuxPackage(id, req.Software)
	case "darwin":
		err = errors.New("macOS programs are updated by their own updater or the App Store; Helm cannot do it for you")
	default:
		err = s.updateWingetProgram(id, req.Software)
	}
	if err != nil {
		writeErr(w, 409, err.Error())
		return
	}
	s.record(r, "update_software", id, req.Software)
	_ = s.startScan(id, "update-software")
	writeJSON(w, 200, map[string]bool{"ok": true})
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
	return errors.New("no newer version of " + pkg + " is available from this system's package sources; the fix may need a different repository or a newer OS release")
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
	return errors.New("winget has no newer version of " + name + ". The vendor may not publish updates through it; update the program by hand or uninstall it")
}
