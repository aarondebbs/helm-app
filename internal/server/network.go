package server

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"helm/internal/netscan"
)

// Network discovery: scan the network a PC (or the server) is on, then install Helm on the Windows PCs found.

type scanSource struct {
	ID     string   `json:"id"` // "server" or a device id
	Name   string   `json:"name"`
	CIDRs  []string `json:"cidrs"`
	OS     string   `json:"os,omitempty"`
	Server bool     `json:"server,omitempty"`
}

type netHost struct {
	netscan.Host
	Managed  string `json:"managed,omitempty"` // device id when the PC already runs Helm
	ManagedN string `json:"managedName,omitempty"`
}

type netResult struct {
	Source string    `json:"source"`
	CIDR   string    `json:"cidr"`
	At     time.Time `json:"at"`
	Hosts  []netHost `json:"hosts"`
}

var lastNet struct {
	sync.Mutex
	r *netResult
}

func cidr24(ip string) string {
	p := net.ParseIP(ip)
	if p == nil || p.To4() == nil || !p.IsPrivate() {
		return ""
	}
	return (&net.IPNet{IP: p.Mask(net.CIDRMask(24, 32)), Mask: net.CIDRMask(24, 32)}).String()
}

func (s *Server) handleNetSources(w http.ResponseWriter, r *http.Request, sess *session) {
	out := []scanSource{}
	for _, d := range s.st.devices() {
		if !d.Approved || d.Hello == nil || s.hub.online(d.ID) == nil {
			continue
		}
		seen := map[string]bool{}
		var c []string
		for _, ip := range d.Hello.IPs {
			if n := cidr24(ip); n != "" && !seen[n] {
				seen[n] = true
				c = append(c, n)
			}
		}
		if len(c) > 0 {
			out = append(out, scanSource{ID: d.ID, Name: d.Name, CIDRs: c, OS: d.Hello.OS})
		}
	}
	if c := netscan.LocalCIDRs(); len(c) > 0 {
		out = append(out, scanSource{ID: "server", Name: "The Helm server", CIDRs: c, Server: true})
	}
	lastNet.Lock()
	last := lastNet.r
	lastNet.Unlock()
	writeJSON(w, 200, map[string]any{"sources": out, "last": last})
}

func (s *Server) annotate(hosts []netscan.Host) []netHost {
	byIP, byMAC := map[string]Device{}, map[string]Device{}
	for _, d := range s.st.devices() {
		if d.Hello == nil {
			continue
		}
		for _, ip := range d.Hello.IPs {
			byIP[ip] = d
		}
		for _, m := range d.Hello.MACs {
			byMAC[strings.ToLower(m)] = d
		}
	}
	out := make([]netHost, 0, len(hosts))
	for _, h := range hosts {
		n := netHost{Host: h}
		d, ok := byIP[h.IP]
		if !ok && h.MAC != "" {
			d, ok = byMAC[strings.ToLower(h.MAC)]
		}
		if ok {
			n.Managed, n.ManagedN = d.ID, d.Name
		}
		out = append(out, n)
	}
	return out
}

func (s *Server) handleNetScan(w http.ResponseWriter, r *http.Request, sess *session) {
	var req struct{ Source, CIDR string }
	if !readJSON(w, r, &req) {
		return
	}
	var raw struct {
		CIDR  string         `json:"cidr"`
		Hosts []netscan.Host `json:"hosts"`
	}
	if req.Source == "" || req.Source == "server" {
		tid := "netscan-" + randHex(6)
		s.taskStart(tid, "net.scan", "Network scan", "", sess.User)
		ctx, cancel := context.WithTimeout(r.Context(), 4*time.Minute)
		defer cancel()
		cidr := strings.TrimSpace(req.CIDR)
		if cidr == "" {
			l := netscan.LocalCIDRs()
			if len(l) == 0 {
				s.taskFinish(tid, "the server is not on a private network")
				writeErr(w, 409, "the server is not on a private network; pick a PC to scan from")
				return
			}
			cidr = l[0]
		}
		hosts, err := netscan.Scan(ctx, cidr, func(p int, m string) { s.taskUpdate(tid, p, m) })
		if err != nil {
			s.taskFinish(tid, err.Error())
			writeErr(w, 400, err.Error())
			return
		}
		s.taskFinish(tid, "")
		raw.CIDR, raw.Hosts = cidr, hosts
	} else {
		if _, ok := s.st.device(req.Source); !ok {
			writeErr(w, 404, "unknown PC")
			return
		}
		args, _ := json.Marshal(map[string]string{"cidr": req.CIDR})
		data, err := s.callCmd(req.Source, "net.scan", args, sess.User)
		if err != nil {
			writeErr(w, 409, err.Error())
			return
		}
		if err := json.Unmarshal(data, &raw); err != nil {
			writeErr(w, 500, "bad scan result")
			return
		}
	}
	res := &netResult{Source: req.Source, CIDR: raw.CIDR, At: time.Now().UTC(), Hosts: s.annotate(raw.Hosts)}
	lastNet.Lock()
	lastNet.r = res
	lastNet.Unlock()
	s.record(r, "network_scan", "", raw.CIDR)
	writeJSON(w, 200, res)
}

// handleNetInstall installs the agent on a Windows PC through a helper PC on the same network.
func (s *Server) handleNetInstall(w http.ResponseWriter, r *http.Request, sess *session) {
	if !s.needStepUp(w, sess) {
		return
	}
	var req struct{ Host, User, Password, Relay string }
	if !readJSON(w, r, &req) {
		return
	}
	ip := net.ParseIP(strings.TrimSpace(req.Host))
	if ip == nil || ip.To4() == nil || !ip.IsPrivate() {
		writeErr(w, 400, "enter the private IPv4 address of the PC")
		return
	}
	if req.User == "" || req.Password == "" {
		writeErr(w, 400, "enter an administrator account of that PC")
		return
	}
	a := s.hub.online(req.Relay)
	rd, ok := s.st.device(req.Relay)
	if a == nil || !ok || rd.Hello == nil || rd.Hello.OS != "windows" {
		writeErr(w, 409, "pick an online Windows PC on the same network to do the install")
		return
	}
	plain, _, err := s.st.CreateToken("remote install "+ip.String(), time.Hour, 1)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	args, _ := json.Marshal(map[string]string{"host": ip.String(), "user": req.User, "password": req.Password,
		"server": s.baseURL(r), "token": plain})
	job, err := s.hub.dispatch(req.Relay, "agent.push", args, sess.User)
	if err != nil {
		writeErr(w, 409, err.Error())
		return
	}
	s.hub.scrubArgs(job.ID)
	s.record(r, "network_install", req.Relay, ip.String()+" as "+req.User)
	writeJSON(w, 200, map[string]string{"job": job.ID})
}
