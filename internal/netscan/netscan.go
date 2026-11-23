// Package netscan finds devices on a local network by trying a few TCP ports and reading the ARP table.
// It is used by the agent (to scan the network a PC is on) and by the server (to scan its own network).
package netscan

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os/exec"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"
)

// Host is one device that answered.
type Host struct {
	IP    string `json:"ip"`
	Name  string `json:"name,omitempty"`
	MAC   string `json:"mac,omitempty"`
	Ports []int  `json:"ports,omitempty"`
	Kind  string `json:"kind"` // windows | linux | other (a guess from open ports)
	WinRM bool   `json:"winrm,omitempty"`
}

// Ports probed. 445/135/3389/5985 point to Windows, 22 to Linux or macOS.
var Ports = []int{445, 135, 3389, 5985, 22, 80, 443, 5900}

const maxHosts = 1024

// LocalCIDRs returns the private IPv4 networks this machine is attached to.
func LocalCIDRs() []string {
	var out []string
	ifs, _ := net.Interfaces()
	for _, ifc := range ifs {
		if ifc.Flags&net.FlagUp == 0 || ifc.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, _ := ifc.Addrs()
		for _, a := range addrs {
			ipn, ok := a.(*net.IPNet)
			if !ok || ipn.IP.To4() == nil || !ipn.IP.IsPrivate() {
				continue
			}
			ones, bits := ipn.Mask.Size()
			if bits != 32 {
				continue
			}
			if ones < 24 { // keep a sensible size: scan the /24 around the address
				ones = 24
			}
			_, n, err := net.ParseCIDR(fmt.Sprintf("%s/%d", ipn.IP.String(), ones))
			if err == nil {
				out = append(out, n.String())
			}
		}
	}
	return out
}

// Expand lists the usable host addresses in a CIDR (private ranges only, at most 1024 hosts).
func Expand(cidr string) ([]net.IP, error) {
	ip, n, err := net.ParseCIDR(strings.TrimSpace(cidr))
	if err != nil || ip.To4() == nil {
		return nil, errors.New("enter an IPv4 network such as 192.168.1.0/24")
	}
	if !n.IP.IsPrivate() {
		return nil, errors.New("only private networks can be scanned (10.x, 172.16-31.x, 192.168.x)")
	}
	ones, bits := n.Mask.Size()
	if bits-ones > 10 {
		return nil, errors.New("that network is too large; use /22 or smaller")
	}
	var out []net.IP
	for c := n.IP.Mask(n.Mask).To4(); n.Contains(c); c = next(c) {
		out = append(out, append(net.IP(nil), c...))
	}
	if len(out) > 2 {
		out = out[1 : len(out)-1] // drop network and broadcast addresses
	}
	if len(out) > maxHosts {
		out = out[:maxHosts]
	}
	return out, nil
}

func next(ip net.IP) net.IP {
	n := append(net.IP(nil), ip...)
	for i := len(n) - 1; i >= 0; i-- {
		n[i]++
		if n[i] != 0 {
			break
		}
	}
	return n
}

// Scan probes every address in the CIDR. report is called with a percentage as it goes (may be nil).
func Scan(ctx context.Context, cidr string, report func(pct int, msg string)) ([]Host, error) {
	ips, err := Expand(cidr)
	if err != nil {
		return nil, err
	}
	if report == nil {
		report = func(int, string) {}
	}
	type res struct {
		ip    string
		ports []int
	}
	jobs := make(chan net.IP)
	results := make(chan res)
	var wg sync.WaitGroup
	for i := 0; i < 96; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for ip := range jobs {
				if ctx.Err() != nil {
					return
				}
				if p := probe(ctx, ip.String()); len(p) > 0 {
					results <- res{ip.String(), p}
				}
			}
		}()
	}
	var done int
	var mu sync.Mutex
	go func() {
		for _, ip := range ips {
			select {
			case jobs <- ip:
				mu.Lock()
				done++
				d := done
				mu.Unlock()
				if d%16 == 0 {
					report(d*80/len(ips), fmt.Sprintf("Checked %d of %d addresses", d, len(ips)))
				}
			case <-ctx.Done():
				close(jobs)
				return
			}
		}
		close(jobs)
	}()
	go func() { wg.Wait(); close(results) }()
	found := map[string][]int{}
	for r := range results {
		found[r.ip] = r.ports
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	report(85, "Reading the address table")
	arp := arpTable()
	// hosts that ignore our ports can still show up in ARP (printers, phones)
	for ip := range arp {
		if _, ok := found[ip]; !ok && inList(ips, ip) {
			found[ip] = nil
		}
	}
	report(90, "Looking up names")
	var hosts []Host
	var hm sync.Mutex
	var nw sync.WaitGroup
	sem := make(chan struct{}, 32)
	for ip, ports := range found {
		nw.Add(1)
		sem <- struct{}{}
		go func(ip string, ports []int) {
			defer nw.Done()
			defer func() { <-sem }()
			h := Host{IP: ip, MAC: arp[ip], Ports: ports}
			rctx, cancel := context.WithTimeout(ctx, 1500*time.Millisecond)
			if names, err := net.DefaultResolver.LookupAddr(rctx, ip); err == nil && len(names) > 0 {
				h.Name = strings.TrimSuffix(names[0], ".")
			}
			cancel()
			h.Kind, h.WinRM = classify(ports)
			hm.Lock()
			hosts = append(hosts, h)
			hm.Unlock()
		}(ip, ports)
	}
	nw.Wait()
	sort.Slice(hosts, func(i, j int) bool { return ipLess(hosts[i].IP, hosts[j].IP) })
	return hosts, nil
}

func inList(ips []net.IP, s string) bool {
	p := net.ParseIP(s)
	for _, ip := range ips {
		if ip.Equal(p) {
			return true
		}
	}
	return false
}

func ipLess(a, b string) bool {
	x, y := net.ParseIP(a).To4(), net.ParseIP(b).To4()
	for i := range x {
		if x[i] != y[i] {
			return x[i] < y[i]
		}
	}
	return false
}

func probe(ctx context.Context, ip string) []int {
	var mu sync.Mutex
	var open []int
	var wg sync.WaitGroup
	for _, p := range Ports {
		wg.Add(1)
		go func(p int) {
			defer wg.Done()
			d := net.Dialer{Timeout: 700 * time.Millisecond}
			c, err := d.DialContext(ctx, "tcp4", net.JoinHostPort(ip, fmt.Sprint(p)))
			if err == nil {
				c.Close()
				mu.Lock()
				open = append(open, p)
				mu.Unlock()
			}
		}(p)
	}
	wg.Wait()
	sort.Ints(open)
	return open
}

func classify(ports []int) (kind string, winrm bool) {
	has := map[int]bool{}
	for _, p := range ports {
		has[p] = true
	}
	switch {
	case has[135] || has[3389] || has[5985]:
		return "windows", has[5985]
	case has[445] && !has[22]:
		return "windows", false
	case has[22]:
		return "linux", false
	}
	return "other", false
}

var macRe = regexp.MustCompile(`(?i)([0-9a-f]{1,2}[:-]){5}[0-9a-f]{1,2}`)
var ipRe = regexp.MustCompile(`\b(\d{1,3}\.){3}\d{1,3}\b`)

// arpTable maps IPv4 addresses to MAC addresses from the system's neighbour table.
func arpTable() map[string]string {
	out := map[string]string{}
	var raw []byte
	var err error
	if runtime.GOOS == "linux" {
		raw, err = exec.Command("cat", "/proc/net/arp").Output()
	} else {
		raw, err = exec.Command("arp", "-a").Output()
	}
	if err != nil {
		return out
	}
	for _, ln := range strings.Split(string(raw), "\n") {
		ip := ipRe.FindString(ln)
		mac := macRe.FindString(ln)
		if ip == "" || mac == "" {
			continue
		}
		hw, err := net.ParseMAC(normMAC(mac))
		if err != nil || len(hw) != 6 || hw.String() == "00:00:00:00:00:00" || hw.String() == "ff:ff:ff:ff:ff:ff" {
			continue
		}
		out[ip] = hw.String()
	}
	return out
}

// normMAC pads macOS-style short octets ("0:1a:2b:3:4:5") and converts dashes.
func normMAC(m string) string {
	m = strings.ReplaceAll(m, "-", ":")
	parts := strings.Split(m, ":")
	for i, p := range parts {
		if len(p) == 1 {
			parts[i] = "0" + p
		}
	}
	return strings.Join(parts, ":")
}
