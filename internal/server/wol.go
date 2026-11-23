package server

import (
	"bytes"
	"errors"
	"net"
)

// sendMagic broadcasts a Wake-on-LAN packet on every network the server itself is attached to.
// It only reaches PCs on those networks; PCs elsewhere are woken through another online PC (see handleWake).
func sendMagic(hw net.HardwareAddr) error {
	pkt := bytes.Repeat([]byte{0xff}, 6)
	for i := 0; i < 16; i++ {
		pkt = append(pkt, hw...)
	}
	targets := map[string]bool{"255.255.255.255:9": true}
	ifs, _ := net.Interfaces()
	for _, ifc := range ifs {
		addrs, _ := ifc.Addrs()
		for _, ad := range addrs {
			ipn, ok := ad.(*net.IPNet)
			if !ok || ipn.IP.To4() == nil || ipn.IP.IsLoopback() {
				continue
			}
			ip, m := ipn.IP.To4(), ipn.Mask
			if len(m) == 16 {
				m = m[12:]
			}
			if len(m) == 4 {
				b := net.IP{ip[0] | ^m[0], ip[1] | ^m[1], ip[2] | ^m[2], ip[3] | ^m[3]}
				targets[net.JoinHostPort(b.String(), "9")] = true
			}
		}
	}
	sent := 0
	var last error = errors.New("no network to send on")
	for t := range targets {
		c, err := net.Dial("udp4", t)
		if err != nil {
			last = err
			continue
		}
		if _, err := c.Write(pkt); err != nil {
			last = err
		} else {
			sent++
		}
		c.Close()
	}
	if sent == 0 {
		return last
	}
	return nil
}

// wakeFromServer sends the magic packet for each MAC from the server itself; it returns how many were sent.
func wakeFromServer(macs []string) (int, error) {
	n := 0
	var last error
	for _, m := range macs {
		hw, err := net.ParseMAC(m)
		if err != nil || len(hw) != 6 {
			continue
		}
		if err := sendMagic(hw); err != nil {
			last = err
			continue
		}
		n++
	}
	if n == 0 {
		if last == nil {
			last = errors.New("no valid MAC address on record")
		}
		return 0, last
	}
	return n, nil
}
