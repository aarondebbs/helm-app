package proto

import (
	"strings"
	"testing"
)

func TestHelloSanitize(t *testing.T) {
	h := Hello{Hostname: "PC\n\x00-" + strings.Repeat("A", 500), OS: "windows", MACs: make([]string, 500), IPs: []string{"10.0.0.1", "\x01"}}
	for i := range h.MACs {
		h.MACs[i] = strings.Repeat("f", 300)
	}
	c := h.Sanitize()
	if strings.ContainsAny(c.Hostname, "\n\x00") || len([]rune(c.Hostname)) > 100 {
		t.Fatalf("hostname not cleaned: %q", c.Hostname)
	}
	if len(c.MACs) != 16 || len(c.MACs[0]) != 40 {
		t.Fatalf("macs not bounded: %d x %d", len(c.MACs), len(c.MACs[0]))
	}
	if len(c.IPs) != 1 || c.IPs[0] != "10.0.0.1" {
		t.Fatalf("ips: %v", c.IPs)
	}
}
