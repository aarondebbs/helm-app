package netscan

import (
	"context"
	"net"
	"testing"
)

func TestExpand(t *testing.T) {
	ips, err := Expand("192.168.1.0/24")
	if err != nil || len(ips) != 254 || ips[0].String() != "192.168.1.1" || ips[253].String() != "192.168.1.254" {
		t.Fatalf("got %d %v", len(ips), err)
	}
	for _, bad := range []string{"8.8.8.0/24", "10.0.0.0/8", "nope", "::1/128"} {
		if _, err := Expand(bad); err == nil {
			t.Errorf("%s should be refused", bad)
		}
	}
}

func TestClassify(t *testing.T) {
	if k, w := classify([]int{135, 445, 5985}); k != "windows" || !w {
		t.Fatal(k, w)
	}
	if k, _ := classify([]int{22, 80}); k != "linux" {
		t.Fatal(k)
	}
	if k, _ := classify([]int{80}); k != "other" {
		t.Fatal(k)
	}
}

func TestNormMAC(t *testing.T) {
	if normMAC("0:1a:2b:3:4:5") != "00:1a:2b:03:04:05" || normMAC("00-1A-2B-03-04-05") != "00:1A:2B:03:04:05" {
		t.Fatal("normMAC")
	}
}

func TestProbeFindsListener(t *testing.T) {
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Skip(err)
	}
	defer l.Close()
	port := l.Addr().(*net.TCPAddr).Port
	old := Ports
	Ports = []int{port, 1}
	defer func() { Ports = old }()
	got := probe(context.Background(), "127.0.0.1")
	if len(got) != 1 || got[0] != port {
		t.Fatal(got)
	}
}
