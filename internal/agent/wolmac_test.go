package agent

import "testing"

func TestParseHardwarePorts(t *testing.T) {
	out := "Hardware Port: Wi-Fi\nDevice: en0\nEthernet Address: AA:BB:CC:00:11:22\n\nHardware Port: Thunderbolt Bridge\nDevice: bridge0\nEthernet Address: N/A\n\nHardware Port: USB 10/100/1000 LAN\nDevice: en5\nEthernet Address: 00:1a:2b:3c:4d:5e\n"
	m := parseHardwarePorts(out)
	if m["en0"] != "aa:bb:cc:00:11:22" || m["en5"] != "00:1a:2b:3c:4d:5e" || m["bridge0"] != "" {
		t.Fatalf("%v", m)
	}
}
