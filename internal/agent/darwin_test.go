//go:build !windows

package agent

import (
	"strings"
	"testing"
)

func TestMacParsers(t *testing.T) {
	if c := parseTopCPU("Processes: 400 total\nCPU usage: 7.14% user, 3.57% sys, 89.28% idle\n"); c < 10.7 || c > 10.72 {
		t.Errorf("cpu %v", c)
	}
	vm := "Mach Virtual Memory Statistics: (page size of 16384 bytes)\nPages free:                               10000.\nPages active:                            200000.\nPages inactive:                           50000.\nPages speculative:                         5000.\nPages purgeable:                           1000.\n"
	used := parseVMStat(vm, 16<<30)
	want := uint64(16<<30) - uint64(66000*16384)
	if used != want {
		t.Errorf("vm used %d want %d", used, want)
	}

	apps, err := parseApplications([]byte(`{"SPApplicationsDataProvider":[
	 {"_name":"Safari","version":"17.5","obtained_from":"apple","path":"/Applications/Safari.app"},
	 {"_name":"Slack","version":"4.38.121","obtained_from":"identified_developer","signed_by":["Developer ID Application: Slack Technologies, Inc. (BQR82RBBHL)","Developer ID Certification Authority"],"path":"/Applications/Slack.app"},
	 {"_name":"Xcode","version":"15.4","obtained_from":"mac_app_store","path":"/Applications/Xcode.app"},
	 {"version":"1"}]}`))
	if err != nil || len(apps) != 3 {
		t.Fatalf("apps: %v %+v", err, apps)
	}
	if apps[0].Publisher != "Apple" || !strings.HasPrefix(apps[1].Publisher, "Slack Technologies") || apps[2].Publisher != "Mac App Store" {
		t.Errorf("publishers: %+v", apps)
	}

	ps := parsePS("    1   0.0  10240 root /sbin/launchd\n  412  12.5 204800 alice /Applications/Google Chrome.app/Contents/MacOS/Google Chrome\n bad line\n")
	if len(ps) != 2 || ps[1]["name"] != "Google Chrome" || ps[1]["user"] != "alice" || ps[1]["memMB"].(float64) != 200 {
		t.Errorf("ps: %+v", ps)
	}

	lc := parseLaunchctlList("PID\tStatus\tLabel\n412\t0\tcom.apple.Finder\n-\t0\tcom.apple.idle\n-\t78\tcom.vendor.broken\n")
	if len(lc) != 3 || lc[0]["state"] != "Running" || lc[1]["state"] != "Stopped" || lc[2]["state"] != "Failed" {
		t.Errorf("launchctl: %+v", lc)
	}

	su := parseSoftwareUpdate("Software Update Tool\n\nFinding available software\nSoftware Update found the following new or updated software:\n* Label: macOS Sonoma 14.5-23F79\n\tTitle: macOS Sonoma 14.5, Version: 14.5, Size: 1234567KiB, Recommended: YES, Action: restart,\n* Label: Safari17.5VenturaAuto-17.5\n\tTitle: Safari, Version: 17.5, Size: 150000KiB, Recommended: YES,\n")
	if len(su) != 2 || su[0].Label != "macOS Sonoma 14.5-23F79" || !su[0].Restart || su[0].Version != "14.5" || su[1].Restart || su[1].Title != "Safari" {
		t.Errorf("softwareupdate: %+v", su)
	}
	old := parseSoftwareUpdate("Software Update Tool\nSoftware Update found the following new or updated software:\n   * macOS Ventura 13.4-22F66\n\tmacOS Ventura (13.4), 1234K [recommended] [restart]\n")
	if len(old) != 1 || old[0].Label != "macOS Ventura 13.4-22F66" || !old[0].Restart || !old[0].Recommended {
		t.Errorf("old softwareupdate: %+v", old)
	}

	ports := parseLsof("COMMAND   PID USER   FD   TYPE DEVICE SIZE/OFF NODE NAME\nsshd      101 root    3u  IPv4 0x1      0t0  TCP *:22 (LISTEN)\nsshd      101 root    4u  IPv6 0x2      0t0  TCP *:22 (LISTEN)\ncupsd     202 root    5u  IPv4 0x3      0t0  TCP 127.0.0.1:631 (LISTEN)\nmDNSResp  303 _mdns   6u  IPv4 0x4      0t0  UDP *:5353\nchrome    404 alice   7u  IPv4 0x5      0t0  TCP 10.0.0.2:5000->1.2.3.4:443 (ESTABLISHED)\n")
	if len(ports) != 3 || ports[0]["port"] != 22 || ports[2]["port"] != 5353 || ports[1]["address"] != "127.0.0.1" {
		t.Errorf("lsof: %+v", ports)
	}

	logs := parseLogNDJSON(`{"timestamp":"2025-01-02 03:04:05.123456+0100","messageType":"Error","process":"kernel","eventMessage":"disk0 error"}
{"timestamp":"2025-01-02 03:05:05.123456+0100","messageType":"Fault","subsystem":"com.apple.x","eventMessage":"fault happened"}
garbage`, 10)
	if len(logs) != 2 || logs[0]["level"] != "Critical" || logs[1]["provider"] != "kernel" || logs[1]["time"] != "2025-01-02T02:04:05Z" {
		t.Errorf("logs: %+v", logs)
	}
	if appleString("a\"b\\c\nd") != `"a\"b\\c\nd"` {
		t.Errorf("appleString %s", appleString("a\"b\\c\nd"))
	}
}

func TestParseDnfCheck(t *testing.T) {
	out := "\nkernel.x86_64   6.1.0-1.fc39   updates\nNetworkManager.x86_64 1.44.2-1.fc39 updates-security\nLast metadata expiration check: 0:01:00 ago\nObsoleting Packages\nfoo.x86_64 1 2\n"
	l := parseDnfCheck(out)
	if len(l) != 2 || l[0]["id"] != "kernel" || l[1]["id"] != "NetworkManager" || l[1]["severity"] != "Important" || l[0]["needsReboot"] != true {
		t.Fatalf("%+v", l)
	}
}
