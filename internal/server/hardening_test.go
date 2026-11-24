package server

import (
	"testing"

	"helm/internal/proto"
)

func TestDownloadNamesCannotTraverse(t *testing.T) {
	for _, bad := range []string{"..", ".", ".hidden", "../x", "a/b", "", "a b"} {
		if reFile.MatchString(bad) {
			t.Errorf("%q must not be a valid download name", bad)
		}
	}
	for _, ok := range []string{"Helm-Agent.msi", "helm-agent_0.9.0.pkg", "latest.json"} {
		if !reFile.MatchString(ok) {
			t.Errorf("%q should be valid", ok)
		}
	}
}

func TestLockoutBucketsArePerUser(t *testing.T) {
	st, _ := OpenStore(t.TempDir())
	if _, err := st.SetAdmin("admin", "a-long-test-password-1", ""); err != nil {
		t.Fatal(err)
	}
	s := &Server{st: st}
	if s.acctKey("admin") == s.acctKey("nobody") {
		t.Fatal("known and unknown names must not share a bucket")
	}
	if s.acctKey("nobody") != s.acctKey("someone-else") {
		t.Fatal("unknown names share one bucket so the table cannot grow")
	}
}

func TestTOTPStepCanBeTakenOnlyOnce(t *testing.T) {
	st, _ := OpenStore(t.TempDir())
	secret := NewTOTPSecret()
	if _, err := st.SetAdmin("admin", "a-long-test-password-1", secret); err != nil {
		t.Fatal(err)
	}
	won := make(chan bool, 20)
	for i := 0; i < 20; i++ {
		go func() { won <- st.takeStep("admin", 12345) }()
	}
	n := 0
	for i := 0; i < 20; i++ {
		if <-won {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("%d concurrent requests used the same code; exactly one may", n)
	}
	if st.takeStep("admin", 12344) {
		t.Fatal("an older step must be refused")
	}
}

func TestMatchingUpdatesFindsSubPackages(t *testing.T) {
	ups := []Patch{{ID: "openssl", Title: "openssl 3.0.1 → 3.0.2"}, {ID: "openssl-libs", Title: "x"}, {ID: "libssl3t64", Title: "y"}, {ID: "opensslx", Title: "z"}, {ID: "Safari17", Title: "Safari 17.5"}}
	got := matchingUpdates(ups, "OpenSSL")
	if len(got) != 2 || got[0].ID != "openssl" || got[1].ID != "openssl-libs" {
		t.Fatalf("%+v", got)
	}
	if m := matchingUpdates(ups, "safari"); len(m) != 1 {
		t.Fatalf("title match: %+v", m)
	}
	if matchingUpdates(ups, "") != nil || len(matchingUpdates(ups, "nginx")) != 0 {
		t.Fatal("unexpected match")
	}
}

func TestCommandsAreSkippedWhereTheyDoNotApply(t *testing.T) {
	lin := Device{Hello: &proto.Hello{OS: "linux"}}
	mac := Device{Hello: &proto.Hello{OS: "darwin"}}
	win := Device{Hello: &proto.Hello{OS: "windows"}}
	if notApplicable(lin, "winget.upgrade") == "" || notApplicable(mac, "winget.upgrade") != "" || notApplicable(win, "winget.upgrade") != "" {
		t.Fatal("app upgrades: Linux skips, Mac (Homebrew) and Windows run")
	}
	if notApplicable(mac, "rdp.enable") == "" || notApplicable(win, "rdp.enable") != "" {
		t.Fatal("Remote Desktop is Windows only")
	}
	if notApplicable(lin, "updates.install") != "" || notApplicable(mac, "updates.install") != "" {
		t.Fatal("system updates apply everywhere")
	}
}

func TestOSLabel(t *testing.T) {
	cases := []struct{ goos, ver, want string }{
		{"linux", "Ubuntu 24.04", "Linux"},
		{"darwin", "14.5", "macOS"},
		{"windows", "10.0.22631", "Windows 11"},
		{"windows", "10.0.19045", "Windows 10"},
		{"windows", "", "Unknown"},
	}
	for _, c := range cases {
		if got := osLabel(c.goos, c.ver, ""); got != c.want {
			t.Errorf("osLabel(%q,%q)=%q want %q", c.goos, c.ver, got, c.want)
		}
	}
}
