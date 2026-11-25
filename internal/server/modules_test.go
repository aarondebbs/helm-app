package server

import (
	"fmt"
	"testing"

	"helm/internal/proto"
)

func TestModulesAllow(t *testing.T) {
	cases := []struct {
		have []string
		cmd  string
		want bool
	}{
		{[]string{"rmm"}, "exec", true},
		{[]string{"rmm"}, "av.scan", false},
		{[]string{"av"}, "exec", false},
		{[]string{"av"}, "av.scan", true},
		{[]string{"av"}, "scan.software", true}, // security posture is open to every plan
		{[]string{"edr"}, "process.list", true},
		{[]string{"edr"}, "file.delete", false},
		{[]string{"edr"}, "edr.isolate", true},
		{[]string{"av", "edr"}, "edr.snapshot", true},
		{nil, "exec", false},
		{nil, "ping", true},
	}
	for _, c := range cases {
		if got := modulesAllow(c.have, c.cmd); got != c.want {
			t.Errorf("modulesAllow(%v,%q)=%v want %v", c.have, c.cmd, got, c.want)
		}
	}
	for name := range commands {
		_ = cmdModules(name) // every command resolves
	}
}

func TestCleanModules(t *testing.T) {
	got := cleanModules([]string{"edr", "bogus", "rmm", "edr"})
	if len(got) != 2 || got[0] != "rmm" || got[1] != "edr" {
		t.Fatalf("got %v", got)
	}
}

func TestTokenIsOnePC(t *testing.T) {
	st, err := OpenStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	plain, tk, err := st.CreateToken("x", 999*3600e9, 50)
	if err != nil {
		t.Fatal(err)
	}
	if tk.MaxUses != 1 || tk.ExpiresAt.Sub(tk.CreatedAt) > 31*60e9 {
		t.Fatalf("token must be single use and 30 minutes: %+v", tk)
	}
	if _, _, err := st.Enroll(plain, proto.Hello{Hostname: "pc"}, "1.2.3.4"); err != nil {
		t.Fatalf("first enroll: %v", err)
	}
	if _, _, err := st.Enroll(plain, proto.Hello{Hostname: "pc"}, "1.2.3.4"); err == nil {
		t.Fatal("a token must work for one PC only")
	}
}

func TestModuleInstallAllowedOnAnyPlan(t *testing.T) {
	for _, have := range [][]string{{"av"}, {"edr"}, {"rmm"}} {
		if !modulesAllow(have, "module.install") {
			t.Errorf("module.install should be allowed for plan %v", have)
		}
	}
}

func TestReusableInstallerUntilRevoked(t *testing.T) {
	st, err := OpenStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	plain, tk, err := st.CreateReusable("deploy", 0, 0, &Profile{AutoApprove: true, Modules: []string{"rmm", "av"}})
	if err != nil {
		t.Fatal(err)
	}
	if tk.Profile.AutoApprove || len(tk.Profile.Modules) != 0 {
		t.Fatal("a reusable installer must never approve PCs by itself")
	}
	for i := 0; i < 3; i++ {
		if _, _, err := st.Enroll(plain, proto.Hello{Hostname: fmt.Sprintf("pc%d", i), OS: "windows"}, "1.2.3.4"); err != nil {
			t.Fatalf("enrol %d: %v", i, err)
		}
	}
	_ = st.update(func(d *data) error { d.Tokens[tk.ID].Revoked = true; return nil })
	if _, _, err := st.Enroll(plain, proto.Hello{Hostname: "late", OS: "windows"}, "1.2.3.4"); err == nil {
		t.Fatal("a revoked installer must stop working")
	}
}

func TestSetupWaitsForOfflinePC(t *testing.T) {
	s := newTestServer(t)
	s.kickAV("offline-pc", []string{"rmm", "av"}) // no agent is connected
	var got []string
	s.db.view(func(x *dbData) {
		if r := x.AV["offline-pc"]; r != nil {
			got = r.SetupPending
		}
	})
	if len(got) != 2 {
		t.Fatalf("setup should be remembered for an offline PC, got %v", got)
	}
}
