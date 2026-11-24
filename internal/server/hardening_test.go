package server

import "testing"

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
