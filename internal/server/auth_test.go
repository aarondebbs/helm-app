package server

import (
	"testing"
	"time"
)

func TestTOTPVectors(t *testing.T) {
	secret := "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ" // "12345678901234567890"
	cases := map[int64]string{59: "287082", 1111111109: "081804", 1234567890: "005924", 2000000000: "279037"}
	for ts, want := range cases {
		got, err := totpCode(secret, ts/30)
		if err != nil || got != want {
			t.Fatalf("t=%d got %s want %s (%v)", ts, got, want, err)
		}
	}
}

func TestTOTPReplayAndDrift(t *testing.T) {
	secret := NewTOTPSecret()
	now := time.Unix(1700000000, 0)
	code, _ := totpCode(secret, now.Unix()/30)
	step, ok := verifyTOTP(secret, code, now, 0)
	if !ok {
		t.Fatal("valid code rejected")
	}
	if _, ok := verifyTOTP(secret, code, now, step); ok {
		t.Fatal("replayed code accepted")
	}
	prev, _ := totpCode(secret, now.Unix()/30-1)
	if _, ok := verifyTOTP(secret, prev, now, 0); !ok {
		t.Fatal("previous step should be accepted (drift)")
	}
	old, _ := totpCode(secret, now.Unix()/30-3)
	if _, ok := verifyTOTP(secret, old, now, 0); ok {
		t.Fatal("stale code accepted")
	}
	if _, ok := verifyTOTP(secret, "12345", now, 0); ok {
		t.Fatal("short code accepted")
	}
}

func TestPasswordStrength(t *testing.T) {
	for pw, ok := range map[string]bool{"short1A!": false, "alllowercaseletters": false, "Correct-Horse-9": true, "abcdefgh1234": true} {
		if (ValidatePasswordStrength(pw) == nil) != ok {
			t.Errorf("%q expected ok=%v", pw, ok)
		}
	}
}

func TestLimiter(t *testing.T) {
	l := newLimiter(3, time.Minute, time.Minute)
	for i := 0; i < 2; i++ {
		l.fail("k")
	}
	if !l.allowed("k") {
		t.Fatal("blocked too early")
	}
	l.fail("k")
	if l.allowed("k") {
		t.Fatal("should be blocked")
	}
	if !l.allowed("other") {
		t.Fatal("other key affected")
	}
}

func TestSemver(t *testing.T) {
	if !semverNewer("1.2.0", "1.1.9") || semverNewer("1.2.0", "1.2.0") || semverNewer("1.0.0", "1.0.1") || !semverNewer("1.0.0", "") {
		t.Fatal("semver compare wrong")
	}
}
