package server

import (
	"testing"
	"time"
)

func TestPatchWindow(t *testing.T) {
	loc := time.UTC
	at := func(day, hour int) time.Time { return time.Date(2026, 11, day, hour, 30, 0, 0, loc) } // 22 Nov 2026 is a Sunday
	p := PatchSettings{Enabled: true, Days: []int{0}, StartHour: 22, Hours: 5}                   // Sunday 22:00 to Monday 03:00
	cases := []struct {
		t    time.Time
		want bool
	}{
		{at(22, 21), false}, {at(22, 22), true}, {at(22, 23), true}, {at(23, 2), true}, {at(23, 3), false}, {at(24, 23), false},
	}
	for _, c := range cases {
		if got := p.inWindow(c.t); got != c.want {
			t.Errorf("%v: got %v want %v", c.t, got, c.want)
		}
	}
	p.Enabled = false
	if p.inWindow(at(22, 23)) {
		t.Error("disabled window must never be open")
	}
	bad := PatchSettings{Enabled: true, StartHour: 25, Hours: 2, Days: []int{1}}
	if bad.clean() == "" {
		t.Error("start hour 25 must be rejected")
	}
	empty := PatchSettings{Enabled: true, StartHour: 2, Hours: 2}
	if empty.clean() == "" {
		t.Error("enabled with no days must be rejected")
	}
}
