//go:build !windows

package agent

import "testing"

func TestMacFlagsAndKeys(t *testing.T) {
	if f := macFlags(InputMsg{Ctrl: true, Meta: true}, true); f != 0x20000|0x40000|0x100000 {
		t.Fatalf("flags %x", f)
	}
	for _, c := range []string{"KeyA", "Enter", "Escape", "ArrowUp", "Space", "Backspace", "F5"} {
		if _, ok := macKeys[c]; !ok {
			t.Fatalf("no mac key for %s", c)
		}
	}
	if macKeys["KeyA"] != 0 || macKeys["Enter"] != 36 || macKeys["ArrowUp"] != 126 {
		t.Fatal("wrong virtual key codes")
	}
}
