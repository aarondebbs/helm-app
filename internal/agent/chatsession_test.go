//go:build !windows

package agent

import (
	"strings"
	"testing"
)

func TestCleanForShell(t *testing.T) {
	got := cleanForShell("say \"hi\" \\ then\nrun `x`")
	if strings.ContainsAny(got, "\"\\\n") {
		t.Fatalf("unsafe characters left: %q", got)
	}
	if long := cleanForShell(strings.Repeat("a", 500)); len([]rune(long)) > 141 {
		t.Fatalf("not shortened: %d", len([]rune(long)))
	}
}

// With nobody signed in at a screen (a server, a container), a new message must be a quiet no-op.
func TestChatNotifyWithoutDesktop(t *testing.T) {
	a := &Agent{}
	a.tray.AllowSupport = true
	a.chatNotifyUser("hello") // must return without panicking or hanging
}
