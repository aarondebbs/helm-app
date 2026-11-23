package server

import (
	"bytes"
	"os"
	"testing"
)

func TestPersonalizeMSI(t *testing.T) {
	tpl := append(append(append([]byte("xx"), phServer...), append([]byte("--"), phToken...)...), append([]byte("--"), phConsent...)...)
	out, err := personalizeMSI(tpl, "https://pi.example.ts.net", "hlm_0123456789abcdef0123456789abcdef01234567", "unattended")
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != len(tpl) {
		t.Fatal("the file size must not change")
	}
	for _, want := range []string{"https://pi.example.ts.net   ", "hlm_0123456789abcdef0123456789abcdef01234567 ", "unattended "} {
		if !bytes.Contains(out, []byte(want)) {
			t.Errorf("missing %q", want)
		}
	}
	if bytes.Contains(out, []byte("HELMPH_")) {
		t.Error("a placeholder is still present")
	}
	if _, err := personalizeMSI([]byte("no placeholders"), "https://a", "hlm_x", "unattended"); err == nil {
		t.Error("a damaged template must be refused")
	}
	if _, err := personalizeMSI(tpl, "https://"+string(bytes.Repeat([]byte("a"), 200)), "t", "unattended"); err == nil {
		t.Error("an over-long server URL must be refused")
	}
}

// Optional: runs against the real template when the build output is present.
func TestPersonalizeRealTemplate(t *testing.T) {
	tpl, err := os.ReadFile("../../out/server-data/dist/Helm-Agent.template.msi")
	if err != nil {
		t.Skip("no built template")
	}
	out, err := personalizeMSI(tpl, "https://pi.example.ts.net", "hlm_0123456789abcdef0123456789abcdef01234567", "unattended")
	if err != nil {
		t.Fatal(err)
	}
	os.WriteFile(os.TempDir()+"/patched.msi", out, 0o644)
}
