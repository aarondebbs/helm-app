package server

import (
	"encoding/base64"
	"testing"
)

func TestCheckPNGLogo(t *testing.T) {
	ok := logoPrefix + base64.StdEncoding.EncodeToString([]byte("\x89PNG\r\n\x1a\nabc"))
	if err := checkPNGLogo(ok); err != nil {
		t.Fatal(err)
	}
	if err := checkPNGLogo(""); err != nil {
		t.Fatal("empty means no logo")
	}
	for _, bad := range []string{"http://x/y.png", logoPrefix + "!!!", "data:image/svg+xml;base64,PHN2Zy8+", logoPrefix + base64.StdEncoding.EncodeToString([]byte("GIF89a......"))} {
		if checkPNGLogo(bad) == nil {
			t.Fatalf("accepted %q", bad)
		}
	}
}
