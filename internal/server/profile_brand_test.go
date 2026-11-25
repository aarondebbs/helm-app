package server

import (
	"encoding/base64"
	"testing"
)

func TestProfileBranding(t *testing.T) {
	png := logoPrefix + base64.StdEncoding.EncodeToString([]byte("\x89PNG\r\n\x1a\nxxxx"))
	if p, err := cleanProfile(&Profile{Accent: "#0d7a70", Logo: png}); err != nil || p == nil || p.Logo != png {
		t.Fatalf("valid branding rejected: %v", err)
	}
	for _, bad := range []*Profile{
		{Accent: "red"},
		{Accent: "#12345"},
		{Logo: "data:image/png;base64,AAAA"},
		{Logo: "data:image/svg+xml;base64," + base64.StdEncoding.EncodeToString([]byte("<svg/>"))},
		{Logo: logoPrefix + base64.StdEncoding.EncodeToString(append([]byte("\x89PNG\r\n\x1a\n"), make([]byte, 70000)...))},
	} {
		if _, err := cleanProfile(bad); err == nil {
			t.Fatalf("accepted %+v", bad)
		}
	}
}
