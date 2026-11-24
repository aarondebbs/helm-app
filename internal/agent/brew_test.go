//go:build !windows

package agent

import "testing"

func TestParseBrewOutdated(t *testing.T) {
	js := `{"formulae":[{"name":"openssl@3","installed_versions":["3.3.0"],"current_version":"3.3.2"}],
	"casks":[{"name":"google-chrome","installed_versions":"126.0","current_version":"127.0"},{"name":"old","installed_versions":["1","2"],"current_version":"3"}]}`
	p, err := parseBrewOutdated(js)
	if err != nil || len(p) != 3 {
		t.Fatalf("%v %v", p, err)
	}
	if p[0].ID != "openssl@3" || p[0].Available != "3.3.2" || p[1].ID != "cask:google-chrome" || p[2].Version != "1 2" {
		t.Fatalf("%+v", p)
	}
}

func TestBrewIDsAreSafe(t *testing.T) {
	for _, bad := range []string{"-rf", "--force", "a b", "../x", "cask:", "x;y", "$(id)", ""} {
		if reBrewID.MatchString(bad) {
			t.Errorf("%q accepted", bad)
		}
	}
	for _, ok := range []string{"openssl@3", "cask:google-chrome", "homebrew/cask/firefox", "python@3.12"} {
		if !reBrewID.MatchString(ok) {
			t.Errorf("%q rejected", ok)
		}
	}
}
