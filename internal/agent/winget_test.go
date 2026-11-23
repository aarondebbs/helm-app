package agent

import "testing"

func TestParseWingetUpgrade(t *testing.T) {
	out := "\r-\r\\\r|\r   \r\r" +
		"Name                 Id                      Version   Available Source\r\n" +
		"-----------------------------------------------------------------------\r\n" +
		"Git                  Git.Git                 2.43.0    2.44.0    winget\r\n" +
		"Mozilla Firefox      Mozilla.Firefox         122.0     123.0     winget\r\n" +
		"2 upgrades available.\r\n"
	pk := parseWingetUpgrade(out)
	if len(pk) != 2 {
		t.Fatalf("got %d packages: %+v", len(pk), pk)
	}
	if pk[0].ID != "Git.Git" || pk[0].Version != "2.43.0" || pk[0].Available != "2.44.0" || pk[0].Source != "winget" {
		t.Fatalf("bad row 0: %+v", pk[0])
	}
	if pk[1].Name != "Mozilla Firefox" || pk[1].ID != "Mozilla.Firefox" {
		t.Fatalf("bad row 1: %+v", pk[1])
	}
}

func TestParseWingetNone(t *testing.T) {
	if p := parseWingetUpgrade("No installed package found matching input criteria.\r\n"); p != nil {
		t.Fatalf("expected nil, got %+v", p)
	}
}

func TestWingetIDValidation(t *testing.T) {
	for id, ok := range map[string]bool{"Git.Git": true, "Mozilla.Firefox": true, "a b": false, "x;rm": false, "": false, "-bad": false} {
		if reWingetID.MatchString(id) != ok {
			t.Errorf("%q: want %v", id, ok)
		}
	}
}
