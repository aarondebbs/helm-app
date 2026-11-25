package agent

import "testing"

func TestClassifyChassis(t *testing.T) {
	for _, c := range []struct {
		f    chassisFacts
		ed   string
		want string
	}{
		{chassisFacts{Model: "Raspberry Pi 5 Model B Rev 1.0"}, "", "pi"},
		{chassisFacts{Model: "VirtualBox", Type: 1}, "", "vm"},
		{chassisFacts{Model: "Virtual Machine", Vendor: "Microsoft Corporation"}, "", "vm"},
		{chassisFacts{MacModel: "MacBookPro18,1"}, "", "laptop"},
		{chassisFacts{MacModel: "Macmini9,1"}, "", "desktop"},
		{chassisFacts{Type: 10}, "", "laptop"},
		{chassisFacts{Type: 3, HasBatt: true}, "", "desktop"},
		{chassisFacts{Type: 3, HasBatt: true, Battery: true}, "", "laptop"}, // a battery wins over a generic chassis
		{chassisFacts{Type: 23}, "", "server"},
		{chassisFacts{HasBatt: true}, "Windows Server 2022", "server"},
		{chassisFacts{HasBatt: true, Battery: true}, "", "laptop"},
		{chassisFacts{HasBatt: true}, "", "desktop"},
		{chassisFacts{}, "", ""},
	} {
		if got := classifyChassis(c.f, c.ed); got != c.want {
			t.Errorf("%+v %q: got %q, want %q", c.f, c.ed, got, c.want)
		}
	}
}
