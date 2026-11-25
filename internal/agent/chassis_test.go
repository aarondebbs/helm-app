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

func TestNormVendor(t *testing.T) {
	cases := []struct {
		f    chassisFacts
		want string
	}{
		{chassisFacts{Vendor: "Dell Inc.", Model: "Latitude 5420"}, "Dell"},
		{chassisFacts{Vendor: "LENOVO"}, "Lenovo"},
		{chassisFacts{Vendor: "Hewlett-Packard"}, "HP"},
		{chassisFacts{Model: "Raspberry Pi 5 Model B Rev 1.0"}, "Raspberry Pi"},
		{chassisFacts{MacModel: "MacBookPro18,1"}, "Apple"},
		{chassisFacts{Vendor: "To Be Filled By O.E.M."}, ""},
		{chassisFacts{Vendor: "innotek GmbH", Model: "VirtualBox"}, "VirtualBox"},
	}
	for _, c := range cases {
		if got := normVendor(c.f); got != c.want {
			t.Errorf("%+v: got %q want %q", c.f, got, c.want)
		}
	}
}
