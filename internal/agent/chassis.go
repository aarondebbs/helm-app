package agent

import (
	"strings"
	"sync"
)

// What kind of machine this is, so the console can draw the right picture: "pi", "laptop", "desktop", "vm",
// "server" or "" when it cannot tell. Detection is best effort and never blocks enrollment.

var (
	chassisOnce sync.Once
	chassisVal  string
)

func detectChassis(edition string) string {
	chassisOnce.Do(func() { chassisVal = classifyChassis(rawChassis(), edition) })
	return chassisVal
}

// chassisFacts is what the platform code could read. Fields are empty when unknown.
type chassisFacts struct {
	Model    string // board or product name ("Raspberry Pi 5 Model B", "MacBookPro18,1", "VirtualBox")
	Vendor   string
	Type     int  // SMBIOS enclosure type, 0 when unknown
	Battery  bool // the machine has a battery
	HasBatt  bool // Battery was actually determined
	Virtual  bool
	MacModel string
}

func classifyChassis(f chassisFacts, edition string) string {
	m := strings.ToLower(f.Model + " " + f.Vendor + " " + f.MacModel)
	switch {
	case strings.Contains(m, "raspberry pi"):
		return "pi"
	case f.Virtual || containsAny(m, "virtualbox", "vmware", "qemu", "kvm", "virtual machine", "hyper-v", "xen", "parallels", "bochs", "virtualmac", "amazon ec2", "google compute"):
		return "vm"
	case strings.Contains(strings.ToLower(f.MacModel), "macbook"):
		return "laptop"
	case containsAny(strings.ToLower(f.MacModel), "macmini", "imac", "macpro", "mac studio", "mac14", "mac15", "mac16"):
		return "desktop"
	}
	switch f.Type {
	case 8, 9, 10, 11, 14, 30, 31, 32: // portable, laptop, notebook, hand held, sub notebook, tablet, convertible, detachable
		return "laptop"
	case 17, 23, 25, 28, 29: // main server chassis, rack mount, multi-system, blade, blade enclosure
		return "server"
	case 3, 4, 5, 6, 7, 13, 15, 16, 24, 34, 35, 36: // desktop, low profile, pizza box, mini tower, tower, all in one, space-saving, lunch box, sealed case, mini pc, stick pc
		if f.HasBatt && f.Battery {
			return "laptop"
		}
		return "desktop"
	}
	if f.HasBatt && f.Battery {
		return "laptop"
	}
	if strings.Contains(strings.ToLower(edition), "server") {
		return "server"
	}
	if f.HasBatt {
		return "desktop"
	}
	return ""
}

func containsAny(s string, subs ...string) bool {
	for _, x := range subs {
		if strings.Contains(s, x) {
			return true
		}
	}
	return false
}
