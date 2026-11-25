//go:build !windows

package agent

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
)

func readTrim(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(strings.ReplaceAll(string(b), "\x00", ""))
}

func rawChassis() chassisFacts {
	var f chassisFacts
	switch runtime.GOOS {
	case "darwin":
		if out, err := exec.Command("/usr/sbin/sysctl", "-n", "hw.model").Output(); err == nil {
			f.MacModel = strings.TrimSpace(string(out))
		}
	case "linux":
		f.Model = readTrim("/proc/device-tree/model") // Raspberry Pi and other boards
		if f.Model == "" {
			f.Model = readTrim("/sys/class/dmi/id/product_name")
		}
		f.Vendor = readTrim("/sys/class/dmi/id/sys_vendor")
		f.Type, _ = strconv.Atoi(readTrim("/sys/class/dmi/id/chassis_type"))
		if m, _ := filepath.Glob("/sys/class/power_supply/BAT*"); len(m) > 0 {
			f.Battery = true
		}
		f.HasBatt = true
		if v, _ := os.ReadFile("/proc/cpuinfo"); strings.Contains(string(v), "hypervisor") {
			f.Virtual = true
		}
	}
	return f
}
