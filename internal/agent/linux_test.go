//go:build linux

package agent

import (
	"context"
	"encoding/json"
	"testing"
	"time"
)

// Runs the real Linux collectors against this machine. Each one must return valid data in the same JSON shape the
// console reads; tools that are missing on the CI box (dpkg, ss, systemd) may produce a clear error instead.
func TestRealLinuxCollectors(t *testing.T) {
	t.Setenv("HELM_FIXTURES", "0")
	if !realLinux() {
		t.Skip("not linux")
	}
	a := &Agent{}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	must := func(name string, v any, err error, wantKeys ...string) {
		t.Helper()
		if err != nil {
			t.Logf("%s: %v (tool not present?)", name, err)
			return
		}
		b, _ := json.Marshal(v)
		if !json.Valid(b) || len(b) < 2 {
			t.Fatalf("%s: bad JSON %s", name, b)
		}
		for _, k := range wantKeys {
			var m map[string]any
			_ = json.Unmarshal(b, &m)
			if _, ok := m[k]; !ok {
				t.Errorf("%s: missing key %q in %.200s", name, k, b)
			}
		}
	}
	v, err := a.linuxInventory(ctx)
	must("inventory", v, err, "computerName", "osCaption", "ramBytes", "network", "disks")
	v, err = a.linuxProcesses(ctx)
	must("processes", v, err)
	if ps, _ := v.([]map[string]any); len(ps) == 0 {
		t.Error("no processes listed")
	}
	v, err = a.linuxSoftware(ctx, true)
	must("software", v, err)
	v, err = a.linuxScanPorts(ctx)
	must("ports", v, err)
	v, err = a.linuxScanConfig(ctx)
	must("config", v, err, "build", "edition", "checks")
	v, err = a.linuxServices(ctx)
	must("services", v, err)
	st := linuxStats()
	if st.MemTotal == 0 || len(st.Disks) == 0 {
		t.Errorf("stats incomplete: %+v", st)
	}
	if osInfoName, _ := linuxOSInfo(); osInfoName == "" {
		t.Error("empty OS name")
	}
}

func TestUpstreamVersion(t *testing.T) {
	for in, want := range map[string]string{"1:2.4.52-1ubuntu4": "2.4.52", "1.1.1n-0+deb11u5": "1.1.1n", "3.0.2-0ubuntu1.15": "3.0.2", "5.1": "5.1", "2.38.1+dfsg-1": "2.38.1"} {
		if got := upstreamVersion(in); got != want {
			t.Errorf("%s -> %s, want %s", in, got, want)
		}
	}
}
