package agent

import (
	"context"
	"strconv"
	"strings"
	"time"
)

func rawChassis() chassisFacts {
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	script := `$e=@(Get-CimInstance Win32_SystemEnclosure).ChassisTypes -join ',';$s=Get-CimInstance Win32_ComputerSystem;$b=@(Get-CimInstance Win32_Battery).Count;"$e|$($s.Model)|$($s.Manufacturer)|$b"`
	cmd := shellCommandPS(ctx, script)
	out, err := cmd.Output()
	if err != nil {
		return chassisFacts{}
	}
	p := strings.Split(strings.TrimSpace(string(out)), "|")
	if len(p) < 4 {
		return chassisFacts{}
	}
	f := chassisFacts{Model: p[1], Vendor: p[2], HasBatt: true}
	for _, t := range strings.Split(p[0], ",") {
		if n, err := strconv.Atoi(strings.TrimSpace(t)); err == nil && n > 1 { // 1 = "other", 2 = unknown
			f.Type = n
			break
		}
	}
	n, _ := strconv.Atoi(strings.TrimSpace(p[3]))
	f.Battery = n > 0
	return f
}
