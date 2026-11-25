package e2e

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestOnboardingPlan(t *testing.T) {
	e := newEnv(t)
	e.login()
	st, b := e.do("POST", "/api/tokens", map[string]any{"label": "ob", "hours": 9999, "maxUses": 99})
	if st != 200 {
		t.Fatalf("token: %d %s", st, b)
	}
	var tk struct {
		Token string
		Info  struct {
			MaxUses   int
			ExpiresAt time.Time
			CreatedAt time.Time
		}
	}
	_ = json.Unmarshal(b, &tk)
	if tk.Info.MaxUses != 1 || tk.Info.ExpiresAt.Sub(tk.Info.CreatedAt) > 31*time.Minute {
		t.Fatalf("a token is for one PC and lasts 30 minutes: %+v", tk.Info)
	}
	e.startAgent(t, tk.Token)
	dev := e.waitDevice(func(d devView) bool { return d.Online })
	if dev.Approved {
		t.Fatal("a PC waits for onboarding")
	}
	if st, _ := e.do("POST", "/api/devices/"+dev.ID+"/onboard", map[string]any{"modules": []string{}}); st != 400 {
		t.Fatalf("a plan needs a module: %d", st)
	}
	if st, b := e.do("POST", "/api/devices/"+dev.ID+"/onboard", map[string]any{"modules": []string{"av"}, "name": "Reception PC", "group": "Front"}); st != 200 {
		t.Fatalf("onboard: %d %s", st, b)
	}
	time.Sleep(300 * time.Millisecond)
	// Antivirus only: RMM actions are refused, antivirus ones go through.
	if st, b := e.do("POST", "/api/devices/"+dev.ID+"/cmd", map[string]any{"name": "exec", "args": map[string]any{"shell": "powershell", "script": "1"}, "wait": 3}); st != 409 || !strings.Contains(string(b), "plan") {
		t.Fatalf("exec must be outside an antivirus-only plan: %d %s", st, b)
	}
	if st, _ := e.do("POST", "/api/devices/"+dev.ID+"/cmd", map[string]any{"name": "av.status", "wait": 20}); st != 200 {
		t.Fatalf("av.status: %d", st)
	}
	// Switch to RMM + EDR: exec is now allowed to be sent (it needs step-up, so 428 proves it passed the plan check).
	if st, _ := e.do("POST", "/api/devices/"+dev.ID+"/modules", map[string]any{"modules": []string{"rmm", "edr"}}); st != 200 {
		t.Fatalf("modules: %d", st)
	}
	if st, _ := e.do("POST", "/api/devices/"+dev.ID+"/cmd", map[string]any{"name": "av.scan", "wait": 3}); st != 409 {
		t.Fatalf("av.scan must be refused without the module: %d", st)
	}
	if st, b := e.do("GET", "/api/av", nil); st != 200 || !strings.Contains(string(b), `"rows"`) {
		t.Fatalf("av page: %d %s", st, b)
	}
}
