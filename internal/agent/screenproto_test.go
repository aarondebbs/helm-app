package agent

import (
	"testing"
	"time"
)

func TestAdaptiveSlowsDownAndRecovers(t *testing.T) {
	var a Adaptive
	a.SetCeiling(12, 70)
	for i := 0; i < 12; i++ {
		a.Observe(400 * time.Millisecond)
	}
	if a.FPS() >= 12 || a.Quality() >= 70 {
		t.Fatalf("slow sends must lower fps and quality, got %d fps q%d", a.FPS(), a.Quality())
	}
	if a.FPS() < 2 || a.Quality() < 30 {
		t.Fatalf("floors broken: %d fps q%d", a.FPS(), a.Quality())
	}
	for i := 0; i < 60; i++ {
		a.Observe(5 * time.Millisecond)
	}
	if a.FPS() != 12 || a.Quality() != 70 {
		t.Fatalf("a recovered link must return to the ceiling, got %d fps q%d", a.FPS(), a.Quality())
	}
	a.SetCeiling(6, 50)
	if a.FPS() != 6 || a.Quality() != 50 {
		t.Fatalf("lowering the ceiling must clamp: %d fps q%d", a.FPS(), a.Quality())
	}
}

func TestAbsPointAcrossTwoMonitors(t *testing.T) {
	// two 1920x1080 monitors side by side; virtual desktop is 3840x1080 at 0,0
	left := MonRect{X: 0, Y: 0, W: 1920, H: 1080, Primary: true}
	right := MonRect{X: 1920, Y: 0, W: 1920, H: 1080}
	x, y := AbsPoint(left, 0, 0, 3840, 1080, 0, 0)
	if x != 0 || y != 0 {
		t.Errorf("left top-left: %d,%d", x, y)
	}
	x, _ = AbsPoint(right, 0, 0, 3840, 1080, 1, 0)
	if x != 65535 {
		t.Errorf("right edge of the right monitor must be 65535, got %d", x)
	}
	x, _ = AbsPoint(right, 0, 0, 3840, 1080, 0, 0)
	if x < 32700 || x > 32900 {
		t.Errorf("left edge of the right monitor should be near the middle, got %d", x)
	}
	// a monitor to the left of the primary has negative coordinates
	neg := MonRect{X: -1920, Y: 0, W: 1920, H: 1080}
	x, _ = AbsPoint(neg, -1920, 0, 3840, 1080, 0, 0)
	if x != 0 {
		t.Errorf("negative origin: %d", x)
	}
}
