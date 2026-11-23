package agent

import (
	"os"
	"testing"
)

// The test-suite drives the development fixtures, not the real Linux implementations.
func TestMain(m *testing.M) {
	os.Setenv("HELM_FIXTURES", "1")
	os.Exit(m.Run())
}
