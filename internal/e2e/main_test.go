package e2e

import (
	"os"
	"testing"
)

func TestMain(m *testing.M) {
	os.Setenv("HELM_FIXTURES", "1")
	os.Exit(m.Run())
}
