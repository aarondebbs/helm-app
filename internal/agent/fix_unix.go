//go:build !windows

package agent

import (
	"context"
	"fmt"
	"time"
)

func runFix(ctx context.Context, argv []string) (any, error) {
	out, err := lrun(ctx, 10*time.Minute, []string{"DEBIAN_FRONTEND=noninteractive", "LC_ALL=C"}, argv[0], argv[1:]...)
	if err != nil {
		return nil, fmt.Errorf("%s failed: %s", argv[0], firstLines(lastLines(out, 4)+" "+err.Error(), 400))
	}
	return map[string]any{"fixed": true}, nil
}
