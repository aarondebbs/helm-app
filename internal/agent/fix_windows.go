//go:build windows

package agent

import (
	"context"
	"errors"
)

func runFix(ctx context.Context, argv []string) (any, error) {
	return nil, errors.New("not supported on Windows")
}
