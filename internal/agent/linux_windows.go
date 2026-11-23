//go:build windows

package agent

import (
	"context"
	"errors"
)

// Linux-only hooks: never reached on Windows.
func (a *Agent) linuxHandlers(m map[string]handlerFn) {}

func (a *Agent) linuxDebInstall(ctx context.Context, path string) (map[string]any, error) {
	return nil, errors.New("not supported on Windows")
}

func (a *Agent) macHandlers(m map[string]handlerFn) {}

func (a *Agent) macPkgInstall(ctx context.Context, path string) (map[string]any, error) {
	return nil, errors.New("not supported on Windows")
}

// WriteLinuxConfig is Linux/macOS-only.
func WriteLinuxConfig(server, token, consent string) error {
	return errors.New("only supported on Linux")
}
