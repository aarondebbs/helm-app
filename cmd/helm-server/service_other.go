//go:build !windows

package main

import (
	"context"
	"errors"
)

var errNotService = errors.New("not a Windows service")

func runService(name string, fn func(ctx context.Context)) error { return errNotService }

func defaultDataDir() string { return "/var/lib/helm" }
