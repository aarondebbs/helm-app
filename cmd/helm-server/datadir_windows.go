//go:build windows

package main

import (
	"os"
	"path/filepath"
)

func defaultDataDir() string {
	if pd := os.Getenv("ProgramData"); pd != "" {
		return filepath.Join(pd, "Helm")
	}
	return `C:\ProgramData\Helm`
}
