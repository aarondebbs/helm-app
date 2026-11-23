//go:build windows

package server

func diskSpace(dir string) (total, free int64) { return 0, 0 }
