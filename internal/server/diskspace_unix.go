//go:build !windows

package server

import "syscall"

// diskSpace returns the total and free bytes of the filesystem holding dir.
func diskSpace(dir string) (total, free int64) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(dir, &st); err != nil {
		return 0, 0
	}
	return int64(st.Blocks) * int64(st.Bsize), int64(st.Bavail) * int64(st.Bsize)
}
