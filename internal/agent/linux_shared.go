package agent

import (
	"os"
	"runtime"
)

// realLinux reports whether the agent runs on a real Linux host (not the fixture-driven test mode).
func realLinux() bool { return runtime.GOOS == "linux" && os.Getenv("HELM_FIXTURES") != "1" }

// realMac reports whether the agent runs on a real macOS host.
func realMac() bool { return runtime.GOOS == "darwin" && os.Getenv("HELM_FIXTURES") != "1" }

// realUnix is true on a real Linux or macOS host: config file, no Windows service manager, native handlers.
func realUnix() bool { return realLinux() || realMac() }

// unixConfPath is the root-owned agent configuration file.
func unixConfPath() string {
	if runtime.GOOS == "darwin" {
		return "/Library/Application Support/Helm/agent.conf"
	}
	return "/etc/helm-agent/agent.conf"
}
