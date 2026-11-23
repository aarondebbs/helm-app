# macOS agent

**Status: written and unit-tested for parsers only. It has not been run on a real Mac.** Expect fixes.

- Supports macOS 12+, Intel and Apple silicon. Shell, processes, services (launchctl), software, updates (softwareupdate), security scan, logs, power, messages, files.
- Not supported: remote screen, winget.
- Install: *Add a PC -> macOS*. Script: `sudo bash install-macos.sh` (token baked in). Package: run the unsigned `.pkg` with `helm-enroll.conf` next to it (or in `/Users/Shared`).
- The .pkg is built only on a Mac (`installer/build-pkg.sh`); the GitHub workflow does this on a macOS runner.
- Gatekeeper: unsigned pkgs need right-click -> Open (or `sudo installer -pkg ... -target /`).
- Grant **Full Disk Access** to `/usr/local/bin/helm-agent` (System Settings -> Privacy & Security) for complete logs, file access and scans.
- Config: `/Library/Application Support/Helm/agent.conf`; LaunchDaemon `com.helm.agent`.
