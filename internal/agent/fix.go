package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// One-click fixes for configuration findings. Only the fixed commands below can ever run: the console sends an
// identifier, never a command line. Anything that could lock the owner out (firewalls on a remote server, SSH
// settings, disk encryption) is deliberately not offered.

// WinFixes are PowerShell snippets keyed by scan check id.
var WinFixes = map[string]struct{ Does, Script string }{
	"firewall":      {"Turn Windows Firewall on for the domain, private and public profiles.", `Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True`},
	"av_realtime":   {"Turn Microsoft Defender real-time protection on.", `Set-MpPreference -DisableRealtimeMonitoring $false`},
	"av_signatures": {"Download the latest Defender definitions.", `Update-MpSignature`},
	"smb1":          {"Remove the obsolete SMBv1 protocol (finishes after a restart).", `Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart | Out-Null`},
	"rdp":           {"Require Network Level Authentication for Remote Desktop.", `Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name UserAuthentication -Value 1`},
	"uac":           {"Turn User Account Control on (finishes after a restart).", `Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name EnableLUA -Value 1`},
	"guest":         {"Disable the built-in Guest account.", `Disable-LocalUser -Name 'Guest'`},
}

// MacFixes and LinuxFixes are fixed argument vectors keyed by scan check id.
var MacFixes = map[string]struct {
	Does string
	Argv []string
}{
	"firewall":   {"Turn the macOS application firewall on.", []string{"/usr/libexec/ApplicationFirewall/socketfilterfw", "--setglobalstate", "on"}},
	"gatekeeper": {"Turn Gatekeeper on.", []string{"spctl", "--master-enable"}},
	"autoupdate": {"Turn on automatic update checks.", []string{"softwareupdate", "--schedule", "on"}},
	"guest":      {"Turn off the Guest account.", []string{"sysadminctl", "-guestAccount", "off"}},
}

var LinuxFixes = map[string]struct {
	Does string
	Argv []string
}{
	"auto_updates": {"Install unattended-upgrades so security updates install on their own.", []string{"apt-get", "install", "-y", "unattended-upgrades"}},
	"ntp":          {"Turn on network time synchronisation.", []string{"timedatectl", "set-ntp", "true"}},
}

const fixWrap = `# helm:fix
$ErrorActionPreference = 'Stop'
try { %s; @{ ok = $true } | ConvertTo-Json -Compress } catch { @{ ok = $false; message = "$_" } | ConvertTo-Json -Compress }`

func (a *Agent) cmdFixApply(ctx context.Context, c *cmdCtx) (any, error) {
	var args struct {
		ID string `json:"id"`
	}
	if err := decode(c.args, &args); err != nil {
		return nil, err
	}
	switch {
	case realMac():
		f, ok := MacFixes[args.ID]
		if !ok {
			return nil, errors.New("there is no one-click fix for this setting on macOS")
		}
		return runFix(ctx, f.Argv)
	case realLinux():
		f, ok := LinuxFixes[args.ID]
		if !ok {
			return nil, errors.New("there is no one-click fix for this setting on Linux")
		}
		return runFix(ctx, f.Argv)
	}
	f, ok := WinFixes[args.ID]
	if !ok {
		return nil, errors.New("there is no one-click fix for this setting")
	}
	raw, err := a.psJSON(ctx, fmt.Sprintf(fixWrap, f.Script), nil, 5*time.Minute)
	if err != nil {
		return nil, err
	}
	var r struct {
		OK      bool   `json:"ok"`
		Message string `json:"message"`
	}
	if json.Unmarshal(raw, &r) != nil {
		return nil, errors.New("unexpected result from the fix")
	}
	if !r.OK {
		return nil, errors.New(firstLines(r.Message, 400))
	}
	return map[string]any{"fixed": args.ID}, nil
}

func fixAvailable(os, id string) bool {
	switch os {
	case "darwin":
		_, ok := MacFixes[id]
		return ok
	case "linux":
		_, ok := LinuxFixes[id]
		return ok
	}
	_, ok := WinFixes[id]
	return ok
}
