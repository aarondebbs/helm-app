package agent

import (
	"context"
	"time"
)

// Vulnerability-scan collectors. Each returns raw facts; the server turns them into findings
// (CVE matching, scoring) so rules can improve without touching the agents.

const scriptScanSoftware = `# helm:scansoftware
$ErrorActionPreference='SilentlyContinue'
$keys = @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*','HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*')
# also the per-user installs of every loaded user hive (users who are signed in)
foreach ($h in (Get-ChildItem Registry::HKEY_USERS | Where-Object { $_.PSChildName -match '^S-1-5-21-[0-9-]+$' })) {
  $keys += "Registry::HKEY_USERS\$($h.PSChildName)\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*"
}
$seen = @{}
$list = New-Object System.Collections.ArrayList
foreach ($k in $keys) {
  foreach ($i in (Get-ItemProperty $k)) {
    if (-not $i.DisplayName -or $i.SystemComponent -eq 1 -or $i.ParentKeyName) { continue }
    $id = "$($i.DisplayName)|$($i.DisplayVersion)"
    if ($seen.ContainsKey($id)) { continue }
    $seen[$id] = $true
    $scope = 'machine'; if ($k -like 'Registry::HKEY_USERS*') { $scope = 'user' }
    [void]$list.Add([pscustomobject]@{ name="$($i.DisplayName)"; version="$($i.DisplayVersion)"; publisher="$($i.Publisher)"; installDate="$($i.InstallDate)"; scope=$scope })
  }
}
ConvertTo-Json -InputObject @($list | Sort-Object name) -Compress -Depth 3
`

const scriptScanPorts = `# helm:scanports
$ErrorActionPreference='SilentlyContinue'
$procs = @{}
foreach ($p in (Get-Process)) { $procs[[int]$p.Id] = $p.ProcessName }
$seen = @{}
$out = New-Object System.Collections.ArrayList
foreach ($c in (Get-NetTCPConnection -State Listen)) {
  $id = "$($c.LocalAddress):$($c.LocalPort)"
  if ($seen.ContainsKey($id)) { continue }
  $seen[$id] = $true
  [void]$out.Add([pscustomobject]@{ proto='tcp'; address="$($c.LocalAddress)"; port=[int]$c.LocalPort; pid=[int]$c.OwningProcess; process="$($procs[[int]$c.OwningProcess])" })
}
ConvertTo-Json -InputObject @($out | Sort-Object port) -Compress -Depth 3
`

// scriptScanConfig emits {"build":N,"edition":"..","checks":[{id,title,category,severity,status,detail,fix}]}.
// status: pass | fail | warn | na. severity (when not passing): critical | high | medium | low.
const scriptScanConfig = `# helm:scanconfig
$ErrorActionPreference='SilentlyContinue'
$checks = New-Object System.Collections.ArrayList
function Add-Check($id,$title,$cat,$sev,$status,$detail,$fix) {
  [void]$checks.Add([pscustomobject]@{ id=$id; title=$title; category=$cat; severity=$sev; status=$status; detail="$detail"; fix="$fix" })
}
function Reg($path,$name) { try { (Get-ItemProperty -Path $path -Name $name -ErrorAction Stop).$name } catch { $null } }

$cv = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
$build = [int]$cv.CurrentBuildNumber
$edition = "$($cv.EditionID)"

# --- Defender / antivirus
$mp = Get-MpComputerStatus
$av = @(Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct | ForEach-Object { $_.displayName })
$third = @($av | Where-Object { $_ -and $_ -notmatch 'Windows Defender|Microsoft Defender' })
if ($mp) {
  if ($mp.RealTimeProtectionEnabled) { Add-Check 'av_realtime' 'Real-time antivirus protection' 'Malware protection' 'high' 'pass' 'Microsoft Defender real-time protection is on.' '' }
  elseif ($third.Count -gt 0) { Add-Check 'av_realtime' 'Real-time antivirus protection' 'Malware protection' 'low' 'warn' ("Defender is off; another product is registered: " + ($third -join ', ')) 'Make sure that product is active and up to date.' }
  else { Add-Check 'av_realtime' 'Real-time antivirus protection' 'Malware protection' 'high' 'fail' 'Real-time protection is off and no other antivirus is registered.' 'Turn on real-time protection in Windows Security.' }
  $age = [int]$mp.AntivirusSignatureAge
  if ($mp.RealTimeProtectionEnabled) {
    if ($age -gt 7) { Add-Check 'av_signatures' 'Antivirus definitions up to date' 'Malware protection' 'medium' 'fail' "Definitions are $age days old." 'Run Windows Update / update Defender definitions.' }
    elseif ($age -gt 3) { Add-Check 'av_signatures' 'Antivirus definitions up to date' 'Malware protection' 'low' 'warn' "Definitions are $age days old." 'Update Defender definitions.' }
    else { Add-Check 'av_signatures' 'Antivirus definitions up to date' 'Malware protection' 'medium' 'pass' "Definitions are $age day(s) old." '' }
  }
} elseif ($av.Count -gt 0) { Add-Check 'av_realtime' 'Real-time antivirus protection' 'Malware protection' 'high' 'pass' ("Registered: " + ($av -join ', ')) '' }
else { Add-Check 'av_realtime' 'Real-time antivirus protection' 'Malware protection' 'high' 'fail' 'No antivirus product is registered.' 'Install or enable an antivirus.' }

# --- firewall
$fw = @(Get-NetFirewallProfile)
if ($fw.Count -gt 0) {
  $off = @($fw | Where-Object { -not $_.Enabled } | ForEach-Object { "$($_.Name)" })
  if ($off.Count -eq 0) { Add-Check 'firewall' 'Windows Firewall enabled' 'Network' 'high' 'pass' 'All firewall profiles are on.' '' }
  else { Add-Check 'firewall' 'Windows Firewall enabled' 'Network' 'high' 'fail' ("Off for: " + ($off -join ', ')) 'Turn the firewall on for every profile.' }
}

# --- disk encryption
$bl = $null
try { $bl = Get-BitLockerVolume -MountPoint $env:SystemDrive -ErrorAction Stop } catch { }
if ($bl) {
  if ("$($bl.ProtectionStatus)" -eq 'On' -or $bl.ProtectionStatus -eq 1) { Add-Check 'bitlocker' 'System drive encrypted (BitLocker)' 'Data protection' 'medium' 'pass' 'BitLocker protection is on.' '' }
  else { Add-Check 'bitlocker' 'System drive encrypted (BitLocker)' 'Data protection' 'medium' 'fail' 'The system drive is not protected by BitLocker.' 'Enable BitLocker (or device encryption) and back up the recovery key.' }
} else { Add-Check 'bitlocker' 'System drive encrypted (BitLocker)' 'Data protection' 'medium' 'na' 'BitLocker status is not available on this edition.' '' }

# --- SMBv1
$smb1 = $null
try { $smb1 = (Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -ErrorAction Stop).State } catch { }
if ($smb1) {
  if ("$smb1" -eq 'Enabled') { Add-Check 'smb1' 'SMBv1 disabled' 'Network' 'high' 'fail' 'The obsolete SMBv1 protocol is enabled.' 'Disable the SMB 1.0 Windows feature.' }
  else { Add-Check 'smb1' 'SMBv1 disabled' 'Network' 'high' 'pass' 'SMBv1 is disabled.' '' }
}

# --- Remote Desktop
$deny = Reg 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' 'fDenyTSConnections'
$nla = Reg 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' 'UserAuthentication'
if ($null -ne $deny) {
  if ($deny -eq 1) { Add-Check 'rdp' 'Remote Desktop exposure' 'Network' 'high' 'pass' 'Remote Desktop is disabled.' '' }
  elseif ($nla -eq 1) { Add-Check 'rdp' 'Remote Desktop exposure' 'Network' 'low' 'warn' 'Remote Desktop is enabled with Network Level Authentication.' 'Disable it if you do not use it.' }
  else { Add-Check 'rdp' 'Remote Desktop exposure' 'Network' 'high' 'fail' 'Remote Desktop is enabled WITHOUT Network Level Authentication.' 'Require Network Level Authentication, or disable Remote Desktop.' }
}

# --- UAC
$lua = Reg 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' 'EnableLUA'
if ($null -ne $lua) {
  if ($lua -eq 1) { Add-Check 'uac' 'User Account Control enabled' 'Accounts' 'high' 'pass' 'UAC is on.' '' }
  else { Add-Check 'uac' 'User Account Control enabled' 'Accounts' 'high' 'fail' 'UAC is turned off.' 'Turn UAC on.' }
}

# --- firmware
$sb = $null
try { $sb = Confirm-SecureBootUEFI -ErrorAction Stop } catch { }
if ($null -ne $sb) {
  if ($sb) { Add-Check 'secureboot' 'Secure Boot enabled' 'Firmware' 'medium' 'pass' 'Secure Boot is on.' '' }
  else { Add-Check 'secureboot' 'Secure Boot enabled' 'Firmware' 'medium' 'fail' 'Secure Boot is off.' 'Enable Secure Boot in the firmware settings.' }
} else { Add-Check 'secureboot' 'Secure Boot enabled' 'Firmware' 'medium' 'na' 'Secure Boot is not available (legacy BIOS or unsupported).' '' }
$tpm = Get-Tpm
if ($tpm) {
  if ($tpm.TpmPresent -and $tpm.TpmReady) { Add-Check 'tpm' 'TPM present and ready' 'Firmware' 'low' 'pass' 'A TPM is present and ready.' '' }
  else { Add-Check 'tpm' 'TPM present and ready' 'Firmware' 'low' 'warn' 'No ready TPM was found.' 'Enable the TPM in firmware if the PC has one.' }
}

# --- accounts
$aal = Reg 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' 'AutoAdminLogon'
$dpw = Reg 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' 'DefaultPassword'
if ("$aal" -eq '1') {
  if ($dpw) { Add-Check 'autologon' 'No automatic sign-in with a stored password' 'Accounts' 'high' 'fail' 'Automatic sign-in is on and a password is stored in plain text in the registry.' 'Turn off automatic sign-in.' }
  else { Add-Check 'autologon' 'No automatic sign-in with a stored password' 'Accounts' 'medium' 'warn' 'Automatic sign-in is enabled.' 'Turn off automatic sign-in if the PC leaves a trusted place.' }
} else { Add-Check 'autologon' 'No automatic sign-in with a stored password' 'Accounts' 'high' 'pass' 'Automatic sign-in is off.' '' }
$guest = Get-LocalUser -Name 'Guest'
if ($guest) {
  if ($guest.Enabled) { Add-Check 'guest' 'Guest account disabled' 'Accounts' 'medium' 'fail' 'The built-in Guest account is enabled.' 'Disable the Guest account.' }
  else { Add-Check 'guest' 'Guest account disabled' 'Accounts' 'medium' 'pass' 'The Guest account is disabled.' '' }
}
$admins = @(Get-LocalGroupMember -SID 'S-1-5-32-544' | ForEach-Object { "$($_.Name)" })
if ($admins.Count -gt 0) {
  if ($admins.Count -gt 3) { Add-Check 'admins' 'Few local administrators' 'Accounts' 'low' 'warn' ("$($admins.Count) administrators: " + ($admins -join ', ')) 'Remove admin rights from accounts that do not need them.' }
  else { Add-Check 'admins' 'Few local administrators' 'Accounts' 'low' 'pass' ("Administrators: " + ($admins -join ', ')) '' }
}
$tmp = Join-Path $env:TEMP ("helm-sec-" + [guid]::NewGuid().ToString('N') + '.inf')
try {
  & secedit.exe /export /cfg $tmp /areas SECURITYPOLICY | Out-Null
  $inf = Get-Content $tmp -ErrorAction Stop
  $minLen = $null; $lock = $null
  foreach ($l in $inf) {
    if ($l -match '^\s*MinimumPasswordLength\s*=\s*(\d+)') { $minLen = [int]$Matches[1] }
    if ($l -match '^\s*LockoutBadCount\s*=\s*(\d+)') { $lock = [int]$Matches[1] }
  }
  if ($null -ne $minLen) {
    if ($minLen -lt 8) { Add-Check 'pw_length' 'Minimum password length' 'Accounts' 'medium' 'fail' "Minimum length is $minLen." 'Require at least 8 (better 12) characters.' }
    else { Add-Check 'pw_length' 'Minimum password length' 'Accounts' 'medium' 'pass' "Minimum length is $minLen." '' }
  }
  if ($null -ne $lock) {
    if ($lock -eq 0) { Add-Check 'pw_lockout' 'Account lockout after failed sign-ins' 'Accounts' 'medium' 'fail' 'Accounts are never locked after failed sign-ins.' 'Set an account lockout threshold (e.g. 10 attempts).' }
    else { Add-Check 'pw_lockout' 'Account lockout after failed sign-ins' 'Accounts' 'medium' 'pass' "Lockout after $lock failed attempts." '' }
  }
} catch { } finally { Remove-Item $tmp -Force -ErrorAction SilentlyContinue }

# --- OS hygiene
$wu = Get-Service -Name wuauserv
$nau = Reg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU' 'NoAutoUpdate'
if ($wu) {
  if ("$($wu.StartType)" -eq 'Disabled' -or $nau -eq 1) { Add-Check 'wu_enabled' 'Windows Update is enabled' 'Patching' 'high' 'fail' 'Windows Update is disabled by service or policy.' 'Re-enable the Windows Update service / policy.' }
  else { Add-Check 'wu_enabled' 'Windows Update is enabled' 'Patching' 'high' 'pass' 'Windows Update is enabled.' '' }
}
$rp = (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired') -or (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending')
if ($rp) { Add-Check 'reboot' 'No restart pending' 'Patching' 'low' 'warn' 'A restart is pending; some patches are not active yet.' 'Restart the PC.' }
else { Add-Check 'reboot' 'No restart pending' 'Patching' 'low' 'pass' 'No restart pending.' '' }
$eol = @{ 19045='2025-10-14'; 22000='2023-10-10'; 22621='2024-10-08'; 22631='2025-11-11'; 26100='2026-10-13' }
if ($edition -match 'Enterprise|Education' ) { Add-Check 'os_support' 'Windows version still receives security updates' 'Patching' 'high' 'na' "Build $build ($edition) has a longer service period; verify it in Microsoft's lifecycle tables." '' }
elseif ($eol.ContainsKey($build)) {
  if ([datetime]::UtcNow -gt [datetime]::Parse($eol[$build])) { Add-Check 'os_support' 'Windows version still receives security updates' 'Patching' 'high' 'fail' "Windows build $build reached the end of servicing on $($eol[$build])." 'Upgrade to a supported Windows version.' }
  else { Add-Check 'os_support' 'Windows version still receives security updates' 'Patching' 'high' 'pass' "Windows build $build is serviced until $($eol[$build])." '' }
}
$lsa = Reg 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'RunAsPPL'
if ($lsa -eq 1 -or $lsa -eq 2) { Add-Check 'lsa' 'LSA protection enabled' 'Hardening' 'low' 'pass' 'LSA runs as a protected process.' '' }
else { Add-Check 'lsa' 'LSA protection enabled' 'Hardening' 'low' 'warn' 'LSA protection is not enabled.' 'Enable "Configure LSASS to run as a protected process".' }
$v2 = $null
try { $v2 = (Get-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root -ErrorAction Stop).State } catch { }
if ($v2) {
  if ("$v2" -eq 'Enabled') { Add-Check 'ps2' 'PowerShell 2.0 disabled' 'Hardening' 'low' 'warn' 'The legacy PowerShell 2.0 engine is installed.' 'Remove the PowerShell 2.0 Windows feature.' }
  else { Add-Check 'ps2' 'PowerShell 2.0 disabled' 'Hardening' 'low' 'pass' 'PowerShell 2.0 is not installed.' '' }
}
ConvertTo-Json -InputObject ([pscustomobject]@{ build=$build; edition=$edition; checks=@($checks) }) -Compress -Depth 4
`

func (a *Agent) scanHandlers() map[string]handlerFn {
	return map[string]handlerFn{
		"scan.software": func(ctx context.Context, c *cmdCtx) (any, error) {
			return a.psJSON(ctx, scriptScanSoftware, nil, 3*time.Minute)
		},
		"scan.config": func(ctx context.Context, c *cmdCtx) (any, error) {
			return a.psJSON(ctx, scriptScanConfig, nil, 4*time.Minute)
		},
		"scan.ports": func(ctx context.Context, c *cmdCtx) (any, error) {
			return a.psJSON(ctx, scriptScanPorts, nil, 2*time.Minute)
		},
	}
}
