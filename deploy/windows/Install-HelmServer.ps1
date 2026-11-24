<#
.SYNOPSIS
  Installs, upgrades, downgrades or removes the Helm server on Windows Server (2016 or newer) and Windows 10/11.

.DESCRIPTION
  Reads the releases of your GitHub repository, lets you pick a version, checks the download against the
  release's checksum list, and runs the server as the Windows service "HelmServer" that starts at boot and
  restarts itself if it stops. Run it from an elevated PowerShell:

    .\Install-HelmServer.ps1                      pick a version from a list
    .\Install-HelmServer.ps1 -Version v0.10.0     install exactly this version
    .\Install-HelmServer.ps1 -Version latest      install the newest release
    .\Install-HelmServer.ps1 -List                only show the available versions
    .\Install-HelmServer.ps1 -Uninstall           remove the service (data is kept unless -PurgeData)

  Running it again on a machine that already has Helm changes the version in place; your data is kept.
  Later you can also switch versions from the portal: Settings, Updates.
#>
[CmdletBinding()]
param(
  [string]$Repo = 'aarondebbs/helm-app',
  [string]$Version = '',
  [string]$InstallDir = (Join-Path $env:ProgramFiles 'Helm'),
  [string]$DataDir = (Join-Path $env:ProgramData 'Helm'),
  [string]$Listen = '127.0.0.1:8787',
  [string]$AdminUser = 'admin',
  [switch]$NoAdmin,
  [switch]$IncludePrerelease,
  [switch]$List,
  [switch]$Uninstall,
  [switch]$PurgeData
)
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$Svc = 'HelmServer'

function Say($m)  { Write-Host "  $m" }
function Head($m) { Write-Host ""; Write-Host $m -ForegroundColor Cyan }
function Fail($m) { Write-Host ""; Write-Host "  $m" -ForegroundColor Red; exit 1 }

if ($Repo -notmatch '^[A-Za-z0-9._-]{1,80}/[A-Za-z0-9._-]{1,100}$') { Fail "Repo must look like owner/name." }
$me = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $List -and -not $me.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
  Fail "Open PowerShell as Administrator and run this again."
}
$arch = switch ($env:PROCESSOR_ARCHITECTURE) { 'ARM64' { 'arm64' } default { 'amd64' } }
if ($env:PROCESSOR_ARCHITEW6432 -eq 'ARM64') { $arch = 'arm64' }
$asset = "helm-server-windows-$arch.exe"
$exe = Join-Path $InstallDir 'helm-server.exe'

# ---------- remove ----------
if ($Uninstall) {
  Head "Removing Helm server"
  if (Get-Service $Svc -ErrorAction SilentlyContinue) {
    Stop-Service $Svc -Force -ErrorAction SilentlyContinue
    & sc.exe delete $Svc | Out-Null
    Say "Service removed."
  }
  Get-NetFirewallRule -DisplayName 'Helm server' -ErrorAction SilentlyContinue | Remove-NetFirewallRule
  if (Test-Path $InstallDir) { Remove-Item $InstallDir -Recurse -Force }
  if ($PurgeData -and (Test-Path $DataDir)) { Remove-Item $DataDir -Recurse -Force; Say "Data deleted." }
  elseif (Test-Path $DataDir) { Say "Your data is still in $DataDir (add -PurgeData to delete it)." }
  exit 0
}

# ---------- find the releases ----------
function Get-Releases {
  $h = @{ 'User-Agent' = 'helm-installer'; 'Accept' = 'application/vnd.github+json' }
  try { $r = Invoke-RestMethod -Uri "https://api.github.com/repos/$Repo/releases?per_page=30" -Headers $h }
  catch { Fail "Could not read the releases of $Repo from GitHub ($($_.Exception.Message)). Check the name and that the repository is public." }
  $r | Where-Object {
    -not $_.draft -and ($IncludePrerelease -or -not $_.prerelease) -and
    ($_.assets | Where-Object { $_.name -eq $asset }) -and ($_.assets | Where-Object { $_.name -eq 'helm-release.json' })
  }
}
Head "Helm server for Windows  ($Repo, $arch)"
$rels = @(Get-Releases)
if ($rels.Count -eq 0) { Fail "No release of $Repo carries $asset yet. Publish a release with the Helm release workflow first." }

if ($List) {
  $rels | ForEach-Object { "{0,-10} {1:yyyy-MM-dd}  {2}" -f $_.tag_name, ([datetime]$_.published_at), (($_.body -split "`n")[0]) }
  exit 0
}

$chosen = $null
if ($Version -and $Version -ne 'latest') {
  $want = if ($Version.StartsWith('v')) { $Version } else { "v$Version" }
  $chosen = $rels | Where-Object { $_.tag_name -eq $want } | Select-Object -First 1
  if (-not $chosen) { Fail "Version $want was not found. Run with -List to see what is available." }
} elseif ($Version -eq 'latest') {
  $chosen = $rels[0]
} elseif ([Environment]::UserInteractive -and -not [Console]::IsInputRedirected) {
  Say "Which version do you want to install?"
  Write-Host ""
  for ($i = 0; $i -lt $rels.Count; $i++) {
    $r = $rels[$i]; $first = (($r.body -split "`n") | Where-Object { $_.Trim() } | Select-Object -First 1)
    if ($first -and $first.Length -gt 60) { $first = $first.Substring(0, 57) + '...' }
    $tag = if ($i -eq 0) { ' (latest)' } else { '' }
    Write-Host ("   [{0}] {1}{2}  {3:yyyy-MM-dd}  {4}" -f ($i + 1), $r.tag_name, $tag, ([datetime]$r.published_at), $first)
  }
  Write-Host ""
  $pick = Read-Host "  Number (Enter for the latest)"
  if ([string]::IsNullOrWhiteSpace($pick)) { $pick = '1' }
  if ($pick -notmatch '^\d+$' -or [int]$pick -lt 1 -or [int]$pick -gt $rels.Count) { Fail "That is not one of the numbers in the list." }
  $chosen = $rels[[int]$pick - 1]
} else { $chosen = $rels[0] }
$tag = $chosen.tag_name
Say "Installing $tag"
$notes = ($chosen.body | Out-String).Trim()
if ($notes) { Write-Host ""; ($notes -split "`n" | Select-Object -First 12 | ForEach-Object { "    $_" }); Write-Host "" }

# ---------- download and check ----------
$tmp = Join-Path ([IO.Path]::GetTempPath()) ("helm-" + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $tmp | Out-Null
try {
  $exeUrl = ($chosen.assets | Where-Object { $_.name -eq $asset }).browser_download_url
  $manUrl = ($chosen.assets | Where-Object { $_.name -eq 'helm-release.json' }).browser_download_url
  foreach ($u in @($exeUrl, $manUrl)) {
    if ($u -notmatch '^https://(github\.com|[A-Za-z0-9.-]+\.githubusercontent\.com)/') { Fail "Unexpected download address: $u" }
  }
  Say "Downloading $asset ..."
  Invoke-WebRequest -Uri $exeUrl -OutFile (Join-Path $tmp $asset) -UseBasicParsing
  Invoke-WebRequest -Uri $manUrl -OutFile (Join-Path $tmp 'helm-release.json') -UseBasicParsing
  $man = Get-Content (Join-Path $tmp 'helm-release.json') -Raw | ConvertFrom-Json
  $entry = $man.files | Where-Object { $_.name -eq $asset } | Select-Object -First 1
  if (-not $entry) { Fail "The release list does not mention $asset." }
  $got = (Get-FileHash (Join-Path $tmp $asset) -Algorithm SHA256).Hash.ToLower()
  if ($got -ne $entry.sha256.ToLower()) { Fail "The download does not match the release's checksum. Nothing was installed." }
  Say "Checksum OK. (The server also checks the release signature itself whenever it updates.)"

  # ---------- install ----------
  Head "Installing"
  $existing = Get-Service $Svc -ErrorAction SilentlyContinue
  if ($existing) {
    Say "Helm is already installed: switching the version, your data stays."
    Stop-Service $Svc -Force -ErrorAction SilentlyContinue
    (Get-Process helm-server -ErrorAction SilentlyContinue) | Where-Object { $_.Path -eq $exe } | Stop-Process -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 1
  }
  New-Item -ItemType Directory -Force -Path $InstallDir, $DataDir | Out-Null
  if (Test-Path $exe) { Copy-Item $exe "$exe.prev" -Force }
  Copy-Item (Join-Path $tmp $asset) $exe -Force

  # Only administrators and the service may touch these folders.
  & icacls.exe $InstallDir /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' '*S-1-5-19:(OI)(CI)M' | Out-Null
  & icacls.exe $DataDir    /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' '*S-1-5-19:(OI)(CI)M' | Out-Null

  $bin = "`"$exe`" serve -data `"$DataDir`" -listen $Listen -update-repo $Repo"
  # New-Service and the registry keep the quotes in the path intact (sc.exe on Windows PowerShell 5.1 does not).
  if (-not $existing) {
    New-Service -Name $Svc -BinaryPathName $bin -DisplayName 'Helm server' | Out-Null
  }
  Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\$Svc" -Name ImagePath -Value $bin
  & sc.exe config $Svc start= delayed-auto obj= 'NT AUTHORITY\LocalService' | Out-Null
  if ($LASTEXITCODE -ne 0) { Fail "Windows refused to configure the service (sc.exe exit $LASTEXITCODE)." }
  & sc.exe description $Svc 'Helm management server: web console and agent hub.' | Out-Null
  # Restart after 5 s, 10 s, then 30 s; this is also how a version switch from the portal comes back up.
  & sc.exe failure $Svc reset= 86400 actions= restart/5000/restart/10000/restart/30000 | Out-Null
  & sc.exe failureflag $Svc 1 | Out-Null

  $bindsAll = $Listen -notmatch '^(127\.0\.0\.1|localhost|\[::1\])'
  Get-NetFirewallRule -DisplayName 'Helm server' -ErrorAction SilentlyContinue | Remove-NetFirewallRule
  if ($bindsAll) {
    $port = ($Listen -split ':')[-1]
    New-NetFirewallRule -DisplayName 'Helm server' -Direction Inbound -Protocol TCP -LocalPort $port -Action Allow | Out-Null
    Say "Opened Windows Firewall for TCP $port because you chose to listen beyond this machine."
  }

  # ---------- first administrator ----------
  $hasAdmin = Test-Path (Join-Path $DataDir 'state.json')
  if (-not $hasAdmin -and -not $NoAdmin) {
    Head "Create the administrator"
    Say "Choose a password of at least 12 characters."
    $p1 = Read-Host "  Password for '$AdminUser'" -AsSecureString
    $p2 = Read-Host "  Repeat it" -AsSecureString
    $b1 = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($p1); $b2 = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($p2)
    $s1 = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($b1); $s2 = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($b2)
    [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($b1); [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($b2)
    if ($s1 -ne $s2) { Fail "The passwords do not match. Run the script again." }
    $env:HELM_ADMIN_PASSWORD = $s1
    try { & $exe init-admin -data $DataDir -user $AdminUser } finally { Remove-Item Env:\HELM_ADMIN_PASSWORD -ErrorAction SilentlyContinue }
    if ($LASTEXITCODE -ne 0) { Fail "Could not create the administrator." }
    & icacls.exe $DataDir /grant '*S-1-5-19:(OI)(CI)M' /T /C | Out-Null
  }

  Start-Service $Svc
  $ok = $false
  $url = "http://" + ($Listen -replace '^0\.0\.0\.0', '127.0.0.1' -replace '^\[::\]', '127.0.0.1') + "/api/auth/config"
  for ($i = 0; $i -lt 20 -and -not $ok; $i++) {
    Start-Sleep -Milliseconds 700
    try { Invoke-WebRequest -Uri $url -UseBasicParsing -TimeoutSec 3 | Out-Null; $ok = $true } catch {}
  }
  if (-not $ok) { Fail "The service started but did not answer. Look in Event Viewer, Windows Logs, Application." }
  Head "Helm $tag is running"
  Say "Console on this machine:  http://$Listen"
  Say "Switch versions later:    Settings, Updates in the console, or run this script again."
  Write-Host ""
  Say "To reach it from the internet over HTTPS, install Tailscale on this server and run:"
  Say "    tailscale funnel --bg $(($Listen -split ':')[-1])"
} finally {
  Remove-Item $tmp -Recurse -Force -ErrorAction SilentlyContinue
}
