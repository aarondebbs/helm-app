package agent

// PowerShell scripts used by the agent. Each starts with a "# helm:<name>"
// marker line (used by development fixtures). Arguments are passed through
// environment variables (HELM_A_*), never interpolated into the script text.
// All scripts run as SYSTEM under Windows PowerShell 5.1.

const psHeader = "[Console]::OutputEncoding=[System.Text.UTF8Encoding]::new($false)\n$ProgressPreference='SilentlyContinue'\n"

const scriptInventory = `# helm:inventory
$ErrorActionPreference='SilentlyContinue'
$os = Get-CimInstance Win32_OperatingSystem
$cs = Get-CimInstance Win32_ComputerSystem
$bios = Get-CimInstance Win32_BIOS
$cpu = Get-CimInstance Win32_Processor | Select-Object -First 1
$gpu = @(Get-CimInstance Win32_VideoController | ForEach-Object { $_.Name })
$disks = @(Get-CimInstance Win32_DiskDrive | ForEach-Object { [pscustomobject]@{ model=$_.Model; sizeBytes=[int64]$_.Size } })
$av = @(Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct | ForEach-Object { $_.displayName })
$mp = Get-MpComputerStatus
$net = @(Get-CimInstance Win32_NetworkAdapterConfiguration | Where-Object { $_.IPEnabled } | ForEach-Object { [pscustomobject]@{ description=$_.Description; mac=$_.MACAddress; ips=@($_.IPAddress); dns=@($_.DNSServerSearchOrder) } })
$fw = @(Get-NetFirewallProfile | ForEach-Object { [pscustomobject]@{ name="$($_.Name)"; enabled=[bool]$_.Enabled } })
$rp = (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired') -or (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending')
$obj = [pscustomobject]@{
  computerName = $env:COMPUTERNAME
  domain = $cs.Domain
  partOfDomain = $cs.PartOfDomain
  manufacturer = $cs.Manufacturer
  model = $cs.Model
  serial = $bios.SerialNumber
  biosVersion = $bios.SMBIOSBIOSVersion
  osCaption = $os.Caption
  osVersion = $os.Version
  osBuild = $os.BuildNumber
  osArch = $os.OSArchitecture
  installDate = $(if($os.InstallDate){$os.InstallDate.ToString('o')}else{$null})
  lastBoot = $(if($os.LastBootUpTime){$os.LastBootUpTime.ToString('o')}else{$null})
  cpu = $cpu.Name
  cores = $cpu.NumberOfCores
  threads = $cpu.NumberOfLogicalProcessors
  ramBytes = [int64]$cs.TotalPhysicalMemory
  gpu = $gpu
  disks = $disks
  network = $net
  antivirus = $av
  defender = $(if($mp){ [pscustomobject]@{ enabled=$mp.AntivirusEnabled; realtime=$mp.RealTimeProtectionEnabled; signatureAgeDays=$mp.AntivirusSignatureAge } }else{$null})
  firewall = $fw
  timezone = (Get-TimeZone).Id
  pendingReboot = [bool]$rp
}
ConvertTo-Json -InputObject $obj -Compress -Depth 5
`

const scriptSoftware = `# helm:software
$ErrorActionPreference='SilentlyContinue'
$paths = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*','HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
$list = @(Get-ItemProperty $paths | Where-Object { $_.DisplayName -and -not $_.SystemComponent } | Sort-Object DisplayName |
  ForEach-Object { [pscustomobject]@{ name=$_.DisplayName; version=$_.DisplayVersion; publisher=$_.Publisher; installDate=$_.InstallDate } })
ConvertTo-Json -InputObject $list -Compress -Depth 3
`

const scriptProcesses = `# helm:processes
$ErrorActionPreference='SilentlyContinue'
$p = @(Get-Process -IncludeUserName | ForEach-Object {
  [pscustomobject]@{ pid=$_.Id; name=$_.ProcessName; cpu=[math]::Round([double]$_.CPU,1); memMB=[math]::Round($_.WorkingSet64/1MB,1); user=$_.UserName; path=$_.Path }
})
ConvertTo-Json -InputObject $p -Compress -Depth 3
`

const scriptServices = `# helm:services
$ErrorActionPreference='SilentlyContinue'
$s = @(Get-CimInstance Win32_Service | ForEach-Object {
  [pscustomobject]@{ name=$_.Name; display=$_.DisplayName; state=$_.State; start=$_.StartMode; account=$_.StartName }
})
ConvertTo-Json -InputObject $s -Compress -Depth 3
`

const scriptServiceControl = `# helm:servicecontrol
$ErrorActionPreference='Stop'
$n = $env:HELM_A_NAME
switch ($env:HELM_A_ACTION) {
  'start'   { Start-Service -Name $n }
  'stop'    { Stop-Service -Name $n -Force }
  'restart' { Restart-Service -Name $n -Force }
  'auto'    { Set-Service -Name $n -StartupType Automatic }
  'manual'  { Set-Service -Name $n -StartupType Manual }
  'disable' { Set-Service -Name $n -StartupType Disabled }
  default   { throw 'unknown action' }
}
$s = Get-Service -Name $n
ConvertTo-Json -InputObject ([pscustomobject]@{ name=$s.Name; status="$($s.Status)"; startType="$($s.StartType)" }) -Compress
`

const scriptEventLog = `# helm:eventlog
$ErrorActionPreference='Stop'
switch ($env:HELM_A_LEVEL) { 'errors' { $lvl = 1,2 } 'warnings' { $lvl = 1,2,3 } default { $lvl = 1,2,3,4 } }
try {
  $ev = @(Get-WinEvent -FilterHashtable @{ LogName=$env:HELM_A_LOG; Level=$lvl } -MaxEvents ([int]$env:HELM_A_COUNT) | ForEach-Object {
    $m = ''; if ($_.Message) { $m = $_.Message; if ($m.Length -gt 600) { $m = $m.Substring(0,600) } }
    [pscustomobject]@{ time=$_.TimeCreated.ToString('o'); id=$_.Id; provider=$_.ProviderName; level=$_.LevelDisplayName; message=$m }
  })
} catch [System.Exception] {
  if ($_.FullyQualifiedErrorId -like 'NoMatchingEventsFound*') { $ev = @() } else { throw }
}
ConvertTo-Json -InputObject $ev -Compress -Depth 3
`

const scriptUpdatesCheck = `# helm:updatescheck
$ErrorActionPreference='Stop'
$session = New-Object -ComObject Microsoft.Update.Session
$searcher = $session.CreateUpdateSearcher()
$res = $searcher.Search("IsInstalled=0 and IsHidden=0")
$list = @()
foreach ($u in $res.Updates) {
  $list += [pscustomobject]@{
    id = $u.Identity.UpdateID
    title = $u.Title
    kb = @($u.KBArticleIDs)
    sizeMB = [math]::Round($u.MaxDownloadSize/1MB,1)
    severity = $u.MsrcSeverity
    needsReboot = ($u.InstallationBehavior.RebootBehavior -ne 0)
    downloaded = [bool]$u.IsDownloaded
    categories = @($u.Categories | ForEach-Object { $_.Name })
  }
}
$rp = (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired') -or (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending')
ConvertTo-Json -InputObject ([pscustomobject]@{ updates=@($list); rebootPending=[bool]$rp }) -Compress -Depth 4
`

const scriptUpdatesInstall = `# helm:updatesinstall
$ErrorActionPreference='Stop'
$want = @()
if ($env:HELM_A_IDS) { $want = @($env:HELM_A_IDS -split ',') }
$session = New-Object -ComObject Microsoft.Update.Session
$searcher = $session.CreateUpdateSearcher()
$res = $searcher.Search("IsInstalled=0 and IsHidden=0")
$coll = New-Object -ComObject Microsoft.Update.UpdateColl
foreach ($u in $res.Updates) {
  if ($want.Count -eq 0 -or $want -contains $u.Identity.UpdateID) {
    if (-not $u.EulaAccepted) { $u.AcceptEula() }
    [void]$coll.Add($u)
  }
}
if ($coll.Count -eq 0) { Write-Output 'RESULT:{"installed":0,"resultCode":2,"rebootRequired":false,"items":[]}'; exit 0 }
Write-Output "PROGRESS:Downloading $($coll.Count) update(s)..."
$dl = $session.CreateUpdateDownloader(); $dl.Updates = $coll; $null = $dl.Download()
Write-Output "PROGRESS:Installing..."
$inst = $session.CreateUpdateInstaller(); $inst.Updates = $coll
$ir = $inst.Install()
$items = @()
for ($i = 0; $i -lt $coll.Count; $i++) { $items += [pscustomobject]@{ title=$coll.Item($i).Title; resultCode=$ir.GetUpdateResult($i).ResultCode } }
$out = [pscustomobject]@{ installed=$coll.Count; resultCode=$ir.ResultCode; rebootRequired=[bool]$ir.RebootRequired; items=$items }
Write-Output ('RESULT:' + (ConvertTo-Json -InputObject $out -Compress -Depth 4))
`

const scriptRDPStatus = `# helm:rdpstatus
$ErrorActionPreference='SilentlyContinue'
$ts = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server'
$deny = (Get-ItemProperty $ts).fDenyTSConnections
$rdp = Get-ItemProperty "$ts\WinStations\RDP-Tcp"
$ed = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion').EditionID
$svc = Get-Service TermService
ConvertTo-Json -InputObject ([pscustomobject]@{
  enabled = ($deny -eq 0); port = [int]$rdp.PortNumber; nla = ($rdp.UserAuthentication -eq 1)
  edition = $ed; supported = ($ed -notmatch '^Core'); service = $(if($svc){"$($svc.Status)"}else{'missing'})
}) -Compress
`

const scriptRDPSet = `# helm:rdpset
$ErrorActionPreference='Stop'
$ts = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server'
$ed = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion').EditionID
if ($env:HELM_A_ENABLE -eq '1') {
  if ($ed -match '^Core') { throw 'Remote Desktop hosting is not available on Windows Home editions.' }
  Set-ItemProperty -Path $ts -Name fDenyTSConnections -Value 0
  Set-ItemProperty -Path "$ts\WinStations\RDP-Tcp" -Name UserAuthentication -Value 1
  Set-Service -Name TermService -StartupType Manual
  Start-Service -Name TermService
  'Remote Desktop enabled (network level authentication required). No firewall rule was added: access is through the Helm tunnel only.'
} else {
  Set-ItemProperty -Path $ts -Name fDenyTSConnections -Value 1
  'Remote Desktop disabled.'
}
`
