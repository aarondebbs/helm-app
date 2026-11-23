package agent

import (
	"context"
	"errors"
	"net"
	"regexp"
	"runtime"
	"strings"
	"time"

	"helm/internal/netscan"
)

// cmdNetScan scans the network this PC is on and reports the devices that answer.
func (a *Agent) cmdNetScan(ctx context.Context, c *cmdCtx) (any, error) {
	var args struct {
		CIDR string `json:"cidr"`
	}
	if err := decode(c.args, &args); err != nil {
		return nil, err
	}
	cidr := strings.TrimSpace(args.CIDR)
	if cidr == "" {
		l := netscan.LocalCIDRs()
		if len(l) == 0 {
			return nil, errors.New("this PC is not on a private network")
		}
		cidr = l[0]
	}
	c.pct(1, "Scanning "+cidr)
	hosts, err := netscan.Scan(ctx, cidr, func(p int, m string) { c.pct(p, m) })
	if err != nil {
		return nil, err
	}
	return map[string]any{"cidr": cidr, "hosts": hosts}, nil
}

var hostRe = regexp.MustCompile(`^[A-Za-z0-9.\-]{1,100}$`)

const scriptPushInstall = `# helm:pushinstall
$ErrorActionPreference='Stop'
$h = $env:HELM_A_HOST
$sec = ConvertTo-SecureString $env:HELM_A_PW -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential($env:HELM_A_USER, $sec)
Write-Output "PROGRESS:10:Connecting to $h"
$old = $null; $changed = $false
try { $old = (Get-Item WSMan:\localhost\Client\TrustedHosts).Value } catch {}
if ($h -match '^\d+\.\d+\.\d+\.\d+$' -and ($old -split ',') -notcontains $h) {
  Set-Item WSMan:\localhost\Client\TrustedHosts -Value $h -Concatenate -Force; $changed = $true
}
try {
  $opt = New-PSSessionOption -OpenTimeout 30000 -OperationTimeout 600000
  $s = New-PSSession -ComputerName $h -Credential $cred -SessionOption $opt -Authentication Negotiate
  Write-Output "PROGRESS:35:Connected. Downloading the installer on the PC"
  $code = Invoke-Command -Session $s -ArgumentList $env:HELM_A_SERVER, $env:HELM_A_TOKEN -ScriptBlock {
    param($srv, $tok)
    $ErrorActionPreference = 'Stop'
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    $msi = Join-Path $env:TEMP 'Helm-Agent.msi'
    Invoke-WebRequest -UseBasicParsing -Uri "$srv/dl/Helm-Agent.msi" -OutFile $msi
    $p = Start-Process msiexec.exe -ArgumentList "/i ""$msi"" /qn SERVER=$srv TOKEN=$tok" -Wait -PassThru
    Remove-Item $msi -Force -ErrorAction SilentlyContinue
    $p.ExitCode
  }
  Remove-PSSession $s
} finally {
  if ($changed) { try { Set-Item WSMan:\localhost\Client\TrustedHosts -Value $old -Force } catch {} }
}
Write-Output "PROGRESS:90:Installer finished"
if ($code -ne 0 -and $code -ne 3010) { throw "The installer on the PC returned code $code." }
Write-Output ('RESULT:{"host":"' + $h + '","exitCode":' + $code + '}')
`

// cmdPushInstall installs the Helm agent on another Windows PC on this network over PowerShell remoting.
// The credentials come through the environment, are used once and are never written anywhere.
func (a *Agent) cmdPushInstall(ctx context.Context, c *cmdCtx) (any, error) {
	if runtime.GOOS != "windows" {
		return nil, errors.New("remote install needs a Windows PC on that network as the helper")
	}
	var args struct {
		Host, User, Password, Server, Token string
	}
	if err := decode(c.args, &args); err != nil {
		return nil, err
	}
	if !hostRe.MatchString(args.Host) || args.User == "" || args.Password == "" || args.Token == "" || !strings.HasPrefix(args.Server, "https://") && !strings.HasPrefix(args.Server, "http://") {
		return nil, errors.New("host, user, password, server and token are required")
	}
	if net.ParseIP(args.Host) != nil && !net.ParseIP(args.Host).IsPrivate() {
		return nil, errors.New("only private addresses can be installed to")
	}
	var result string
	res, err := a.runScript(ctx, scriptOpts{shell: "powershell", script: scriptPushInstall, internal: true, timeout: 20 * time.Minute,
		env: map[string]string{"HELM_A_HOST": args.Host, "HELM_A_USER": args.User, "HELM_A_PW": args.Password,
			"HELM_A_SERVER": strings.TrimRight(args.Server, "/"), "HELM_A_TOKEN": args.Token},
		onLine: func(ln string) {
			switch {
			case strings.HasPrefix(ln, "PROGRESS:"):
				m := strings.TrimPrefix(ln, "PROGRESS:")
				if p, rest, ok := strings.Cut(m, ":"); ok {
					if n, e := atoiPct(p); e {
						c.pct(n, rest)
						return
					}
				}
				c.progress(m)
			case strings.HasPrefix(ln, "RESULT:"):
				result = strings.TrimPrefix(ln, "RESULT:")
			}
		}})
	if err != nil {
		return nil, scrub(err, args.Password)
	}
	if result == "" {
		msg := strings.TrimSpace(res.Stderr)
		if msg == "" {
			msg = "the remote install did not report a result"
		}
		return nil, scrub(errors.New(firstLines(msg, 300)), args.Password)
	}
	return map[string]string{"result": result}, nil
}

func atoiPct(s string) (int, bool) {
	n := 0
	if s == "" || len(s) > 3 {
		return 0, false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return 0, false
		}
		n = n*10 + int(r-'0')
	}
	return n, n <= 100
}

func scrub(err error, secret string) error {
	if secret == "" {
		return err
	}
	return errors.New(strings.ReplaceAll(err.Error(), secret, "•••"))
}
