# Helm

Manage Windows PCs from anywhere: a small background agent (installed with an MSI) plus a web console
that runs on your Raspberry Pi and is published with Tailscale Funnel.

* **Agent** (`helm-agent.exe`, Go, no dependencies) – Windows service running as SYSTEM, dials *out* to your server.
  No inbound ports, no firewall changes on the PCs.
* **Server** (`helm-server`, Go, no dependencies) – one binary + a JSON state file. Serves the website and relays
  screen / terminal / file / RDP traffic between your browser and the PCs.
* **Console** – sign in with password **and** authenticator code. Dangerous actions (power, scripts, updates, files,
  remote screen, terminal) additionally need a code from the last 10 minutes.

## What you can do

Inventory & live CPU/RAM/disk · Windows Update (check/install, optional restart) · winget app upgrades ·
restart / shut down / lock / sleep / hibernate / sign out · PowerShell/cmd terminal · file browser, upload, download ·
processes (end) · services (start/stop/restart/startup type) · event logs · pop-up message to the user ·
remote screen **in the browser** (works on Home and Pro, sees the sign-in screen) · RDP **tunnel** for a native client
(Pro/Enterprise only) · Wake-on-LAN via another PC on the same LAN · bulk actions · audit log · agent self-update (signed).

## Install from GitHub

Every release at <https://github.com/aarondebbs/helm-app/releases> carries the server for Windows and Linux, the agents and
installers, a signed `helm-release.json`, and a release log (what changed). You pick the version.

### Windows Server (2016 or newer) or Windows 10/11

Open **PowerShell as Administrator**:

```powershell
Invoke-WebRequest https://github.com/aarondebbs/helm-app/releases/latest/download/Install-HelmServer.ps1 -OutFile Install-HelmServer.ps1
powershell -ExecutionPolicy Bypass -File .\Install-HelmServer.ps1
```

The script lists the releases with their dates and a line of the release log, you type the number of the version you want
(Enter = newest), and it then:

1. downloads that version's `helm-server-windows-<amd64|arm64>.exe` and checks it against the release checksum,
2. installs it to `C:\Program Files\Helm`, keeps data in `C:\ProgramData\Helm`, locked to Administrators and the service,
3. creates the **HelmServer** Windows service (starts at boot, restarts itself if it stops),
4. asks you for an administrator password and prints the authenticator key to add to your app,
5. starts the server on `http://127.0.0.1:8787`.

Options: `-Version v0.13.3` (exact version) · `-Version latest` · `-List` (just show versions) · `-Listen 0.0.0.0:8787`
(also opens the firewall) · `-Repo owner/name` (your own fork) · `-IncludePrerelease` · `-Uninstall` (`-PurgeData` deletes data too).
Run it again any time to switch version; your data stays.

To publish it on the internet over HTTPS, install Tailscale on the server and run `tailscale funnel --bg 8787`.

### Raspberry Pi / Linux

```bash
sudo mkdir -p /opt/helm /var/lib/helm
# pick a version: https://github.com/aarondebbs/helm-app/releases  (replace v0.13.3 and arm64/amd64 as needed)
sudo curl -fL -o /opt/helm/helm-server https://github.com/aarondebbs/helm-app/releases/download/v0.13.3/helm-server-linux-arm64
sudo chmod 0755 /opt/helm/helm-server && sudo ln -sf /opt/helm/helm-server /usr/local/bin/helm-server
sudo curl -fL -o /etc/systemd/system/helm-server.service https://raw.githubusercontent.com/aarondebbs/helm-app/main/deploy/helm-server.service
sudo useradd --system --home /var/lib/helm --shell /usr/sbin/nologin helm; sudo chown -R helm:helm /opt/helm /var/lib/helm
sudo -u helm helm-server init-admin -data /var/lib/helm     # creates the admin and shows the authenticator key
sudo systemctl daemon-reload && sudo systemctl enable --now helm-server
```

### Updates and choosing a version later

In the console open **Settings, Updates**. Enter the repository (`aarondebbs/helm-app` is filled in by the Windows installer),
then open **Versions and release logs**: every release is listed with its log, and each has **Install** (newer) or
**Roll back to this** (older). A backup is taken first, the file is verified against the release signature, and the server
restarts by itself (PCs reconnect within seconds). PCs follow with their own signed self-update.

Rolling back is safe for the program but an older version may not understand data a newer one saved; restore the
automatic backup (Settings, Backups) if something looks wrong.

### Publishing your own releases

Fork the repository, add the contents of `keys/release.key` as the repository secret `HELM_RELEASE_KEY` (create one with
`go run ./cmd/helm-sign keygen -out keys/release.key`; keep it private), then run **Actions, release** with a tag such as
`v0.10.1`, or push that tag. The workflow tests, builds everything, writes the release log from your commit messages since the
previous tag, and publishes the release. Use your own `owner/name` for `-Repo` and in Settings.

**Not yet verified on real machines:** the Windows Server service and `Install-HelmServer.ps1` were built and unit-tested but
not run on a Windows Server. Try it on a test machine first and report anything odd.

## Build

Needs Go ≥ 1.24, `wixl`/`msibuild` (package `msitools`) for the MSI.

```
./build.sh            # version from ./VERSION
```

Produces `out/`:

| path | what |
|---|---|
| `out/helm-server-linux-arm64` | server for the Pi (`-amd64` also built) |
| `out/server-data/dist/Helm-Agent.msi` | the installer (served at `/dl/Helm-Agent.msi`) |
| `out/server-data/releases/windows-*/` | signed binaries for agent self-update |
| `out/agent/*.exe` | raw agents |
| `keys/release.key` | **update-signing key. Keep private, back it up.** Created on first build. |

The matching public key is compiled into every agent. If you lose the key you must re-install the MSI on every PC;
if someone steals it they can push code to every PC.

## Fleet management & security (web console)

* **Dashboard** – fleet health, average security score, open alerts, recent activity. **Devices** – cards/list, search (press `/`),
  groups and tags, bulk actions.
* **Vulnerability scanner** – per PC: installed software matched against NVD CVEs (CISA KEV-flagged ones are marked actively
  exploited), pending Windows patches, security-configuration audit (firewall, Defender, UAC, BitLocker, SMBv1, RDP/NLA…),
  and listening ports. Results are scored 0–100. CVE matches are *potentially affected* (version-range matching, no exploit
  verification). The Pi downloads NVD data and caches it for 7 days; a free NVD API key in Settings speeds the first fill.
* **Alerts** – offline PCs, low disk, new critical/KEV findings, etc., with optional **Telegram** notifications (bot token + chat id in Settings).
* **Automation** – script library, schedules (interval/daily/weekly; all PCs, a group, a tag or chosen PCs), run history.
* **Software** – catalog and fleet-wide inventory; deploy via winget or an uploaded .msi/.exe (SHA-256 verified by the agent).
* **Sessions** – history of screen/terminal/file/RDP sessions (metadata only; no video recording). **Reports** – CSV exports and a printable summary.

## Linux agent (Debian, Ubuntu, Raspberry Pi OS)

In the console open **Add a PC**, create a token and run the shown Linux command on the machine, e.g.
`curl -fsSL https://<your-helm>/dl/install-linux.sh | sudo bash -s -- --server https://<your-helm> --token <token>`.
Alternatively install `helm-agent-linux-<arch>.deb` (from `/dl/`) and run
`sudo helm-agent configure --server https://<your-helm> --token <token> && sudo systemctl enable --now helm-agent`.
The agent runs as a systemd service (root), self-updates (signed) and appears under Devices for approval.
Supported: inventory, processes, systemd services, journal logs, apt updates, terminal, files, power, messages (`wall`),
script runs (bash), security scan (dpkg software vs CVEs, listening ports, ~10 hardening checks, pending apt updates),
and software deployment (apt package names or uploaded `.deb`). Not available on Linux: remote screen, RDP tunnel, winget.
CVE matching uses upstream versions of Debian packages; distributions backport fixes, so results are "potentially affected"
and noisier than on Windows. Uninstall from the console (*Tools → Uninstall agent*) or `sudo apt purge helm-agent`.

## Install the server (Raspberry Pi, 64-bit OS)

```
scp -r out deploy pi@raspberrypi:~/helm && ssh pi@raspberrypi
cd ~/helm && sudo ./deploy/install-server.sh
sudo -u helm /usr/local/bin/helm-server init-admin -data /var/lib/helm   # password + prints the 2FA setup key
sudo systemctl enable --now helm-server
sudo tailscale funnel --bg 8787                                          # https://<pi>.<tailnet>.ts.net
```

The server listens on `127.0.0.1:8787` only; Funnel provides HTTPS. Open the Funnel URL, sign in.
Forgot something? `helm-server reset-password -data …` / `reset-2fa -data …` (needs shell access to the Pi).

## Add a PC

Console → **Add a PC** → *Create install command*, then on the PC in an **elevated** prompt:

```
msiexec /i https://<pi>.<tailnet>.ts.net/dl/Helm-Agent.msi /qn SERVER=https://<pi>.<tailnet>.ts.net TOKEN=hlm_…
```

(or copy `Helm-Agent.msi` there first). Optional `CONSENT=prompt_if_present|always_prompt|unattended`.
The PC appears as **Pending approval**; approve it in the console. The token is deleted from the PC after use.

Remote-screen consent (default `prompt_if_present`): if someone is signed in they get an Allow/Deny prompt and a banner
while you are connected; at the sign-in screen / nobody signed in it connects directly. Terminal and file access
do **not** prompt – they are admin functions that run as SYSTEM.

## Updates (cloud, via GitHub Releases)

Helm 0.4.0 can update itself and the agents from a GitHub repository you own.

**One-time setup**
1. Create a GitHub repo and push this source. Add the repository secret `HELM_RELEASE_KEY` (contents of `keys/release.key`, the ed25519 private key).
2. Install the 0.4.0 server once by hand (a 0.3.x server has no release public key compiled in, so it cannot verify cloud updates). Build it with `./build.sh` so the public key is embedded.
3. In the console: *Settings -> Updates*, enter `owner/repo`.

**Releasing**: bump `VERSION`, commit, tag `vX.Y.Z`, push the tag. `.github/workflows/release.yml` builds everything (including the macOS .pkg on a macOS runner), signs `helm-release.json` and publishes the release.

**Applying**: *Settings -> Updates -> Check now*, then *Update PCs now* (agents verify signature and SHA-256 before swapping) and *Update this server* (Linux only; verifies, keeps `.prev`, restarts the service). Agent roll-out can be automatic (toggle). Every file is checked against an ed25519 signature before use; nothing unsigned is installed.

**Without GitHub**: bump `VERSION`, run `./build.sh`, copy `out/server-data/.` over `/var/lib/helm/`.

## Backups and health

Settings, Backups and health shows disk space, memory, uptime and the state of the data files. The server makes a
backup every day (kept for 14 days) and you can create, download and restore backups from the same page. A restore
asks for a fresh authenticator code. `GET /healthz` answers `{"status":"ok"}` without signing in and returns 503 when
the data folder cannot be written, so an uptime monitor can watch the Pi.

## Sign in with Google (optional)

1. In the Google Cloud console create a project, open APIs & Services, OAuth consent screen, choose External and add
   your Gmail address as a test user.
2. Credentials, Create credentials, OAuth client ID, type Web application. Add the redirect address shown in
   Settings, Sign-in as an authorized redirect URI. It must match the address you open the console on (for example
   your Tailscale Funnel host) exactly.
3. Paste the client ID and secret into Settings, Sign-in, enter your Gmail address and save.

Only that one address can sign in. Sensitive changes still ask for the authenticator code.

## Patch window

Settings, Updates, Patch window installs pending updates by itself on online PCs: pick the days, start time and length,
and whether to allow restarts or limit it to security updates. PCs are patched one at a time, at most once a day each,
and results appear in the activity log. Times use the server's local time.

## Alerts by e-mail and Telegram

Settings → Alerts and notifications has an **E-mail** panel next to Telegram. Enter your SMTP server (STARTTLS on 587 or
TLS on 465; plain port 25 works only without a password), a From address and up to 10 recipients, then press *Send test
e-mail*. Passwords are only sent over an encrypted connection. A new **Restart pending** rule raises an alert when a PC is
waiting for a restart, and the PC's Overview shows a banner with a *Restart in 1 minute* button.

On the Remote screen tab you can drag a file onto the picture to send it to the PC (default: the shared Public Desktop).

## Chat with the person at a PC

Open **Inbox** (or a PC's **Chat** tab) and write to a PC. The person at the PC sees it at once and replies from the same
window; the reply comes back to your Inbox, and you get a Telegram or e-mail alert if you have those on (rule *New chat
message*). Messages are kept for 30 days. Your messages show *delivered* and then *seen* once the person has opened the chat; the Windows tray tooltip shows how many are unread. Chat follows the *Request support* setting of the install profile.

- **Windows:** a small native window opens by itself (the tray menu also has *Chat with support*). It flashes in the
  taskbar when a message arrives while it is in the background.
- **Linux and macOS:** the agent finds the user signed in at the screen, shows a desktop notification and opens the chat
  as a small app-style window in their session (Chrome, Chromium, Edge or Brave if installed, otherwise the default
  browser). Run `helm-agent chat` to open it by hand. Notifications use `notify-send` on Linux and the system banner on
  macOS. Nothing opens when nobody is signed in at a screen.

## A new console

The console was redesigned: **Home** lists what needs you (urgent alerts, PCs awaiting approval, unread chats) with the fix
beside each item, **PCs** is a dense list that expands in place, the PC page puts Overview, Remote screen, Files and Chat
first, and on a phone there is a bottom bar (Home, PCs, Inbox, Alerts, More).

## Updates on each operating system

The Updates tab only offers what exists on that PC. Windows: Windows Update and winget. Linux: apt or dnf system updates
(no app updater). macOS: Apple's `softwareupdate` for system updates and Homebrew for apps (needs Homebrew installed;
casks that ask for an administrator password may fail). *Fix* on a vulnerability finding upgrades the package with the
matching tool on that OS, and says so plainly when no fix is available. Scheduled jobs skip PCs they do not apply to.

## One-click fixes

On the Security page, configuration findings that have a safe fix show a Fix button (Windows firewall, Defender
real-time protection, SMBv1, UAC, Guest account, Gatekeeper, automatic updates, time sync, unattended-upgrades). The
console only sends the name of the check. The agent maps it to a fixed command and refuses anything else. Nothing that
could lock you out of a remote server (SSH settings, disk encryption) is offered.

## Remote screen: monitors, clipboard, adaptive speed

With several monitors a picker lets you choose which one to watch and control. Send my clipboard and Get PC clipboard
move plain text between your browser and the PC. The frame rate and quality you choose are ceilings: Helm lowers them by
itself while the connection is slow and raises them again when it recovers. These features run only on Windows and have
not yet been tried on real hardware; see docs/WINDOWS-TEST-CHECKLIST.md.

Since 0.11.0 the viewer acknowledges every frame it draws, and the PC never has more than two frames in flight, so a slow
link can no longer build up a queue of stale frames. Helm now measures the real round trip to your browser (not the local
socket) to pick the frame rate and quality. Text and flat areas are sent as compact palette PNG, photos and video as JPEG,
the screen is captured right after a click or key press, and it sharpens by itself once the picture stops changing. Older
browser tabs that do not acknowledge frames keep working, unthrottled. Capture reuses one bitmap, only changed tiles are copied and compressed, and capturing the next frame overlaps compressing
and sending the last one, so up to 60 fps is possible for ordinary desktop use. Full-screen video is limited by the
PC's CPU and the link. Two-way chat with the person at the PC is not built yet.

## Accepting risks

On the Security page, Accept risk keeps a finding listed but stops it lowering the score or raising alerts, for things
you cannot fix. Findings for programs whose vendor publishes no update are marked "no update published".

## When the authenticator code is asked for

Routine actions (installing updates, one-click fixes, restarts, service and process control, approving a PC, settings,
patch window) never ask for the code. Critical ones do, then stay unlocked for 30 minutes: running commands and
scripts, the terminal, the remote screen, file transfer and deleting, RDP tunnels, removing a PC or the agent,
backups, updating this server, and the sign-in and account settings.

## Inventory
Hardware/OS inventory is collected from each online PC daily, stored on the server and shown on the device Overview (*Collect full inventory* refreshes). *Reports -> Hardware inventory* exports CSV.

## macOS agent (new, untested on real hardware)
See `docs/MACOS.md`. Add a PC -> macOS gives a personalised script or a .pkg plus `helm-enroll.conf`.

## Antivirus false positives
See `docs/ANTIVIRUS.md`.

## Dark mode
Toggle in the top bar; follows the system setting until you choose.

## RDP tunnel

*Tools → Open RDP tunnel* opens a single-use listener on the Pi (ports 33890-33899, default bind `127.0.0.1`).
To use it from your own machine either start the server with `-rdp-bind <Pi tailscale IP>` and point `mstsc` at
`<that IP>:<port>`, or `ssh -L 3389:127.0.0.1:<port> pi@pi` and connect to `localhost`. The agent only ever forwards to the
PC's own RDP port. Windows Home cannot host RDP – use the in-browser screen there.

## Security notes

* Only you use the website; PCs only authenticate with a per-device secret (stored hashed on the server).
* Login: PBKDF2 password (≥12 chars), TOTP with replay protection, lockouts, 30-minute idle / 12-hour absolute sessions,
  `HttpOnly`/`SameSite=Strict` cookie, CSRF token, strict CSP, same-origin checks on WebSockets.
* Everything an agent reports is treated as untrusted text by the UI.
* Funnel makes the login page reachable from the whole internet – use a long password and keep the authenticator safe.
  Everything else (state file, signing key) stays on your machines. Back up `/var/lib/helm/state.json` and `keys/`.
* The MSI is **unsigned**, so Windows SmartScreen may warn on download; `msiexec` from an elevated prompt is unaffected.
  Sign it with your own code-signing certificate if you distribute it widely.

## Limits you should know about

* Screen streaming goes PC → Pi → Funnel → browser. It is tuned for usability (JPEG tiles, quality/fps controls), not
  video; for a fast session use the RDP tunnel. Tailscale Funnel has bandwidth limits.
* Remote screen shows the **console session** only (not other RDP sessions); Ctrl+Alt+Del requires the
  *SoftwareSASGeneration* policy on the PC.
* The terminal is a plain pipe shell (no PTY): no full-screen/interactive programs.
* winget runs as SYSTEM, so per-user app installs are not seen; some packages refuse to upgrade as SYSTEM.
* Scanner CVE data and Telegram need internet access from the Pi; matches are advisory, not proof of exploitability.
* The MSI contains the x64 agent; on Windows-on-ARM it runs under emulation. Native arm64 binaries are published for
  self-update only if you install them manually (`out/agent/helm-agent-windows-arm64.exe`).

See `docs/WINDOWS-TEST-CHECKLIST.md` – the Windows-specific code could not be executed in the build environment and
**must be tried on one real PC (and a VM snapshot) before you roll it out.**

## Activity

The Activity page shows a **Running now** panel (progress bar, percentage and current stage for each task, refreshed every 2 seconds), the last 7 days of finished tasks with their key stages, and the audit log. Percentages are reported for package/installer downloads, Windows updates and security scans; other tasks show stages only.

## Console users

The first administrator is the **owner**. In *My account* the owner can add more users: an **admin** (full access) or a **viewer** (can look, but cannot change anything, open a remote screen or terminal, or see enrollment tokens, settings and backups). Each user has their own password and authenticator. Adding a user shows their authenticator key once; removing a user signs them out immediately. Google sign-in still maps to the owner account.

## Authenticator in a password manager

When you turn on two-step verification, Helm shows the QR code, the **key** and a **setup link**. To keep the code in 1Password, Bitwarden, Proton Pass or Apple Passwords, copy the key (or the link) into the one-time-password field of a Helm login item.

## Wake-on-LAN

*Wake it* on an offline PC sends the magic packet from another online PC on the same network; if there is none, the server sends it itself (this only works when the server is on that network). The PC needs Wake-on-LAN enabled in its BIOS and network adapter, and Helm must have seen its MAC address while it was online.

## Network scan and remote install

*Network* scans a /24 (up to /22) from any online PC or from the server and lists the devices that answer, with name, MAC, open ports and whether they already run Helm. For a Windows PC you can choose **Install Helm…**: a helper Windows PC on the same network connects over PowerShell remoting with an administrator account you type (used once, never stored), downloads the MSI and installs it. The new PC then waits for your approval under Devices. This needs remote PowerShell on the target (`Enable-PSRemoting -Force` in an administrator PowerShell); for a PC in a workgroup that uses a local account, Windows may also need `LocalAccountTokenFilterPolicy=1`. Linux and macOS PCs are installed from *Add a PC*.

## Install as an app (PWA)

Open the console in Safari, Chrome or Edge and choose *Add to Home Screen* / *Install*. The app shell opens offline; data always comes from the server.

## Customize the installer, and the taskbar icon

On *Add a PC*, **Customize the installer** lets the person deploying choose, before downloading: the group and tags the PC joins, a name prefix, whether it must be approved in the portal (default) or is approved automatically, an organisation name, a support contact, and whether the taskbar icon and the *Request support* button appear. These settings belong to the enrollment token, so the same MSI template is used for everyone and nothing about the installer file changes; the PC applies them when it enrolls. A PC enrolled with manual approval shows as *Pending approval* in Devices and raises a "New PC waiting for approval" alert.

On Windows the agent shows a Helm icon in the notification area (it starts for each signed-in user, runs with that user's rights and stops when the service stops). Click it for a small menu: connection status, this PC's name, the support contact, *Request support* and *About* (there is deliberately no link to the portal). *Request support* creates a "Support requested" alert in the portal (at most one per minute). The icon reads a status file the service keeps in `C:\ProgramData\HelmPublic` that holds no secrets.

## Security notes (0.9.1)

A penetration test of a private test instance covered login, sessions, 2FA, roles, injection, file paths, the agent channel and request limits. Hardening from it:

- Lockout buckets are per account name, so one person's failed attempts cannot lock out another.
- Each TOTP code can be used once, even when two requests arrive at the same moment.
- Data sent by agents (host name, MACs, IPs, errors, progress) is cleaned and size-limited.
- Agents that are not yet approved cannot raise support requests.
- Slow request bodies are cut off after 30 seconds.
- Extra headers: Permissions-Policy, COOP, CORP.

Run Helm behind Tailscale ACLs or an allow-list where you can, and keep admin accounts on 2FA. Admins can run commands on enrolled PCs by design.
