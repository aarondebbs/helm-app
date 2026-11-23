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
