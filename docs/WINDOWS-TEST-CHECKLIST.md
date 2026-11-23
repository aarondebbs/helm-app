# First-run checklist (do this on a Windows 10/11 VM with a snapshot)

The agent's Windows-specific parts (service, session helper, screen capture/input, registry, PowerShell scripts, MSI)
were compiled and statically checked, but never run on Windows during development. Work through this list once.

## Install / uninstall
- [ ] `msiexec /i Helm-Agent.msi /qn SERVER=… TOKEN=…` (elevated) finishes without error; add `/l*v install.log` to get a log.
- [ ] Service **HelmAgent** exists, Automatic, running as LocalSystem, recovery = restart (`sc qfailure HelmAgent`).
- [ ] PC shows as *Pending approval*; after approval it shows Online with CPU/RAM/disk.
- [ ] `HKLM\SOFTWARE\Helm\Agent` has Server, ConsentMode (if given), ProductCode — and **no EnrollToken** after enrolment.
- [ ] `C:\ProgramData\Helm` exists and is only accessible to SYSTEM/Administrators. Logs are in there (`agent.log`).
- [ ] Reboot → agent comes back by itself. Kill `helm-agent.exe` in Task Manager → service restarts within seconds.
- [ ] Re-run the MSI with a higher version and **no** SERVER/TOKEN → upgrades, Server value is kept, still Online.
- [ ] Apps & features → uninstall: service, folder, registry key and `C:\ProgramData\Helm` are removed. Also try *Tools → Uninstall agent*.

## Features (Overview → each tab)
- [ ] Inventory, Processes (end a test notepad), Services (stop/start a harmless one), Event logs.
- [ ] Updates: *Check for Windows updates*, install one; *Check for app updates (winget)* on a PC with winget; upgrade one app.
- [ ] Power: *Lock*, *Restart in 30 s* then *Cancel pending*; message pop-up shows on the signed-in user's desktop.
- [ ] Files: browse, upload a file, download it, rename, delete; try deleting `C:\Windows` (must be refused).
- [ ] Terminal: PowerShell (`whoami` → `nt authority\system`), cmd.

## Remote screen (most important to verify)
- [ ] User signed in, consent *prompt_if_present*: Allow prompt appears on the user's screen; Deny → console shows refusal; Allow → picture, mouse, keyboard, scroll, typing of text and shortcuts (Ctrl+C etc.) work; the banner is visible and clicking it ends the session.
- [ ] Lock the PC / sign out: reconnect → you see the sign-in screen and can type the password of a local admin.
- [ ] *Ctrl+Alt+Del* button (needs policy `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\SoftwareSASGeneration = 1 or 3`).
- [ ] Try a high-DPI display and a two-monitor PC (only the primary is streamed).
- [ ] Windows Home PC: confirm everything above works (this is the Home substitute for RDP).

## RDP tunnel (Pro PC)
- [ ] *Tools* shows RDP status; Enable → status Enabled; Open tunnel → connect with mstsc through it; tunnel closes after use/expiry.

## Self-update
- [ ] Publish version 0.1.1 (`./build.sh 0.1.1`, copy `out/server-data/releases`), *Tools → Update agent now* → agent restarts and reports 0.1.1.

## Security scan, automation & deployment (new)
- [ ] *Security → Scan now* on one PC: software list, config checks, ports and patches all populate; compare a few config results with the PC's real settings.
- [ ] Run a script from *Automation* (e.g. `hostname`) on one PC; output and exit code appear in the run.
- [ ] Create a daily schedule, use *Run now*; confirm results per PC.
- [ ] *Software → Deploy* a winget package (e.g. 7zip.7zip) to a test PC; then uninstall it.
- [ ] Upload a small .msi, deploy it; a wrong hash must be rejected by the agent.
- [ ] Settings → Telegram *Send test* arrives; take a PC offline and confirm the alert + message.

## Linux agent (new, test on a Debian/Ubuntu/Raspberry Pi OS machine or VM)
- [ ] Run the install command from *Add a PC*; the machine appears (approve it); `systemctl status helm-agent` is active.
- [ ] Overview, Processes, Services (start/stop a harmless service), Logs, Terminal and Files work.
- [ ] *Updates → check* lists apt updates; installing one succeeds; *reboot-required* is reflected.
- [ ] *Security → Scan now*: ports, config checks (compare with `ufw status`, `sshd -T`) and software appear.
- [ ] Deploy an apt package (e.g. `htop`) and an uploaded `.deb`; remove the apt package again.
- [ ] *Tools → Update agent now* after publishing a newer version restarts the service on the new version.
- [ ] *Tools → Uninstall agent* removes the service, binary and `/etc/helm-agent`.

## 0.4.0 additions
- [ ] Settings -> Updates: with a published release, *Check now* shows the new version; *Update PCs now* upgrades a test PC; *Update this server* restarts and returns.
- [ ] Device Overview shows stored hardware inventory with "Collected ... ago"; Reports -> Hardware inventory downloads.
- [ ] Account -> 2FA: enable, confirm, disable, enable again.
- [ ] Dark mode toggle persists after reload.
- [ ] Linux/macOS: personalised script from Add a PC enrols the machine; macOS .pkg + `helm-enroll.conf` enrols.
- [ ] Install the MSI/exe on a PC with Defender/Bitdefender: no detection; note any in `docs/ANTIVIRUS.md`.
