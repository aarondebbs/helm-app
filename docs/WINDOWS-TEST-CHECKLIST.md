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

## Remote screen additions (0.6.0): never run on a real PC yet

- [ ] One monitor: the picker is hidden, the screen looks and behaves exactly as before.
- [ ] Two or more monitors: the picker appears; switching shows the other monitor and the mouse lands on the right spot on it (including a monitor placed left of or above the main one).
- [ ] Unplug or plug in a monitor during a session: the picker updates within a few seconds and the session survives.
- [ ] Send my clipboard: copy text in the browser, press the button, paste on the PC (try accented letters and emoji).
- [ ] Get PC clipboard: copy text on the PC, press the button, paste in the browser. If the browser blocks copying, a box with the text appears.
- [ ] View only: clipboard buttons do nothing, the monitor picker still works.
- [ ] Throttle the connection (or use a slow link): the picture gets coarser and the frame rate drops instead of lagging, then recovers when the link does.

## Fixes and patching (0.5.x)

- [ ] Security page: Fix on the firewall finding turns the firewall on; the finding is gone after the rescan.
- [ ] Update vulnerable software: a program with a newer winget version updates and the rescan shows the CVEs gone; a program winget does not know gives the "no newer version" message and the "no update published" badge.
- [ ] Patch window: set a window a few minutes ahead, watch the PC install updates, then check the activity log.

## Smoother remote screen (0.6.2): never run on a real PC yet

- [ ] Choose "Up to 60 fps": moving a window, typing and scrolling look fluid and the picture stays sharp when still.
- [ ] Drag a window quickly or play a video: the quality drops a little but the frame rate holds; it sharpens again when things stop moving.
- [ ] Mouse pointer follows your hand without trailing (the browser now sends pointer moves about 70 times a second).
- [ ] Half size and Low quality are still available and clearly faster on a slow link.
- [ ] Leave a session open for 30 minutes at 60 fps: no memory growth in `helm-agent.exe` (Task Manager) and no stutter.
- [ ] Switching monitors, changing resolution and the sign-in screen (Ctrl+Alt+Del) still work.

## 0.8.0

- [ ] Wake-on-LAN: shut down a PC, press *Wake it* from a PC on the same network; then with no helper PC online (server on the same network).
- [ ] Network scan from a PC and from the server; the hosts match your router's list.
- [ ] *Install Helm…* on a second Windows PC with remote PowerShell enabled; the PC appears for approval. Try a wrong password (clear error, nothing stored).
- [ ] Add a viewer user; confirm they cannot change anything, open a remote screen, or see tokens.
- [ ] Save the authenticator key in a password manager and sign in with its code.
- [ ] Install the console as an app on iPhone and Android; open it offline.

## 0.9.0

- [ ] Install an MSI created with *Customize the installer* (group, tags, prefix, org, support text): the PC appears with them; with manual approval it waits, with automatic approval it goes online.
- [ ] The Helm icon appears in the taskbar notification area within ~30 s of install and after sign-in; left and right click both open the menu.
- [ ] Menu shows org, status, this PC, support text; there is no *Open Helm portal* item; *Request support* raises an alert in the portal.
- [ ] Icon turns amber while pending/connecting and grey when offline; disappears when *Show the Helm icon* is off.
- [ ] Switch users (Fast User Switching): each user gets their own icon. Restart Explorer: the icon comes back.
- [ ] Upgrade and uninstall the MSI: no "files in use" prompt and no reboot request (the service stops the icons first).

## 0.11.0

- [ ] Remote screen over a slow or remote link: no growing lag, the Stats line shows round trip and frames in flight (max 2); typing and clicking feel immediate.
- [ ] Text areas look crisp after ~0.3 s of stillness; scrolling a page stays smooth.
- [ ] An open old browser tab (before upgrading the server) still shows the screen.
- [ ] Taskbar menu has no *Open Helm portal*.
- [ ] Updates tab on Windows shows Windows Update and Apps (winget); on Linux only System updates.

## 0.12.0

- [ ] Drag a file onto the remote screen: it appears in the chosen folder on the PC; a second drop of the same name asks before overwriting.
- [ ] A PC with a pending restart shows the banner on Overview and a *Restart pending* alert.
