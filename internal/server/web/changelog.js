'use strict';
/* Helm console: What's new. Newest first. Each entry lists what is New, Improved or Fixed in plain words. */
const CHANGELOG = [
  { v: '1.0.5', date: '2026-11-25', title: 'Set up components now works on up-to-date agents', fixed: [
    'Set up components and the automatic install when a plan is assigned failed with unknown command on agents that were fully up to date. The agent did not know the command. It does now.',
  ] },
  { v: '1.0.4', date: '2026-11-25', title: 'Change logs in the console, hourly update checks', new: [
    'Settings → Updates → Versions and release logs now shows the real change log of every version, not a link.',
  ], better: [
    'Helm checks for new versions every hour instead of every six.',
    'The sign-in page no longer fills in admin as the username.',
  ] },
  { v: '1.0.3', date: '2026-11-25', title: 'Older agents no longer show an error', fixed: [
    'PCs still running an agent from before 1.0.1 no longer fail with unknown command module.install. Helm carries on with the antivirus update, and Set up components tells you to update that PC first.',
  ] },
  { v: '1.0.2', date: '2026-11-25', title: 'A proper About and Updates section', new: [
    'Settings → Updates now opens with the Helm logo and the exact version this server runs, like winver.',
  ], better: [
    'The GitHub repository field is gone. Every Helm updates from the same place, so it is no longer asked for.',
  ] },
  { v: '1.0.1', date: '2026-11-25', title: 'Plans install what they need, clearer activity, separate tabs', new: [
    'Choosing a plan now installs the parts it needs on the PC: ClamAV on Linux, a firewall tool for isolation, a Defender check on Windows. Then it fetches the first definitions. Use Set up components to retry.',
    'Activity is now a readable feed: plain sentences, grouped by day, with filters and a search. Click an entry for the exact time, address and technical detail.',
    'Terminal and Remote screen open in their own browser tab.',
    'Each PC shows its maker and model (Dell, Lenovo, Raspberry Pi, Apple and so on) next to its picture.',
  ], fixed: [
    'Clicking inside a PC\'s side pane no longer reloads the page.',
  ] },
  { v: '1.0.0', date: '2026-11-25', title: 'Helm 1.0 (prerelease): one agent, three modules', new: [
    'Plans: every PC can run RMM, Antivirus, EDR, or any mix. The agent only connects the PC; you choose what it gets, and can change it any time under Plan & modules.',
    'Onboarding: a PC that connects waits for you to pick its plan, name, group and tags. Installers are made for one PC and stop working after 30 minutes or the first use.',
    'Antivirus: scans, threat history and an Antivirus page showing the engine version of every PC. Helm tells every PC to fetch fresh definitions at least every 24 hours and flags any that fall behind.',
    'EDR: process, network and start-up telemetry with flags for suspicious programs, and one-click network isolation that releases itself.',
    'PC details open in a side pane with a section menu instead of tabs across the top.',
    'Sign-in shows progress and a short welcome. Google sign-in has a guided setup that reads Google\'s downloaded client file.',
    'Profiles: full name, email and job title for every console user.'],
    better: ['The side menu follows your accent colour.', 'Adding a PC is now Download agent: pick Windows, Linux or macOS and the installer downloads at once. PCs join only by installing it.'],
    fixed: ['Linux and macOS PCs: the file browser now uses / paths and opens the root folder correctly.'] },
  { v: '0.15.0', title: 'Make the console yours', new: [
    'Settings, Appearance: choose light, dark or follow the system, pick an accent colour from six tested palettes, and switch between comfortable and compact density.',
    'Settings, Branding: your own name and logo on the sign-in page and at the top of the menu.'],
    better: ['The console starts after all its scripts have loaded, which avoids a rare blank first screen.'], fixed: [] },
  { v: '0.14.0', date: '2026-11-25', title: 'A new sign-in, a rebuilt PC list, branded installers', new: [
    'Sign in with Google from a clean, centred sign-in page.',
    'The PC list is rebuilt: rows or cards, live CPU and memory that move smoothly, filter chips, grouping and bulk actions.',
    'Each PC gets a picture of what it is: Raspberry Pi, laptop, desktop, server or virtual machine, detected by the agent.',
    'Installers can carry your logo and brand colour, with a live preview of the chat window on the PC, next to company name, support text, group, tags and naming pattern.',
    'This What\'s new page, and a short summary after each update.'],
    better: ['Smoother page changes across the console.'], fixed: [] },
  { v: '0.13.3', date: '2026-11-25', title: 'Home fix', new: [], better: [], fixed: ['Home no longer keeps loading when there are no chats yet.'] },
  { v: '0.13.2', date: '2026-11-25', title: 'Chat receipts', new: ['Your chat messages show "seen" once the person at the PC has opened them.'], better: ['The Windows tray tooltip shows how many messages are unread.'], fixed: [] },
  { v: '0.13.1', date: '2026-11-25', title: 'Native chat window', new: [
    'Windows: the chat with support is now a native window that flashes in the taskbar when you write.',
    'Linux and macOS: a desktop notification and a small chat window open in the signed-in user\'s session.',
    'The command helm-agent chat opens the chat by hand on any system.'], better: [], fixed: [] },
  { v: '0.13.0', title: 'Chat and a new console', new: [
    'Chat with the person at a PC, from an Inbox for every PC or from each PC\'s Chat tab. Messages are kept for 30 days.',
    'Telegram and e-mail alert when someone writes to you.'], better: [
    'The console was redesigned from scratch, with a phone layout and a bottom tab bar.',
    'Home now answers one question: what needs you right now.'], fixed: [] },
  { v: '0.12.0', title: 'E-mail alerts and file drop', new: [
    'E-mail (SMTP) alerts next to Telegram.',
    'A banner and an alert when a PC needs a restart.',
    'Drop a file onto the remote screen to send it to the PC.'], better: [], fixed: [] },
  { v: '0.11.0', title: 'Remote screen and per-system updates', new: [
    'Remote screen: smoother video with flow control and sharper PNG tiles.',
    'Updates and software now follow the PC\'s system: Windows Update and winget on Windows, the package manager on Linux, Homebrew on macOS.',
    'Linux and macOS vulnerability checks and patching.'], better: [
    'The tray menu no longer says "Open Helm portal".',
    'The console matches the sign-in look.'], fixed: ['Operating system names show correctly in the PC list.'] },
];

const seenKey = 'helm-seen-version';
const unseenVersion = () => { try { return !!S.version && localStorage.getItem(seenKey) !== S.version; } catch (e) { return false; } };
const markSeen = () => { try { if (S.version) localStorage.setItem(seenKey, S.version); } catch (e) { /* private mode */ } const d = $('#verdot'); if (d) d.remove(); };

function changeBlock(entry, tag) {
  const part = (cls, label, items) => items && items.length ? h('div', { class: 'chg ' + cls }, h('h4', null, label), h('ul', null, items.map(t => h('li', null, t)))) : null;
  return h('article', { class: 'release' },
    h('header', null, h(tag || 'h2', null, entry.title), h('span', { class: 'rel-meta' }, 'Version ' + entry.v + (entry.date ? ' · ' + new Date(entry.date + 'T12:00').toLocaleDateString([], { day: 'numeric', month: 'long', year: 'numeric' }) : ''))),
    part('new', 'New', entry.new), part('better', 'Improved', entry.better), part('fixed', 'Fixed', entry.fixed));
}

route(/^\/whatsnew$/, () => {
  shell('whatsnew', [h('div', { class: 'pagehead' }, h('h1', null, 'What\'s new')), h('div', { class: 'releases' }, CHANGELOG.map(e => changeBlock(e)))]);
  markSeen();
});

// Shown once after the console updates to a new version.
async function maybeShowWhatsNew() {
  if (!unseenVersion()) return;
  const e = CHANGELOG.find(x => x.v === S.version);
  let had = false; try { had = !!localStorage.getItem(seenKey); } catch (x) { /* ignore */ }
  if (!e || !had) { markSeen(); return; } // a first visit gets no popup
  markSeen();
  const r = await modal('Helm was updated', changeBlock(e, 'h3'), [{ label: 'Close', value: null }, { label: 'See everything', value: true, cls: 'primary' }], { wide: true });
  if (r) location.hash = '#/whatsnew';
}
