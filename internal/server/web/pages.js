'use strict';
/* Helm console pages: dashboard, security, alerts, sessions, reports, settings. (Loaded after app.js.) */

// ---------- shared: vulnerability database status ----------
function cveNotice(cve) {
  if (!cve) return null;
  if (cve.lastError) return h('div', { class: 'notice warn' }, h('b', null, 'Vulnerability database: '), 'the last download failed (', cve.lastError, '). It will retry automatically. This server needs internet access to services.nvd.nist.gov.');
  if (cve.queue > 0) return h('div', { class: 'notice' }, h('span', { class: 'spinner' }), ' Downloading vulnerability data for ' + plural(cve.queue, 'product') + '. Without an NVD API key this is slow (about one request every 7 seconds), so results fill in over the next minutes. Add a free key in Settings to speed it up.');
  return null;
}

// ---------- dashboard ----------
// White-on-colour gauge for the status banner.
// Dashboard statement: one plain sentence about the fleet, plus the fleet map (one square per PC).
function fleetMap(devs) {
  const list = devs.filter(d => d.approved).sort((x, y) => ((x.security && x.security.hasData ? x.security.score : 101) - (y.security && y.security.hasData ? y.security.score : 101)));
  const cls = d => { const s = d.security; return !s || !s.hasData || s.score == null ? 'none' : s.score >= 80 ? 'good' : s.score >= 50 ? 'fair' : 'poor'; };
  const cells = list.map(d => {
    const s = d.security, has = s && s.hasData && s.score != null;
    return h('a', { class: 'cell ' + cls(d) + (d.online ? '' : ' off'), href: '#/d/' + d.id, title: d.name + ' · ' + (has ? 'score ' + s.score : 'not scanned') + ' · ' + (d.online ? 'online' : 'offline') }, has ? String(s.score) : '');
  });
  const key = (c, t, off) => h('span', null, h('i', { class: off ? 'off' : '', style: { '--c': c } }), t);
  return h('div', { class: 'fleet' },
    h('div', { class: 'count' }, list.length ? plural(list.length, 'PC') + ', lowest score first' : 'No PCs enrolled yet'),
    h('div', { class: 'cells' }, cells),
    list.length ? h('div', { class: 'key' }, key('var(--ok)', '80 or more'), key('var(--sev-m)', '50 to 79'), key('var(--bad)', 'Under 50'), key('var(--line3)', 'Not scanned'), key('var(--text2)', 'Offline', true)) : null);
}

function heroBanner(d, crit, high, devs) {
  let tone = 'info', title, text;
  if (!d.total) { title = 'No PCs yet.'; text = 'Create an enrollment token, install the agent on a PC, and this page shows how the fleet is doing.'; }
  else if (!d.scored) { title = 'Nothing has been scanned.'; text = 'Scans run automatically on online PCs. You can also start one now.'; }
  else if (crit || (d.avgScore != null && d.avgScore < 50)) { tone = 'bad'; title = crit ? plural(crit, 'critical issue') + ' to fix.' : 'The fleet is at risk.'; text = `${plural(d.buckets.poor, 'PC')} scored under 50. Average score ${d.avgScore}.`; }
  else if (high || d.alerts.length || (d.avgScore != null && d.avgScore < 80)) { tone = 'warn'; title = 'Some PCs need work.'; text = [high ? plural(high, 'high-severity finding') : '', d.alerts.length ? plural(d.alerts.length, 'open alert') : ''].filter(Boolean).join(' and ') + `. Average score ${d.avgScore}.`; }
  else { tone = 'ok'; title = 'The fleet is in good shape.'; text = `All ${plural(d.scored, 'scanned PC')} score 80 or more (average ${d.avgScore}). Scanning continues in the background.`; }
  return h('div', { class: 'statement ' + (tone === 'info' ? '' : tone) },
    h('div', null, h('h2', null, title), h('p', null, text),
      h('div', { class: 'acts' },
        d.total ? actionButton('Scan all PCs', async () => { const r = await api('POST', '/api/run/scan', { target: { all: true } }); toast('Scanning ' + plural(r.results.length, 'PC'), 'ok'); }, 'primary') : h('a', { class: 'btn primary', href: '#/enroll' }, icon('plus'), 'Add a PC'),
        d.scored ? h('a', { class: 'btn', href: '#/security' }, 'Review findings') : null)),
    fleetMap(devs || []));
}

function tile(ic, label, value, unit, note, tone, href) {
  return h('a', { class: 'tile ' + tone, href }, h('div', { class: 'ti' }, icon(ic)),
    h('div', null, h('div', { class: 'tl' }, label), h('div', { class: 'tv' }, value, unit ? h('small', null, unit) : null), h('div', { class: 'tn' }, note)));
}
route(/^\/$/, viewDashboard);
async function viewDashboard() {
  const host = h('div', null, h('span', { class: 'spinner' }));
  shell('dashboard', [pageHead('Dashboard', 'Fleet health and security at a glance'), host]);
  const my = routeToken;
  const draw = async () => {
    let d, devs = [];
    try { d = await api('GET', '/api/dashboard'); devs = await getDevices(true); } catch (e) { clear(host).append('Could not load: ' + e.message); return; }
    if (my !== routeToken) return;
    const crit = d.counts.critical, high = d.counts.high;
    const sevSegs = [{ label: 'Critical', v: d.counts.critical, color: 'var(--sev-c)' }, { label: 'High', v: d.counts.high, color: 'var(--sev-h)' },
      { label: 'Medium', v: d.counts.medium, color: 'var(--sev-m)' }, { label: 'Low', v: d.counts.low, color: 'var(--sev-l)' }];
    const sevTotal = sevSegs.reduce((a, s) => a + s.v, 0);
    const groups = Object.entries(d.groups).sort((a, b) => b[1] - a[1]);
    const oses = Object.entries(d.os).sort((a, b) => b[1] - a[1]);
    clear(host).append(
      d.pending ? h('div', { class: 'notice warn', style: { marginBottom: '16px' } }, h('b', null, plural(d.pending, 'PC') + ' waiting for approval. '), h('a', { href: '#/devices' }, 'Review')) : null,
      cveNotice(d.cve) ? h('div', { style: { marginBottom: '16px' } }, cveNotice(d.cve)) : null,
      heroBanner(d, crit, high, devs),
      h('div', { class: 'tiles' },
        tile('devices', 'Devices online', d.online + '', ' / ' + d.total, d.offline ? plural(d.offline, 'PC') + ' offline' : 'All reachable', d.total === 0 ? 'info' : d.offline ? (d.online ? 'warn' : 'bad') : 'ok', '#/devices'),
        tile('shield', 'Serious vulnerabilities', String(crit + high), '', `${crit} critical · ${high} high` + (d.scored < d.total ? ` · ${d.total - d.scored} not scanned` : ''), crit ? 'bad' : high ? 'warn' : d.scored ? 'ok' : 'info', '#/security'),
        tile('bell', 'Open alerts', String(d.alerts.length), '', d.alerts.length ? 'Need attention' : 'All clear', d.alerts.some(a => a.severity === 'critical') ? 'bad' : d.alerts.length ? 'warn' : 'ok', '#/alerts'),
        tile('disk', 'Low disk space', String(d.lowDisks.length), '', d.lowDisks.length ? 'Drives under 15% free' : 'Every drive has room', d.lowDisks.length ? 'warn' : 'ok', '#/devices'),
        tile('pulse', 'Fleet load', Math.round(d.avgCpu) + '%', ' CPU', Math.round(d.avgMem) + '% memory in use (online PCs)', d.avgCpu > 85 || d.avgMem > 90 ? 'warn' : 'info', '#/devices')),
      h('div', { class: 'grid two' },
        panel('Findings by severity', 'Across all scanned PCs', null,
          sevTotal ? h('div', { class: 'donutwrap' }, donut(sevSegs, String(sevTotal), 'findings'), legend(sevSegs)) : emptyState('✅', d.scored ? 'No findings' : 'Nothing scanned yet', d.scored ? 'Every scanned PC is clean.' : 'Scans run automatically, or use "Scan all PCs".'))),
      h('div', { class: 'grid two', style: { marginTop: '16px' } },
        panel('Open alerts', null, h('a', { href: '#/alerts' }, 'All alerts →'), d.alerts.length ? h('div', { class: 'stack', style: { gap: '4px' } }, d.alerts.map(a => h('div', { class: 'row', style: { padding: '8px 0', borderBottom: '1px solid var(--line)', flexWrap: 'nowrap' } },
          sevBadge(a.severity), h('div', null, h('div', null, a.title), h('div', { class: 'muted small-text' }, fmtAgo(a.opened)))))) : h('p', { class: 'muted' }, 'No open alerts.'))),
      h('div', { class: 'grid two', style: { marginTop: '16px' } },
        panel('Low disk space', 'Drives under 15% free', null, d.lowDisks.length ? h('div', { class: 'stack' }, d.lowDisks.map(x => h('a', { href: '#/d/' + x.id, style: { color: 'inherit' } }, h('div', { class: 'row spread small-text' }, h('span', null, x.name + ' · ' + x.drive), h('b', null, x.freePct + '% free')), barNode(100 - x.freePct)))) : h('p', { class: 'muted' }, 'All drives have plenty of space.')),
        panel('Fleet composition', null, null, h('div', { class: 'grid', style: { gridTemplateColumns: '1fr 1fr' } },
          h('div', null, h('h4', null, 'Groups'), groups.length ? hbars(groups.map(([k, v]) => ({ label: k, v }))) : h('p', { class: 'muted' }, 'No groups yet')),
          h('div', null, h('h4', null, 'Operating systems'), oses.length ? hbars(oses.map(([k, v]) => ({ label: k, v, color: 'var(--text2)' }))) : h('p', { class: 'muted' }, 'No data yet'))))),
      h('div', { style: { marginTop: '16px' } }, panel('Recent activity', 'Scripts, scans, updates and deployments', h('a', { href: '#/automation/runs' }, 'All runs →'),
        d.runs.length ? table(['When', 'Task', 'Trigger', 'Status'].map(x => ({ label: x })), d.runs.map(r => h('tr', { class: 'clickable', onclick: () => { location.hash = '#/automation/runs'; } },
          h('td', { class: 'nowrap' }, fmtAgo(r.started)), h('td', null, r.title), h('td', { class: 'muted' }, r.trigger), h('td', null, h('span', { class: 'badge ' + (r.status === 'done' ? 'done' : 'running') }, r.status))))) : h('p', { class: 'muted' }, 'Nothing has run yet.'))));
  };
  draw(); every(15000, draw);
}

// ---------- Google sign-in ----------
function googlePanel() {
  const box = h('div', { class: 'stack' }, h('span', { class: 'spinner' }));
  const draw = async () => {
    let g; try { g = await api('GET', '/api/settings/google'); } catch (e) { clear(box).append(h('div', { class: 'notice bad' }, e.message)); return; }
    const id = h('input', { type: 'text', value: g.clientId, autocomplete: 'off', spellcheck: 'false', placeholder: '123456789-abc.apps.googleusercontent.com' });
    const secret = h('input', { type: 'password', autocomplete: 'off', placeholder: g.secretSet ? '•••••••• (saved)' : 'Client secret' });
    const email = h('input', { type: 'email', value: g.email, autocomplete: 'off', placeholder: 'you@gmail.com' });
    clear(box).append(
      h('div', { class: g.enabled ? 'notice ok' : 'notice' }, g.enabled ? 'Google sign-in is on. The sign-in page shows a Google button.' : 'Google sign-in is off. Fill in the three fields below to turn it on.'),
      h('ol', { class: 'small-text', style: { margin: 0, paddingLeft: '20px', display: 'flex', flexDirection: 'column', gap: '4px' } },
        h('li', null, 'In the Google Cloud console, create a project and open APIs & Services, then OAuth consent screen. Choose External and add your Gmail address as a test user.'),
        h('li', null, 'Open Credentials, create an OAuth client ID of type Web application, and add the redirect address below as an authorized redirect URI.'),
        h('li', null, 'Paste the client ID and client secret here, enter the Gmail address that may sign in, and save.')),
      h('label', { class: 'field' }, h('span', null, 'Redirect address'), h('div', { class: 'row', style: { flexWrap: 'nowrap' } }, h('input', { type: 'text', readOnly: true, value: g.redirectUri, style: { flex: 1 } }), copyButton(() => g.redirectUri))),
      h('label', { class: 'field' }, h('span', null, 'Client ID'), id),
      h('label', { class: 'field' }, h('span', null, 'Client secret'), secret),
      h('label', { class: 'field' }, h('span', null, 'Google address that may sign in'), email, h('span', { class: 'hint' }, 'Only this account is let in. The password and authenticator code keep working as a fallback.')),
      h('div', { class: 'row' }, actionButton('Save', async () => { await api('PUT', '/api/settings/google', { clientId: id.value, clientSecret: secret.value, email: email.value }); toast('Google sign-in saved', 'ok'); draw(); }, 'primary'),
        g.clientId ? actionButton('Turn off and remove', async () => { if (await confirmDialog('Remove the Google sign-in settings?', 'Remove', true)) { await api('PUT', '/api/settings/google', { clear: true }); draw(); } }, 'danger') : null),
      h('p', { class: 'muted small-text' }, 'Signing in with Google replaces the password and code at the sign-in page. Sensitive changes (settings, backups, commands that need confirmation) still ask for your authenticator code.'));
  };
  draw();
  return panel('Google sign-in', 'Let your Google account open the console', null, box);
}

// ---------- patch window ----------
function patchWindowPanel() {
  const box = h('div', { class: 'stack' }, h('span', { class: 'spinner' }));
  const DAYS = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'];
  const draw = async () => {
    let w; try { w = await api('GET', '/api/patch-window'); } catch (e) { clear(box).append(h('div', { class: 'notice bad' }, e.message)); return; }
    const st = { enabled: w.enabled, days: new Set(w.days), startHour: w.startHour, hours: w.hours || 4, allowReboot: w.allowReboot, securityOnly: w.securityOnly, programs: w.programs };
    const dayRow = h('div', { class: 'pills' }, DAYS.map((d, i) => {
      const b = h('button', { type: 'button', class: 'pill' + (st.days.has(i) ? ' on' : ''), 'aria-pressed': String(st.days.has(i)) }, d);
      b.addEventListener('click', () => { st.days.has(i) ? st.days.delete(i) : st.days.add(i); b.classList.toggle('on', st.days.has(i)); b.setAttribute('aria-pressed', String(st.days.has(i))); });
      return b;
    }));
    const start = h('select', null, Array.from({ length: 24 }, (_, i) => h('option', { value: i, selected: i === st.startHour }, String(i).padStart(2, '0') + ':00')));
    const len = h('select', null, [1, 2, 3, 4, 5, 6, 8, 10, 12].map(n => h('option', { value: n, selected: n === st.hours }, n + (n === 1 ? ' hour' : ' hours'))));
    clear(box).append(
      h('div', { class: w.enabled ? 'notice ok' : 'notice' }, w.enabled ? 'Online PCs install pending updates inside the window, one PC at a time, at most once a day each.' : 'Off. PCs only update when you install updates yourself.'),
      h('label', { class: 'row', style: { justifyContent: 'space-between' } }, h('span', null, 'Install updates automatically in the window'), toggle(st.enabled, v => { st.enabled = v; })),
      h('div', { class: 'field' }, h('span', null, 'Days'), dayRow),
      h('div', { class: 'row' }, h('label', { class: 'field' }, h('span', null, 'Starts at'), start), h('label', { class: 'field' }, h('span', null, 'Window length'), len)),
      h('label', { class: 'row', style: { justifyContent: 'space-between' } }, h('span', null, 'Only security updates'), toggle(st.securityOnly, v => { st.securityOnly = v; })),
      h('label', { class: 'row', style: { justifyContent: 'space-between' } }, h('span', null, 'Also update programs that have known vulnerabilities'), toggle(st.programs, v => { st.programs = v; })),
      h('label', { class: 'row', style: { justifyContent: 'space-between' } }, h('span', null, 'Allow restarts when an update needs one'), toggle(st.allowReboot, v => { st.allowReboot = v; })),
      h('p', { class: 'muted small-text' }, 'Times are the server\u2019s local time. A PC that is off during the window is patched the next time it is online inside one. Results appear in the activity log.'),
      h('div', { class: 'row' }, actionButton('Save window', async () => {
        await api('PUT', '/api/patch-window', { enabled: st.enabled, days: [...st.days].sort(), startHour: +start.value, hours: +len.value, allowReboot: st.allowReboot, securityOnly: st.securityOnly, programs: st.programs });
        toast('Patch window saved', 'ok'); draw();
      }, 'primary')));
  };
  draw();
  return panel('Patch window', 'Install updates automatically at a quiet time', null, box);
}

// ---------- backups and health ----------
function backupPanel() {
  const box = h('div', { class: 'stack' }, h('span', { class: 'spinner' }));
  const uptime = sec => sec >= 86400 ? Math.floor(sec / 86400) + ' d ' + Math.floor(sec % 86400 / 3600) + ' h' : sec >= 3600 ? Math.floor(sec / 3600) + ' h ' + Math.floor(sec % 3600 / 60) + ' min' : Math.floor(sec / 60) + ' min';
  const draw = async () => {
    let hl, bl;
    try { [hl, bl] = await Promise.all([api('GET', '/api/health'), api('GET', '/api/backups')]); } catch (e) { clear(box).append(h('div', { class: 'notice bad' }, e.message)); return; }
    const kv = rows => h('dl', { class: 'kv' }, rows.map(([k, v]) => [h('dt', null, k), h('dd', null, v)]));
    const file = h('input', { type: 'file', accept: '.zip', class: 'hidden' });
    file.addEventListener('change', async () => {
      const f = file.files[0]; if (!f) return;
      try {
        await ensureStepUp();
        const res = await fetch('/api/backups/upload', { method: 'POST', credentials: 'same-origin', headers: { 'X-CSRF-Token': S.csrf, 'Content-Type': 'application/zip' }, body: f });
        const d = await res.json().catch(() => ({}));
        if (!res.ok) throw new Error(d.error || 'upload failed');
        toast('Backup added. Restore it from the list.', 'ok'); draw();
      } catch (e) { toast(e.message, 'bad'); }
      file.value = '';
    });
    clear(box).append(
      (hl.warnings || []).map(w => h('div', { class: 'notice warn' }, w)),
      kv([['Version', hl.version], ['Running for', uptime(hl.uptimeSec)], ['PCs online', hl.devices.online + ' of ' + hl.devices.approved],
        ['Disk free', hl.disk.total ? fmtBytes(hl.disk.free) + ' of ' + fmtBytes(hl.disk.total) : 'unknown'],
        ['Data size', fmtBytes(hl.data.state + hl.data.db + hl.data.audit)], ['Last backup', hl.backups.last ? fmtAgo(hl.backups.last.created) : 'never']]),
      h('div', { class: 'row' }, actionButton('Back up now', async () => { await api('POST', '/api/backups', {}); toast('Backup created', 'ok'); draw(); }, 'primary'),
        h('button', { onclick: () => file.click() }, 'Upload a backup…'), file),
      bl.backups.length ? h('div', { class: 'tablewrap' }, table(['Backup', 'Created', 'Size', ''].map(x => ({ label: x })), bl.backups.map(b => h('tr', null,
        h('td', { class: 'mono' }, b.name.replace(/^helm-|\.zip$/g, '')), h('td', { class: 'nowrap' }, fmtAgo(b.created)), h('td', { class: 'num' }, fmtBytes(b.size)),
        h('td', { class: 'nowrap right' }, h('div', { class: 'row tight', style: { justifyContent: 'flex-end' } },
          actionButton('Download', async () => { await ensureStepUp(); downloadFile('/api/backups/' + encodeURIComponent(b.name)); }, 'small'),
          actionButton('Restore', async () => {
            if (!(await confirmDialog('Restore this backup? Settings, devices and history are replaced by the backup\'s content, and you will be signed out. A safety copy of the current state is made first.', 'Restore', true))) return;
            await api('POST', '/api/backups/restore', { name: b.name }); toast('Restored. Sign in again.', 'ok'); setTimeout(() => location.reload(), 800);
          }, 'small danger'),
          actionButton('Delete', async () => { if (await confirmDialog('Delete this backup?', 'Delete', true)) { await api('DELETE', '/api/backups/' + encodeURIComponent(b.name)); draw(); } }, 'small ghost')))))))
        : h('p', { class: 'muted' }, 'No backups yet.'),
      h('p', { class: 'muted small-text' }, 'A backup is made automatically every day and the newest ' + bl.keep + ' are kept. Backups contain your password hash and device credentials: store downloads safely.'));
  };
  draw();
  return panel('Backups and health', 'Automatic daily backups, one-click restore', null, box);
}

// ---------- security ----------
route(/^\/security(?:\/([a-z]+))?$/, viewSecurity);
async function viewSecurity(tab) {
  tab = tab || 'findings';
  const host = h('div', null, h('span', { class: 'spinner' }));
  shell('security', [pageHead('Security', 'Vulnerabilities, missing patches, risky settings and exposed ports', [
    h('a', { class: 'btn', href: '/api/reports/vulnerabilities', download: '' }, 'Export CSV'),
    actionButton('Scan all PCs', async () => { const r = await api('POST', '/api/run/scan', { target: { all: true } }); toast('Scanning ' + plural(r.results.length, 'PC'), 'ok'); }, 'primary')]),
  h('div', { class: 'tabs' }, [['findings', 'Findings'], ['pcs', 'By PC']].map(([k, l]) => h('a', { href: '#/security/' + k, class: tab === k ? 'active' : '' }, l))), host]);
  const my = routeToken;
  const f = Object.assign({ sev: 'all', kind: 'all', q: '' }, store.get('secfilter', {}));
  let data = null, last = '';
  const draw = () => {
    if (!data) return;
    const sig = JSON.stringify(data) + JSON.stringify(f) + tab;
    if (sig === last) return; last = sig;
    clear(host);
    const sev = { critical: 0, high: 0, medium: 0, low: 0 }; let expl = 0;
    data.findings.forEach(x => { if (sev[x.severity] != null) sev[x.severity] += x.devices.length; if (x.exploited) expl++; });
    const scores = data.devices.filter(x => x.security && x.security.hasData).map(x => x.security.score);
    const avg = scores.length ? Math.round(scores.reduce((a, b) => a + b, 0) / scores.length) : null;
    host.append(cveNotice(data.cve) ? h('div', { style: { marginBottom: '16px' } }, cveNotice(data.cve)) : null,
      h('div', { class: 'kpis' },
        h('div', { class: 'kpi ' + (avg == null ? '' : avg >= 80 ? 'ok' : avg >= 50 ? 'warn' : 'bad') }, h('div', { class: 'lbl' }, 'Average score'), h('div', { class: 'val' }, avg == null ? '–' : avg), h('div', { class: 'note' }, `${data.scanned} of ${data.total} PCs scanned`)),
        h('div', { class: 'kpi ' + (sev.critical ? 'bad' : '') }, h('div', { class: 'lbl' }, 'Critical'), h('div', { class: 'val' }, String(sev.critical)), h('div', { class: 'note' }, 'across the fleet')),
        h('div', { class: 'kpi' }, h('div', { class: 'lbl' }, 'High'), h('div', { class: 'val' }, String(sev.high)), h('div', { class: 'note' }, plural(sev.medium, 'medium') + ' · ' + sev.low + ' low')),
        h('div', { class: 'kpi ' + (expl ? 'bad' : '') }, h('div', { class: 'lbl' }, 'Actively exploited'), h('div', { class: 'val' }, String(expl)), h('div', { class: 'note' }, 'CISA known-exploited CVEs')),
        h('div', { class: 'kpi' }, h('div', { class: 'lbl' }, 'Programs assessed'), h('div', { class: 'val' }, String(data.assessed)), h('div', { class: 'note' }, `${data.unassessed} not identified${data.pending ? ' · ' + data.pending + ' pending' : ''}${data.unavailable ? ' · ' + data.unavailable + ' unavailable' : ''}`))));
    if (tab === 'pcs') return drawPCs();
    drawFindings();
  };
  const drawPCs = () => {
    const rows = [...data.devices].sort((a, b) => ((a.security ? a.security.score : 101) - (b.security ? b.security.score : 101)));
    host.append(h('div', { class: 'panel flush' }, table(['PC', 'Score', 'Findings', 'Last scan', ''].map(x => ({ label: x })), rows.map(d => {
      const s = d.security;
      return h('tr', { class: 'clickable', onclick: () => { location.hash = '#/d/' + d.id + '/security'; } },
        h('td', null, h('div', { class: 'row tight' }, h('span', { class: 'statusdot' + (d.online ? ' on' : '') }), h('b', null, d.name)), d.group ? h('span', { class: 'tag group' }, d.group) : null),
        h('td', null, scoreBadge(s)),
        h('td', { style: { minWidth: '180px' } }, s ? h('div', { class: 'stack', style: { gap: '4px' } }, sevBar(s.counts), h('span', { class: 'muted small-text' }, SEV_ORDER.map(k => s.counts[k] + ' ' + k).join(' · '))) : h('span', { class: 'muted' }, 'Not scanned')),
        h('td', { class: 'muted nowrap' }, s ? (s.status === 'running' ? 'Scanning…' : fmtAgo(s.at)) : 'never'),
        h('td', { onclick: e => e.stopPropagation() }, d.online ? actionButton('Scan', async () => { await api('POST', `/api/devices/${d.id}/scan`, {}); toast('Scan started on ' + d.name, 'ok'); }, 'small') : h('span', { class: 'muted small-text' }, 'offline')));
    }), { empty: 'No approved PCs yet' })));
  };
  const drawFindings = () => {
    const q = f.q.trim().toLowerCase();
    let list = data.findings.filter(x => (f.sev === 'all' || x.severity === f.sev) && (f.kind === 'all' || x.kind === f.kind) &&
      (!q || (x.title + ' ' + x.detail + ' ' + (x.cve || '') + ' ' + (x.software || '') + ' ' + x.devices.map(d => d.name).join(' ')).toLowerCase().includes(q)));
    const search = h('input', { type: 'search', placeholder: 'Search CVE, software, PC…', value: f.q, 'aria-label': 'Search findings' });
    search.addEventListener('input', () => { f.q = search.value; store.set('secfilter', f); last = ''; const pos = search.selectionStart; draw(); const n = $('input[aria-label="Search findings"]'); if (n) { n.focus(); n.setSelectionRange(pos, pos); } });
    const pill = (key, val, label) => h('button', { class: 'pill' + (f[key] === val ? ' on' : ''), onclick: () => { f[key] = val; store.set('secfilter', f); last = ''; draw(); } }, label);
    host.append(h('div', { class: 'toolbar' }, h('div', { class: 'grow' }, search),
      h('div', { class: 'pills' }, pill('sev', 'all', 'All severities'), SEV_ORDER.map(s => pill('sev', s, cap(s)))),
      h('div', { class: 'pills' }, [['all', 'All types'], ['cve', 'Vulnerable software'], ['patch', 'Patches'], ['config', 'Configuration'], ['port', 'Open ports']].map(([k, l]) => pill('kind', k, l)))));
    if (!data.scanned) { host.append(h('div', { class: 'panel' }, emptyState('🛡️', 'No scans yet', 'Scans run automatically on online PCs. You can also start one now.', actionButton('Scan all PCs', async () => { await api('POST', '/api/run/scan', { target: { all: true } }); toast('Scans started', 'ok'); }, 'primary')))); return; }
    if (!list.length) { host.append(h('div', { class: 'panel' }, emptyState('✅', 'Nothing to show', data.findings.length ? 'No findings match these filters.' : 'No findings across your scanned PCs.'))); return; }
    host.append(h('div', { class: 'panel flush' }, list.slice(0, 200).map(x => h('div', { class: 'finding' },
      h('div', null, sevBadge(x.severity)),
      h('div', null, h('div', { class: 'ft' }, x.title, x.cve ? h('a', { href: 'https://nvd.nist.gov/vuln/detail/' + encodeURIComponent(x.cve), target: '_blank', rel: 'noopener noreferrer', style: { marginLeft: '8px', fontWeight: 400 } }, 'NVD ↗') : null,
        x.score ? h('span', { class: 'muted', style: { fontWeight: 400 } }, '  CVSS ' + x.score.toFixed(1)) : null, x.accepted ? h('span', { class: 'badge', style: { marginLeft: '8px' } }, 'accepted risk') : null, x.noFix ? h('span', { class: 'badge', style: { marginLeft: '8px' } }, 'no update published') : null, x.exploited ? h('span', { class: 'badge kev', style: { marginLeft: '8px' } }, 'actively exploited') : null),
        x.detail ? h('div', { class: 'fd' }, x.detail) : null, x.fix ? h('div', { class: 'ff' }, '→ ' + x.fix) : null,
        h('div', { class: 'muted small-text', style: { marginTop: '4px' } }, x.kind === 'cve' ? 'Potentially affected: the version matches the vulnerable range; fixes backported by the operating system vendor are not detected, so confirm with the update check.' : '')),
      h('div', { class: 'right' }, h('button', { class: 'small', onclick: () => affectedDialog(x) }, plural(x.devices.length, 'PC')), x.accepted ? null : fixButton(x), acceptButton(x))))),
      list.length > 200 ? h('p', { class: 'muted', style: { marginTop: '10px' } }, 'Showing the first 200 of ' + list.length + '. Export the CSV for everything.') : null);
  };
  const load = async () => { try { data = await api('GET', '/api/security'); if (my === routeToken) draw(); } catch (e) { clear(host).append('Could not load: ' + e.message); } };
  const onRefresh = () => { last = ''; load(); };
  window.addEventListener('helm-sec-refresh', onRefresh); cleanups.push(() => window.removeEventListener('helm-sec-refresh', onRefresh));
  load(); every(12000, load);
}

// One-click fixes for configuration findings. The console only ever sends a check id; the agent decides what that id
// means on its own platform and refuses anything it does not know.
const FIXABLE = new Set(['firewall', 'av_realtime', 'av_signatures', 'smb1', 'rdp', 'uac', 'guest', 'gatekeeper', 'autoupdate', 'auto_updates', 'ntp']);
function fixButton(x) {
  if (x.kind === 'cve' && x.software) return softwareButton(x);
  const id = x.kind === 'config' && (x.key || '').startsWith('cfg:') ? x.key.slice(4) : '';
  if (!FIXABLE.has(id)) return null;
  const b = h('button', { class: 'small primary', style: { marginTop: '6px' } }, 'Fix on ' + plural(x.devices.length, 'PC'));
  b.addEventListener('click', action(b, async () => {
    if (!confirm('Apply the fix on ' + plural(x.devices.length, 'PC') + '?\n\n' + x.title + (x.fix ? '\n' + x.fix : ''))) return;
    let ok = 0; const bad = [];
    for (const d of x.devices) {
      try {
        const job = await api('POST', '/api/devices/' + d.id + '/cmd', { name: 'fix.apply', args: { id }, wait: 600 });
        if (job && job.status === 'error') bad.push(d.name + ': ' + job.err); else ok++;
      } catch (e) { bad.push(d.name + ': ' + e.message); }
      try { await api('POST', '/api/devices/' + d.id + '/scan', {}); } catch (e) { /* rescan is best effort */ }
    }
    if (ok) toast('Fixed on ' + plural(ok, 'PC') + '. Rescanning.', 'ok');
    if (bad.length) toast(bad.slice(0, 3).join('; '), 'bad');
  }));
  return b;
}

// A vulnerable program is fixed by updating it. The server finds the update through winget or the package manager and
// says plainly when the vendor has not published one.
function acceptButton(x) {
  if (x.severity === 'info') return null;
  const b = h('button', { class: 'small', style: { marginTop: '6px' } }, x.accepted ? 'Stop accepting' : 'Accept risk');
  b.addEventListener('click', action(b, async () => {
    if (x.accepted) { await api('POST', '/api/security/unaccept', { key: x.key }); toast('Counted again', 'ok'); }
    else {
      const note = prompt('Accept this risk? It stays listed but stops lowering the score and raising alerts.\n\nWhy is it acceptable? (optional)');
      if (note === null) return;
      await api('POST', '/api/security/accept', { key: x.key, note });
      toast('Risk accepted', 'ok');
    }
    window.dispatchEvent(new CustomEvent('helm-sec-refresh'));
  }));
  return b;
}

function softwareButton(x) {
  const b = h('button', { class: 'small primary', style: { marginTop: '6px' } }, 'Update on ' + plural(x.devices.length, 'PC'));
  b.addEventListener('click', action(b, async () => {
    if (!confirm('Update ' + x.software + ' on ' + plural(x.devices.length, 'PC') + '?')) return;
    let ok = 0; const bad = [], left = [];
    for (const d of x.devices) {
      try {
        const r = await api('POST', '/api/devices/' + d.id + '/update-software', { software: x.software });
        if (r && r.rescanned && r.remaining > 0) left.push(d.name + ' (' + r.remaining + ' left)'); else ok++;
      } catch (e) { bad.push(d.name + ': ' + e.message); }
    }
    if (ok) toast(x.software + ' updated and checked on ' + plural(ok, 'PC') + '. The vulnerabilities are gone.', 'ok');
    if (left.length) toast('Updated, but the rescan still finds vulnerabilities on ' + left.join(', ') + '. A newer version may be needed.', 'bad');
    if (bad.length) toast(bad.slice(0, 2).join('; '), 'bad');
  }));
  return b;
}

function affectedDialog(x) {
  return modal('Affected PCs', h('div', { class: 'stack' }, h('div', null, sevBadge(x.severity), ' ', h('b', null, x.title)),
    h('div', { class: 'stack', style: { gap: '6px' } }, x.devices.map(d => h('a', { href: '#/d/' + d.id + '/security', onclick: () => { document.querySelector('#modal-root .backdrop')?.remove(); } }, d.name)))));
}

// ---------- alerts ----------
route(/^\/alerts$/, viewAlerts);
async function viewAlerts() {
  const host = h('div', null, h('span', { class: 'spinner' }));
  shell('alerts', [pageHead('Alerts', 'Problems that need your attention', [h('a', { class: 'btn', href: '#/settings' }, 'Alert settings'),
    actionButton('Clear resolved', async () => { await api('POST', '/api/alerts/clear', {}); load(); })]), host]);
  const my = routeToken;
  const load = async () => {
    let list;
    try { list = await api('GET', '/api/alerts'); } catch (e) { clear(host).append('Could not load: ' + e.message); return; }
    if (my !== routeToken) return;
    const open = list.filter(a => isZero(a.resolved)), done = list.filter(a => !isZero(a.resolved));
    setAlertCount(open.filter(a => !a.acked).length);
    const row = a => h('div', { class: 'finding', style: { gridTemplateColumns: '84px 1fr auto' } },
      h('div', null, sevBadge(a.severity)),
      h('div', null, h('div', { class: 'ft' }, a.title), a.detail ? h('div', { class: 'fd' }, a.detail) : null,
        h('div', { class: 'muted small-text', style: { marginTop: '4px' } }, 'Opened ' + fmtAgo(a.opened) + (isZero(a.resolved) ? '' : ' · resolved ' + fmtAgo(a.resolved)) + (a.acked && isZero(a.resolved) ? ' · acknowledged' : ''))),
      h('div', { class: 'row tight' }, a.deviceId && a.rule !== 'new_device' ? h('a', { class: 'btn small', href: '#/d/' + a.deviceId + (a.rule === 'security' || a.rule === 'patches' ? '/security' : '') }, 'View PC') : a.rule === 'new_device' ? h('a', { class: 'btn small', href: '#/devices' }, 'Review') : null,
        isZero(a.resolved) && !a.acked ? actionButton('Acknowledge', async () => { await api('POST', `/api/alerts/${a.id}/ack`, {}); load(); }, 'small') : null));
    clear(host).append(
      h('div', { class: 'panel flush' }, h('div', { class: 'phead' }, h('h3', null, 'Open'), h('span', { class: 'muted' }, String(open.length))),
        open.length ? open.map(row) : emptyState('🎉', 'All clear', 'No open alerts. Helm checks continuously and can message you on Telegram when something breaks.')),
      done.length ? h('details', { class: 'panel flush fold', style: { marginTop: '16px' } }, h('summary', null, 'Resolved (' + done.length + ')'), done.slice(0, 100).map(row)) : null);
  };
  load(); every(10000, load);
}

// ---------- sessions ----------
route(/^\/sessions$/, viewSessions);
async function viewSessions() {
  const host = h('div', null, h('span', { class: 'spinner' }));
  shell('sessions', [pageHead('Remote sessions', 'Who connected to which PC, how, and for how long. Includes refused attempts.', h('a', { class: 'btn', href: '/api/reports/sessions', download: '' }, 'Export CSV')), host]);
  const my = routeToken;
  let rows = [], kind = 'all', q = '';
  const KIND = { screen: 'Remote screen', term: 'Terminal', file: 'File transfer', rdp: 'RDP tunnel' };
  const draw = () => {
    const r = rows.filter(x => (kind === 'all' || x.kind === kind) && (!q || (x.deviceName + ' ' + x.ip + ' ' + x.detail).toLowerCase().includes(q)));
    const search = h('input', { type: 'search', placeholder: 'Search PC or IP…', value: q, 'aria-label': 'Search sessions' });
    search.addEventListener('input', () => { q = search.value.toLowerCase(); const p = search.selectionStart; draw(); const n = $('input[aria-label="Search sessions"]'); if (n) { n.focus(); n.setSelectionRange(p, p); } });
    const active = rows.filter(x => x.result === 'active').length;
    clear(host).append(
      h('div', { class: 'kpis' }, h('div', { class: 'kpi' }, h('div', { class: 'lbl' }, 'Sessions on record'), h('div', { class: 'val' }, String(rows.length))),
        h('div', { class: 'kpi ' + (active ? 'accent' : '') }, h('div', { class: 'lbl' }, 'Active now'), h('div', { class: 'val' }, String(active))),
        h('div', { class: 'kpi' }, h('div', { class: 'lbl' }, 'Refused'), h('div', { class: 'val' }, String(rows.filter(x => x.result === 'refused').length)), h('div', { class: 'note' }, 'blocked by the person at the PC or an error'))),
      h('div', { class: 'toolbar' }, h('div', { class: 'grow' }, search), h('div', { class: 'pills' }, [['all', 'All']].concat(Object.entries(KIND)).map(([k, l]) => h('button', { class: 'pill' + (kind === k ? ' on' : ''), onclick: () => { kind = k; draw(); } }, l)))),
      h('div', { class: 'panel flush' }, table(['Started', 'PC', 'Type', 'Duration', 'From', 'Result', 'Details'].map(x => ({ label: x })), r.map(x => h('tr', null,
        h('td', { class: 'nowrap' }, fmtShort(x.started)), h('td', null, h('a', { href: '#/d/' + x.deviceId }, x.deviceName)),
        h('td', null, KIND[x.kind] || x.kind, x.viewOnly ? h('span', { class: 'muted' }, ' (view only)') : null),
        h('td', { class: 'nowrap' }, x.result === 'active' ? 'in progress' : fmtSpan(x.started, x.ended) || '–'), h('td', { class: 'muted' }, x.ip),
        h('td', null, h('span', { class: 'badge ' + x.result }, x.result)), h('td', { class: 'muted wrap' }, x.detail || ''))), { empty: 'No sessions recorded yet. Screen, terminal, file and RDP sessions will appear here.' })));
  };
  const load = async () => { try { rows = await api('GET', '/api/sessions?limit=500'); if (my === routeToken) draw(); } catch (e) { clear(host).append('Could not load: ' + e.message); } };
  load(); every(10000, () => { if (!document.activeElement || document.activeElement.tagName !== 'INPUT') load(); });
}

// ---------- reports ----------
route(/^\/reports$/, viewReports);
function viewReports() {
  const card = (title, text, kind, ic) => h('div', { class: 'panel stack' }, h('div', { class: 'row' }, h('span', { class: 'avatar' }, icon(ic)), h('h3', { style: { margin: 0 } }, title)), h('p', { class: 'muted', style: { margin: 0, flex: 1 } }, text),
    h('div', null, h('a', { class: 'btn', href: '/api/reports/' + kind, download: '' }, 'Download CSV')));
  shell('reports', [pageHead('Reports', 'Export data for spreadsheets, audits or customers'),
    h('div', { class: 'grid' },
      card('PC inventory', 'Every managed PC with group, tags, OS, agent version, user, live CPU and memory.', 'inventory', 'devices'),
      card('Hardware inventory', 'Manufacturer, model, serial, CPU, RAM and BIOS of every PC, as last collected.', 'hardware', 'devices'),
      card('Vulnerabilities', 'All findings from the latest scan of each PC: CVEs, patches, configuration problems and open ports.', 'vulnerabilities', 'shield'),
      card('Installed software', 'Software found on each PC by the last scan, with versions and publishers.', 'software', 'box'),
      card('Remote sessions', 'History of screen, terminal, file and RDP sessions with times and source IPs.', 'sessions', 'video'),
      card('Activity log', 'Audit trail of actions taken in this console.', 'audit', 'list'),
      h('div', { class: 'panel stack' }, h('div', { class: 'row' }, h('span', { class: 'avatar' }, icon('dash')), h('h3', { style: { margin: 0 } }, 'Security summary')), h('p', { class: 'muted', style: { margin: 0, flex: 1 } }, 'A one-page printable overview. Use Print and choose "Save as PDF".'),
        h('div', null, h('a', { class: 'btn primary', href: '#/reports/summary' }, 'Open summary')))),
    h('p', { class: 'muted', style: { marginTop: '16px' } }, 'CSV files open in Excel and Google Sheets.')]);
}

route(/^\/reports\/summary$/, viewSummary);
async function viewSummary() {
  const host = h('div', null, h('span', { class: 'spinner' }));
  shell('reports', [pageHead('Security summary', new Date().toLocaleDateString([], { dateStyle: 'long' }), [h('a', { class: 'btn', href: '#/reports' }, 'Back'), h('button', { class: 'primary', onclick: () => window.print() }, 'Print / save as PDF')]), host]);
  try {
    const [d, sec] = await Promise.all([api('GET', '/api/dashboard'), api('GET', '/api/security')]);
    const top = sec.findings.filter(x => x.severity === 'critical' || x.severity === 'high').slice(0, 15);
    clear(host).append(
      h('div', { class: 'kpis' }, h('div', { class: 'kpi' }, h('div', { class: 'lbl' }, 'Managed PCs'), h('div', { class: 'val' }, String(d.total))),
        h('div', { class: 'kpi' }, h('div', { class: 'lbl' }, 'Average score'), h('div', { class: 'val' }, d.avgScore == null ? '–' : d.avgScore)),
        h('div', { class: 'kpi' }, h('div', { class: 'lbl' }, 'Critical'), h('div', { class: 'val' }, String(d.counts.critical))), h('div', { class: 'kpi' }, h('div', { class: 'lbl' }, 'High'), h('div', { class: 'val' }, String(d.counts.high)))),
      panel('PCs by score', null, null, table(['PC', 'Group', 'Score', 'Critical', 'High', 'Medium', 'Low', 'Scanned'].map(x => ({ label: x })), [...sec.devices].sort((a, b) => ((a.security ? a.security.score : 101) - (b.security ? b.security.score : 101))).map(x => h('tr', null,
        h('td', null, x.name), h('td', null, x.group || ''), h('td', null, x.security ? String(x.security.score) : '–'), ...['critical', 'high', 'medium', 'low'].map(k => h('td', null, x.security ? String(x.security.counts[k]) : '–')), h('td', null, x.security ? fmtShort(x.security.at) : 'never'))))),
      panel('Most serious findings', 'Critical and high, widest impact first', null, top.length ? table(['Severity', 'Finding', 'PCs'].map(x => ({ label: x })), top.map(x => h('tr', null, h('td', null, sevBadge(x.severity)), h('td', null, x.title), h('td', null, String(x.devices.length))))) : h('p', { class: 'muted' }, 'No critical or high findings.')),
      h('p', { class: 'muted small-text', style: { marginTop: '12px' } }, 'Vulnerability matches are potential: a version in an affected range may already be fixed by a vendor backport. Verify before acting.'));
  } catch (e) { clear(host).append('Could not load: ' + e.message); }
}

// ---------- settings ----------
route(/^\/settings$/, viewSettings);
async function viewSettings() {
  const host = h('div', null, h('span', { class: 'spinner' }));
  shell('settings', [pageHead('Settings', 'Updates, alerts, scanning and backups'), host]);
  const my = routeToken;
  let s;
  try { s = await api('GET', '/api/settings'); } catch (e) { clear(host).append('Could not load: ' + e.message); return; }
  if (my !== routeToken) return;
  const rules = Object.assign({}, s.rules);
  const tgOn = toggle(s.telegram.enabled), token = h('input', { type: 'password', autocomplete: 'off', placeholder: s.telegram.tokenSet ? '•••••••• (saved; leave blank to keep)' : '123456:ABC-DEF…' });
  const chat = h('input', { type: 'text', placeholder: 'e.g. 123456789', value: s.telegram.chatId });
  const em = s.email, emOn = toggle(em.enabled), emHost = h('input', { type: 'text', placeholder: 'smtp.example.com', value: em.host }), emPort = h('input', { type: 'number', min: 1, max: 65535, value: em.port }),
    emSec = h('select', null, [['starttls', 'STARTTLS (port 587)'], ['tls', 'TLS (port 465)'], ['none', 'None (port 25, no password)']].map(([v, t]) => h('option', { value: v, selected: em.security === v }, t))),
    emUser = h('input', { type: 'text', autocomplete: 'off', value: em.user }), emPass = h('input', { type: 'password', autocomplete: 'new-password', placeholder: em.passSet ? '•••••••• (saved; leave blank to keep)' : '' }),
    emFrom = h('input', { type: 'text', placeholder: 'Helm <helm@example.com>', value: em.from }), emTo = h('input', { type: 'text', placeholder: 'you@example.com, helper@example.com', value: em.to });
  emSec.onchange = () => { emPort.value = { starttls: 587, tls: 465, none: 25 }[emSec.value]; };
  const offline = h('input', { type: 'number', min: 0, max: 10080, value: s.offlineMinutes, style: { width: '7em' } });
  const disk = h('input', { type: 'number', min: 0, max: 90, value: s.diskFreePct, style: { width: '7em' } });
  const autoScan = toggle(s.autoScan), every_ = h('input', { type: 'number', min: 1, max: 720, value: s.scanEveryHours, style: { width: '7em' } });
  const nvd = h('input', { type: 'password', autocomplete: 'off', placeholder: s.nvdKeySet ? '•••••••• (saved)' : 'Optional NVD API key' });
  let clearTok = false, clearNvd = false;
  const repo = h('input', { type: 'text', placeholder: 'aarondebbs/helm-app', value: s.updateRepo || '', autocomplete: 'off', spellcheck: 'false' });
  const manualAgents = toggle(!s.manualAgentUpdates);
  const updBox = h('div', { class: 'stack' }, h('span', { class: 'spinner' }));
  const drawUpd = async () => {
    let u; try { u = await api('GET', '/api/update'); } catch (e) { clear(updBox).append(h('div', { class: 'notice bad' }, e.message)); return; }
    const rel = Object.entries(u.agentReleases || {}).map(([k, v]) => `${k} ${v}`).join(' · ') || 'none';
    clear(updBox).append(
      h('div', { class: 'row spread' }, h('span', null, 'This server'), h('b', null, u.current)),
      h('div', { class: 'row spread' }, h('span', null, 'Latest release'), h('b', null, u.latest || (u.repo ? 'not checked yet' : '—'))),
      h('div', { class: 'row spread' }, h('span', null, 'Agent updates ready to roll out'), h('b', null, rel)),
      !u.keyConfigured ? h('div', { class: 'notice warn' }, 'This server was built without a release key, so cloud updates are switched off. Install a build made with build.sh.') : null,
      u.error ? h('div', { class: 'notice bad' }, u.error) : null,
      u.serverNewer ? h('div', { class: 'notice' }, h('b', null, 'Version ' + u.latest + ' is available. '), u.notes || '') : (u.latest ? h('div', { class: 'notice ok' }, 'This server is up to date.') : null),
      h('div', { class: 'row' },
        actionButton('Check now', async () => { await save(true); await api('POST', '/api/update/check', {}); drawUpd(); }),
        actionButton('Update PCs now', async () => { await save(true); await api('POST', '/api/update/agents', {}); toast('Agent releases imported. PCs update themselves within minutes.', 'ok'); drawUpd(); }),
        u.canApply && u.serverNewer ? actionButton('Update this server to ' + u.latest, async () => {
          if (!(await confirmDialog('Install ' + u.latest + ' and restart the server? PCs reconnect automatically in a few seconds.', 'Update server'))) return;
          await save(true); const r = await api('POST', '/api/update/server', {}); toast('Installed ' + r.version + '. Restarting…', 'ok'); setTimeout(() => location.reload(), 6000);
        }, 'primary') : null),
      versionsBox(u));
  };
  // Every release of the repository with its release log; any version can be installed (or rolled back to).
  const versionsBox = (u) => {
    const box = h('div', { class: 'stack' });
    const load = async () => {
      clear(box).append(h('span', { class: 'spinner' }));
      let r; try { r = await api('GET', '/api/update/releases'); } catch (e) { clear(box).append(h('div', { class: 'notice bad' }, e.message)); return; }
      const when = (t) => t ? new Date(t).toLocaleDateString(undefined, { year: 'numeric', month: 'short', day: 'numeric' }) : '';
      const rows = r.releases.map((x, i) => {
        const tags = [x.current ? h('span', { class: 'badge ok' }, 'running') : null, i === 0 && !x.prerelease ? h('span', { class: 'badge info' }, 'latest') : null,
          x.prerelease ? h('span', { class: 'badge warning' }, 'pre-release') : null, !x.hasServer ? h('span', { class: 'badge' }, 'no ' + r.platform + ' build') : null];
        const can = u.canApply && !x.current && x.hasServer;
        const btn = can ? actionButton(x.newer ? 'Install' : 'Roll back to this', async () => {
          const msg = x.newer ? 'Install ' + x.tag + ' and restart the server? PCs reconnect automatically in a few seconds.'
            : x.tag + ' is older than the version you run. A backup is taken first, but an older version may not understand newer data. Go back to ' + x.tag + '?';
          if (!(await confirmDialog(msg, x.newer ? 'Install version' : 'Roll back'))) return;
          const res = await api('POST', '/api/update/server', { version: x.tag });
          toast('Installed ' + res.version + '. Restarting…', 'ok'); setTimeout(() => location.reload(), 6000);
        }, x.newer ? 'primary' : '') : null;
        return h('details', { class: 'release' },
          h('summary', null, h('b', null, x.tag), h('span', { class: 'muted' }, when(x.published)), ...tags, h('span', { class: 'grow' }), btn),
          h('pre', { class: 'relnotes' }, x.notes || 'No release log was written for this version.'));
      });
      clear(box).append(rows.length ? h('div', { class: 'releases' }, ...rows) : h('div', { class: 'muted' }, 'No releases with a Helm manifest were found in this repository.'));
    };
    return h('details', { class: 'fold' }, h('summary', { onclick: (e) => { if (!box.dataset.loaded) { box.dataset.loaded = '1'; load(); } } }, 'Versions and release logs'), h('div', { style: { padding: '12px 18px 16px' } }, box));
  };
  setTimeout(drawUpd, 0);
  const save = async (quiet) => {
    const body = { updateRepo: repo.value, manualAgentUpdates: !manualAgents.querySelector('input').checked, telegram: { enabled: tgOn.querySelector('input').checked, chatId: chat.value, token: token.value, clearToken: clearTok },
      email: { enabled: emOn.querySelector('input').checked, host: emHost.value, port: Number(emPort.value), security: emSec.value, user: emUser.value, pass: emPass.value, from: emFrom.value, to: emTo.value },
      offlineMinutes: Number(offline.value), diskFreePct: Number(disk.value), autoScan: autoScan.querySelector('input').checked, scanEveryHours: Number(every_.value), rules };
    if (nvd.value || clearNvd) body.nvdKey = clearNvd ? '' : nvd.value;
    await api('PUT', '/api/settings', body); if (quiet === true) return; toast('Settings saved', 'ok'); viewSettings();
  };
  clear(host).append(
    h('div', { class: 'grid two' },
      h('div', { class: 'stack' },
        panel('Updates', 'Install new versions from your GitHub releases', null, h('div', { class: 'stack' },
          h('label', { class: 'field' }, h('span', null, 'GitHub repository'), repo, h('span', { class: 'hint' }, 'Owner/name of the repository that publishes Helm releases (public, or any repository whose releases this server can read). Every file is signature-checked before it is installed.')),
          h('div', { class: 'row spread' }, h('span', null, 'Roll agent updates out to PCs automatically'), manualAgents),
          updBox)),
        backupPanel(),
        panel('Telegram notifications', 'Get alerts on your phone', null, h('div', { class: 'stack' },
          h('div', { class: 'row spread' }, h('span', null, 'Send alerts to Telegram'), tgOn),
          h('label', { class: 'field' }, h('span', null, 'Bot token'), token, h('span', { class: 'hint' }, 'Create a bot with @BotFather in Telegram and paste the token it gives you.')),
          h('label', { class: 'field' }, h('span', null, 'Chat ID'), chat, h('span', { class: 'hint' }, 'Send any message to your bot, then open https://api.telegram.org/bot<token>/getUpdates and copy the number after "chat":{"id":.')),
          h('div', { class: 'row' }, actionButton('Send test message', async () => { await save(); await api('POST', '/api/settings/telegram-test', {}); toast('Test message sent. Check Telegram.', 'ok'); }),
            s.telegram.tokenSet ? h('button', { class: 'danger', onclick: e => { clearTok = true; token.value = ''; token.placeholder = 'Token will be removed on save'; e.target.disabled = true; } }, 'Remove saved token') : null))),
        panel('E-mail notifications', 'Send alerts to your inbox', null, h('div', { class: 'stack' },
          h('div', { class: 'row spread' }, h('span', null, 'Send alerts by e-mail'), emOn),
          h('div', { class: 'grid two' }, h('label', { class: 'field' }, h('span', null, 'SMTP server'), emHost), h('label', { class: 'field' }, h('span', null, 'Port'), emPort)),
          h('label', { class: 'field' }, h('span', null, 'Security'), emSec),
          h('div', { class: 'grid two' }, h('label', { class: 'field' }, h('span', null, 'User name (optional)'), emUser), h('label', { class: 'field' }, h('span', null, 'Password'), emPass)),
          h('label', { class: 'field' }, h('span', null, 'Send from'), emFrom),
          h('label', { class: 'field' }, h('span', null, 'Send to'), emTo, h('span', { class: 'hint' }, 'Separate several addresses with commas. A password is only ever sent over an encrypted connection.')),
          h('div', { class: 'row' }, actionButton('Send test e-mail', async () => { await save(true); await api('POST', '/api/settings/email-test', {}); toast('Test e-mail sent. Check your inbox.', 'ok'); }),
            em.passSet ? h('button', { class: 'danger', onclick: async e => { await api('PUT', '/api/settings', { ...{ email: { ...Object.fromEntries(Object.entries(em).filter(([k]) => k !== 'passSet')), clearPass: true } }, offlineMinutes: s.offlineMinutes, diskFreePct: s.diskFreePct, autoScan: s.autoScan, scanEveryHours: s.scanEveryHours, telegram: { enabled: s.telegram.enabled, chatId: s.telegram.chatId } }); toast('Saved password removed', 'ok'); viewSettings(); } }, 'Remove saved password') : null))),
        panel('Thresholds', null, null, h('div', { class: 'stack' },
          h('label', { class: 'field' }, h('span', null, 'Alert when a PC has been offline for (minutes, 0 = never)'), offline),
          h('label', { class: 'field' }, h('span', null, 'Alert when a drive has less free space than (percent, 0 = never)'), disk)))),
      h('div', { class: 'stack' },
        panel('Alert rules', 'Choose what raises an alert', null, h('div', { class: 'stack', style: { gap: '14px' } }, s.ruleInfo.map(r => h('div', { class: 'row spread', style: { flexWrap: 'nowrap' } },
          h('div', null, h('b', null, r.title), h('div', { class: 'muted small-text' }, r.desc)), toggle(rules[r.id], v => { rules[r.id] = v; }))))),
        panel('Vulnerability scanning', 'Software is matched against the US NVD database', null, h('div', { class: 'stack' },
          h('div', { class: 'row spread' }, h('span', null, 'Scan online PCs automatically'), autoScan),
          h('label', { class: 'field' }, h('span', null, 'Scan each PC every (hours)'), every_),
          h('label', { class: 'field' }, h('span', null, 'NVD API key (optional)'), nvd, h('span', { class: 'hint' }, 'A free key from nvd.nist.gov makes the first downloads about 8× faster.')),
          s.nvdKeySet ? h('div', null, h('button', { class: 'danger small', onclick: e => { clearNvd = true; e.target.disabled = true; nvd.placeholder = 'Key will be removed on save'; } }, 'Remove saved key')) : null,
          h('div', { class: s.cve.lastError ? 'notice warn' : 'notice' }, h('b', null, 'Database: '), `${s.cve.products} product${s.cve.products === 1 ? '' : 's'} cached`, s.cve.queue ? ` · ${s.cve.queue} downloading` : '', !isZero(s.cve.lastOk) ? ' · last update ' + fmtAgo(s.cve.lastOk) : '',
            s.cve.lastError ? h('div', null, 'Last error: ' + s.cve.lastError) : null))))),
    h('div', { class: 'row', style: { marginTop: '20px' } }, actionButton('Save settings', save, 'primary')));
  // Regroup the panels into tabs: one short page per topic instead of one long scroll.
  {
    const grid = host.firstChild, by = {};
    grid.querySelectorAll('.panel').forEach(p => { const t = p.querySelector('h3'); if (t) by[t.textContent] = p; });
    by['Google sign-in'] = googlePanel();
    by['Patch window'] = patchWindowPanel();
    const groups = [['updates', 'Updates', ['Updates', 'Patch window']], ['alerts', 'Alerts and notifications', ['Alert rules', 'Thresholds', 'Telegram notifications']],
      ['scanning', 'Scanning', ['Vulnerability scanning']], ['signin', 'Sign-in', ['Google sign-in']], ['backups', 'Backups and health', ['Backups and health']]];
    let cur = store.get('settab', 'updates'); if (!groups.some(g => g[0] === cur)) cur = 'updates';
    const saveRow = host.lastChild, tabsEl = h('div', { class: 'tabs' }), panes = {};
    const show = k => { cur = k; store.set('settab', k); groups.forEach(([id]) => { panes[id].classList.toggle('hidden', id !== k); }); [...tabsEl.children].forEach((a, n) => a.classList.toggle('active', groups[n][0] === k)); saveRow.classList.toggle('hidden', k === 'backups' || k === 'signin'); };
    groups.forEach(([id, label, titles]) => {
      panes[id] = h('div', { class: 'stack', style: { maxWidth: '780px' } }, titles.map(t => by[t]).filter(Boolean));
      tabsEl.append(h('a', { role: 'tab', tabindex: 0, style: { cursor: 'pointer' }, onclick: () => show(id), onkeydown: e => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); show(id); } } }, label));
    });
    clear(host).append(tabsEl, ...groups.map(g => panes[g[0]]), saveRow);
    show(cur);
  }
}

// ---------- my account ----------
route(/^\/account$/, viewAccount);
async function viewAccount() {
  shell('account', [pageHead('My account', 'Sign-in details for this console'), h('div', { class: 'grid two', id: 'acct' })]);
  const nu = h('input', { type: 'text', autocomplete: 'username', value: S.user || '', maxlength: '40' }), pw1 = h('input', { type: 'password', autocomplete: 'current-password' });
  const cur = h('input', { type: 'password', autocomplete: 'current-password' }), n1 = h('input', { type: 'password', autocomplete: 'new-password' }), n2 = h('input', { type: 'password', autocomplete: 'new-password' });
  setTimeout(drawTotp, 0);
  clear($('#acct')).append(
    h('div', { class: 'stack' },
      panel('Username', 'The name you sign in with', null, h('div', { class: 'stack' },
        h('label', { class: 'field' }, h('span', null, 'Username'), nu),
        h('label', { class: 'field' }, h('span', null, 'Current password'), pw1),
        h('div', null, actionButton('Change username', async () => {
          const r = await api('POST', '/api/account/username', { newUser: nu.value, password: pw1.value });
          S.user = r.user; pw1.value = ''; toast('Username changed. Use it next time you sign in.', 'ok'); viewAccount();
        }, 'primary')))),
      panel('Password', 'At least 12 characters. Other sessions are signed out.', null, h('div', { class: 'stack' },
        h('label', { class: 'field' }, h('span', null, 'Current password'), cur),
        h('label', { class: 'field' }, h('span', null, 'New password'), n1),
        h('label', { class: 'field' }, h('span', null, 'Repeat new password'), n2),
        h('div', null, actionButton('Change password', async () => {
          if (n1.value !== n2.value) throw new Error('The new passwords do not match.');
          await api('POST', '/api/account/password', { current: cur.value, new: n1.value });
          cur.value = n1.value = n2.value = ''; toast('Password changed.', 'ok');
        }, 'primary'))))),
    h('div', { class: 'stack' },
      panel('Two-step verification', 'Authenticator app', null, h('div', { class: 'stack' }, h('div', { id: 'totp-box' }, h('span', { class: 'spinner' })))),
      S.role !== 'viewer' && S.user ? usersPanel() : null,
      panel('Session', null, null, h('div', { class: 'row spread' }, h('span', null, 'Signed in as ', h('b', null, S.user)), h('button', { onclick: logout }, 'Sign out')))));
}

async function drawTotp() {
  const box = $('#totp-box');
  if (!box) return;
  const me = await api('GET', '/api/me');
  const pw = h('input', { type: 'password', autocomplete: 'current-password', placeholder: 'Current password' });
  const setup = h('div', { class: 'stack' });
  const code2 = h('input', { type: 'text', inputMode: 'numeric', maxLength: 6, autocomplete: 'one-time-code', placeholder: 'Current 6-digit code', style: { width: '12em' } });
  const startBtn = actionButton(me.totp ? 'Replace authenticator…' : 'Turn on two-step verification', async () => {
    const r = await api('POST', '/api/account/2fa/begin', { password: pw.value, code: code2.value });
    const code = h('input', { type: 'text', inputMode: 'numeric', maxLength: 6, autocomplete: 'one-time-code', placeholder: '6-digit code', style: { width: '10em' } });
    const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
    svg.setAttribute('viewBox', `-3 -3 ${r.qr.size + 6} ${r.qr.size + 6}`); svg.setAttribute('class', 'qr'); svg.setAttribute('shape-rendering', 'crispEdges');
    const bg = document.createElementNS('http://www.w3.org/2000/svg', 'rect'); bg.setAttribute('x', -3); bg.setAttribute('y', -3); bg.setAttribute('width', r.qr.size + 6); bg.setAttribute('height', r.qr.size + 6); bg.setAttribute('fill', '#fff');
    const path = document.createElementNS('http://www.w3.org/2000/svg', 'path'); path.setAttribute('d', r.qr.d); path.setAttribute('fill', '#000');
    svg.append(bg, path);
    clear(setup).append(h('div', { class: 'row', style: { alignItems: 'flex-start', gap: '20px' } }, svg,
      h('div', { class: 'stack', style: { flex: 1 } },
        h('p', { class: 'muted' }, '1. Scan this code with Google Authenticator, Microsoft Authenticator, Authy or 1Password.'),
        h('p', { class: 'muted small-text' }, 'Using a password manager (1Password, Bitwarden, Proton Pass, Apple Passwords)? Save this key as the one-time password for Helm: ', h('code', null, r.secret.replace(/(.{4})/g, '$1 ').trim())),
        h('div', { class: 'row' }, copyButton(() => r.secret, 'Copy key'), copyButton(() => r.uri, 'Copy setup link'), h('a', { class: 'btn small', href: r.uri }, 'Open in authenticator app')),
        h('p', { class: 'muted' }, '2. Type the 6-digit code it shows to finish.'), code,
        actionButton('Confirm and activate', async () => { await api('POST', '/api/account/2fa/confirm', { code: code.value }); toast('Authenticator activated. Other sessions were signed out.', 'ok'); drawTotp(); }, 'primary'))));
  }, 'primary');
  clear(box).append(h('div', { class: 'stack' },
    h('div', { class: 'row' }, h('span', { class: 'chip ' + (me.totp ? 'ok' : 'warn') }, me.totp ? 'On' : 'Off'),
      h('span', { class: 'muted' }, me.totp ? 'Sign-in and sensitive changes need a code from your authenticator.' : 'Anyone with your password can sign in. Turn this on.')),
    h('label', { class: 'field' }, h('span', null, 'Your password (needed to change this)'), pw),
    me.totp ? h('label', { class: 'field' }, h('span', null, 'Current authenticator code (needed to replace or turn off)'), code2) : null,
    h('div', { class: 'row' }, startBtn,
      me.totp ? actionButton('Turn off', async () => {
        if (!await confirmDialog('Turn off two-step verification? Your password alone will then be enough to sign in. This is not recommended.', 'Turn off', true)) return;
        await api('POST', '/api/account/2fa/disable', { password: pw.value, code: code2.value }); toast('Two-step verification is off.', 'ok'); drawTotp();
      }, 'danger') : null),
    setup));
}



// ---------- console users (owner manages; everyone can see the panel only if they are the owner) ----------
function usersPanel() {
  const box = h('div', { class: 'stack' }, h('span', { class: 'spinner' }));
  const pan = panel('Console users', 'Admins can change anything. Viewers can look but not change.', null, box);
  const keyCard = u => {
    const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
    svg.setAttribute('viewBox', `-3 -3 ${u.qr.size + 6} ${u.qr.size + 6}`); svg.setAttribute('class', 'qr'); svg.setAttribute('shape-rendering', 'crispEdges');
    const bg = document.createElementNS('http://www.w3.org/2000/svg', 'rect'); bg.setAttribute('x', -3); bg.setAttribute('y', -3); bg.setAttribute('width', u.qr.size + 6); bg.setAttribute('height', u.qr.size + 6); bg.setAttribute('fill', '#fff');
    const path = document.createElementNS('http://www.w3.org/2000/svg', 'path'); path.setAttribute('d', u.qr.d); path.setAttribute('fill', '#000');
    svg.append(bg, path);
    return h('div', { class: 'row', style: { alignItems: 'flex-start', gap: '20px', padding: '12px', border: '1px solid var(--line2)' } }, svg,
      h('div', { class: 'stack', style: { flex: 1 } }, h('b', null, 'Give ' + u.user + ' their authenticator key now. It is shown once.'),
        h('code', null, u.secret.replace(/(.{4})/g, '$1 ').trim()),
        h('div', { class: 'row' }, copyButton(() => u.secret, 'Copy key'), copyButton(() => u.uri, 'Copy setup link'))));
  };
  const load = async (card) => {
    let r;
    try { r = await api('GET', '/api/users'); } catch (e) { pan.remove(); return; }
    if (!r.canManage) { clear(box).append(h('div', { class: 'muted' }, 'Only the owner can add or remove users.'), ...r.users.map(u => h('div', null, u.user + ' · ' + u.role))); return; }
    const nu = h('input', { type: 'text', placeholder: 'Username', autocomplete: 'off' });
    const np = h('input', { type: 'password', placeholder: 'Starting password', autocomplete: 'new-password' });
    const nr = h('select', null, h('option', { value: 'admin' }, 'Admin'), h('option', { value: 'viewer' }, 'Viewer (read only)'));
    const shown = h('div');
    const rows = r.users.map(u => h('tr', null, h('td', null, u.user, u.owner ? h('span', { class: 'badge', style: { marginLeft: '6px' } }, 'owner') : null),
      h('td', null, u.role), h('td', null, u.totp ? 'on' : 'off'),
      h('td', { class: 'right' }, u.owner ? '' : h('span', { class: 'row' },
        actionButton('Reset sign-in', async () => {
          const pw = prompt('New temporary password for ' + u.user + ' (12+ characters):');
          if (!pw) return;
          const k = await api('POST', '/api/users/reset', { user: u.user, password: pw });
          load(keyCard(k));
        }),
        actionButton('Remove', async () => {
          if (!await confirmDialog('Remove ' + u.user + '? They are signed out immediately.', 'Remove', true)) return;
          await api('POST', '/api/users/remove', { user: u.user }); toast('User removed.', 'ok'); load();
        }, 'danger')))));
    clear(box).append(table(['User', 'Access', 'Authenticator', ''].map(x => ({ label: x })), rows),
      h('div', { class: 'row' }, nu, np, nr, actionButton('Add user', async () => {
        const k = await api('POST', '/api/users', { user: nu.value, password: np.value, role: nr.value });
        nu.value = np.value = ''; load(keyCard(k));
      }, 'primary')), shown);
    if (card) shown.append(card);
  };
  load();
  return pan;
}


// ---------- network scan and remote install ----------
route(/^\/network$/, viewNetwork);
async function viewNetwork() {
  const out = h('div', { class: 'panel flush' }, h('div', { class: 'muted', style: { padding: '16px 18px' } }, 'Pick where to scan from, then scan. Helm lists the devices that answer and which ones already run Helm.'));
  const bar = h('div', { class: 'row' }, h('span', { class: 'spinner' }));
  shell('network', [pageHead('Network', 'Find PCs on a network and put Helm on them'), h('div', { class: 'panel' }, bar), out]);
  let info;
  try { info = await api('GET', '/api/network/sources'); } catch (e) { clear(bar).append('Could not load: ' + e.message); return; }
  const src = h('select', null, info.sources.map(s => h('option', { value: s.id }, s.server ? s.name : s.name + ' (a PC on that network)')));
  const cidr = h('select');
  const fill = () => { const s = info.sources.find(x => x.id === src.value); clear(cidr).append((s ? s.cidrs : []).map(c => h('option', { value: c }, c))); };
  src.addEventListener('change', fill); fill();
  const windows = () => info.sources.filter(s => !s.server && s.os === 'windows');
  const drawHosts = res => {
    clear(out);
    if (!res.hosts.length) { out.append(h('div', { class: 'muted', style: { padding: '16px 18px' } }, 'Nothing answered on ' + res.cidr + '.')); return; }
    const rows = res.hosts.map(x => {
      const kind = { windows: 'Windows PC', linux: 'Linux or Mac', other: 'Other device' }[x.kind];
      const status = x.managed ? h('a', { href: '#/devices/' + x.managed }, 'Managed · ' + (x.managedName || '')) : h('span', { class: 'muted' }, 'Not managed');
      let act = '';
      if (!x.managed && x.kind === 'windows') act = h('button', { class: 'small', onclick: () => installDialog(x) }, 'Install Helm…');
      else if (!x.managed && x.kind === 'linux') act = h('span', { class: 'muted small-text' }, 'Install from Add a PC');
      return h('tr', null, h('td', { class: 'mono' }, x.ip), h('td', null, x.name || ''), h('td', { class: 'mono' }, x.mac || ''), h('td', null, kind), h('td', { class: 'mono muted' }, (x.ports || []).join(' ')), h('td', null, status), h('td', { class: 'right' }, act));
    });
    out.append(h('div', { class: 'muted', style: { padding: '10px 18px' } }, res.hosts.length + ' devices on ' + res.cidr + ' · ' + fmtTime(res.at)),
      table(['Address', 'Name', 'MAC', 'Looks like', 'Open ports', 'Status', ''].map(x => ({ label: x })), rows));
  };
  const installDialog = async x => {
    const wins = windows();
    if (!wins.length) { toast('No online Windows PC with Helm is on that network to run the install.', 'bad'); return; }
    const user = h('input', { type: 'text', placeholder: 'Administrator account of that PC', autocomplete: 'off' });
    const pw = h('input', { type: 'password', placeholder: 'Its password', autocomplete: 'off' });
    const relay = h('select', null, wins.map(s => h('option', { value: s.id }, s.name)));
    const body = h('div', { class: 'stack' },
      h('p', null, 'Install Helm on ', h('b', null, x.ip + (x.name ? ' (' + x.name + ')' : '')), '. The account and password are used once and are not saved.'),
      h('label', { class: 'field' }, h('span', null, 'Do the install from'), relay), h('label', { class: 'field' }, h('span', null, 'User'), user), h('label', { class: 'field' }, h('span', null, 'Password'), pw),
      x.winrm ? null : h('p', { class: 'muted small-text' }, 'This PC does not accept remote PowerShell yet (port 5985 is closed). On it, run once in an administrator PowerShell: Enable-PSRemoting -Force'),
      h('p', { class: 'muted small-text' }, 'The new PC appears under Devices waiting for your approval.'));
    const ok = await modal('Install Helm', body, [{ label: 'Cancel', value: false }, { label: 'Install', value: true, cls: 'primary' }]);
    if (!ok) return;
    try {
      const r = await api('POST', '/api/network/install', { host: x.ip, user: user.value, password: pw.value, relay: relay.value });
      toast('Installing. Watch progress on the Activity page.', 'ok');
      location.hash = '#/activity';
    } catch (e) { toast(e.message, 'bad'); }
  };
  const go = actionButton('Scan', async () => {
    clear(out).append(h('div', { style: { padding: '16px 18px' } }, h('span', { class: 'spinner' }), ' Scanning ' + cidr.value + '. This takes up to a minute.'));
    try { drawHosts(await api('POST', '/api/network/scan', { source: src.value, cidr: cidr.value })); }
    catch (e) { clear(out).append(h('div', { style: { padding: '16px 18px' } }, 'Scan failed: ' + e.message)); }
  }, 'primary');
  clear(bar).append(h('label', null, 'Scan from ', src), h('label', null, 'Network ', cidr), go);
  if (!info.sources.length) clear(bar).append(h('span', { class: 'muted' }, 'No online PC or server network to scan from.'));
  if (info.last) drawHosts(info.last);
}
