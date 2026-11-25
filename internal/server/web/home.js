'use strict';
/* Helm console: Home. It answers one question, "what needs me right now?", and puts the fix next to each answer. */

// One square per PC, lowest security score first. The square is Helm's signature: the same cell is used in lists.
function fleetCells(devs) {
  const list = devs.filter(d => d.approved).sort((x, y) => ((x.security && x.security.hasData ? x.security.score : 101) - (y.security && y.security.hasData ? y.security.score : 101)));
  const cls = d => { const s = d.security; return !s || !s.hasData || s.score == null ? 'none' : s.score >= 80 ? 'good' : s.score >= 50 ? 'fair' : 'poor'; };
  const cells = list.map(d => {
    const s = d.security, has = s && s.hasData && s.score != null;
    return h('a', { class: 'cell ' + cls(d) + (d.online ? '' : ' off'), href: '#/d/' + d.id, title: d.name + ' · ' + (has ? 'security score ' + s.score : 'not scanned') + ' · ' + (d.online ? 'online' : 'offline') }, has ? String(s.score) : '');
  });
  const key = (c, t, off) => h('span', null, h('i', { class: off ? 'off' : '', style: { '--c': c } }), t);
  return h('div', { class: 'fleet' }, h('div', { class: 'cells' }, cells),
    list.length ? h('div', { class: 'key' }, key('var(--ok)', '80 or more'), key('var(--sev-m)', '50 to 79'), key('var(--bad)', 'Under 50'), key('var(--line3)', 'Not scanned'), key('var(--text2)', 'Offline', true)) : null);
}

route(/^\/$/, viewDashboard);
async function viewDashboard() {
  const now = new Date();
  const lead = h('div', { class: 'lead' });
  const host = h('div', null, h('span', { class: 'spinner' }));
  shell('dashboard', [h('div', { class: 'today' }, h('div', { class: 'todaydate' }, now.toLocaleDateString([], { weekday: 'long', day: 'numeric', month: 'long' })), lead), host]);
  const my = routeToken;
  const draw = async () => {
    let d, devs = [], chat = { conversations: [] };
    try { [d, devs] = await Promise.all([api('GET', '/api/dashboard'), getDevices(true)]); } catch (e) { clear(host).append('Could not load: ' + e.message); return; }
    try { chat = await api('GET', '/api/chat'); } catch (e) { /* optional */ }
    if (my !== routeToken) return;
    const work = [];
    for (const c of chat.conversations || []) if (c.unread) work.push({ rank: 2, tone: 'info', title: c.name + ' wrote to you', detail: c.last.text, acts: [h('a', { class: 'btn small primary', href: '#/inbox/' + c.deviceId }, 'Reply')], when: c.last.at });
    for (const p of devs.filter(x => !x.approved)) work.push({ rank: 2, tone: 'warn', title: p.name + ' is waiting for approval', detail: 'Enrolled via "' + (p.via || '?') + '" from ' + p.lastIp,
      acts: [actionButton('Approve', async () => { await api('POST', `/api/devices/${p.id}/approve`, {}); toast('Approved ' + p.name, 'ok'); S.devices = null; draw(); }, 'small primary'), h('a', { class: 'btn small', href: '#/devices' }, 'Review')] });
    for (const a of d.alerts) work.push({ rank: a.severity === 'critical' ? 4 : a.severity === 'warning' ? 3 : 1, tone: a.severity === 'critical' ? 'bad' : a.severity === 'warning' ? 'warn' : 'info', title: a.title,
      detail: [a.deviceName, fmtAgo(a.opened)].filter(Boolean).join(' · '), when: a.opened,
      acts: [a.deviceId ? h('a', { class: 'btn small', href: '#/d/' + a.deviceId }, 'Open PC') : null, actionButton('Dismiss', async () => { await api('POST', `/api/alerts/${a.id}/ack`, {}); draw(); refreshAlertCount(); }, 'small ghost')] });
    work.sort((x, y) => y.rank - x.rank || new Date(y.when || 0) - new Date(x.when || 0));
    const urgent = work.filter(w => w.tone === 'bad').length;
    clear(lead).append(
      d.total === 0 ? h('h1', null, 'Add your first PC.') : work.length ? h('h1', null, h('span', { class: 'sdot ' + (urgent ? 'bad' : 'warn') }), work.length === 1 ? 'One thing needs you.' : work.length + ' things need you.') : h('h1', null, h('span', { class: 'sdot ok' }), 'Nothing needs you.'),
      h('p', { class: 'leadsub' }, d.total ? [plural(d.total, 'PC'), d.online + ' online', d.scored ? 'average security score ' + d.avgScore : 'not scanned yet'].join(' · ') + (urgent ? '. ' + urgent + ' urgent.' : '.') : 'Create an enrollment token, install the agent on a PC, and this page shows how the fleet is doing.'),
      h('div', { class: 'row', style: { marginTop: '14px' } }, d.total ? actionButton('Scan all PCs', async () => { const r = await api('POST', '/api/run/scan', { target: { all: true } }); toast('Scanning ' + plural(r.results.length, 'PC'), 'ok'); }) : h('a', { class: 'btn primary', href: '#/enroll' }, icon('download'), 'Download agent'),
        d.scored ? h('a', { class: 'btn', href: '#/security' }, 'Review findings') : null));
    const runs = d.runs || [];
    const groups = Object.entries(d.groups).sort((a, b) => b[1] - a[1]), oses = Object.entries(d.os).sort((a, b) => b[1] - a[1]);
    clear(host).append(
      cveNotice(d.cve) ? h('div', { style: { marginBottom: '18px' } }, cveNotice(d.cve)) : null,
      work.length ? h('section', { class: 'sec' }, h('h2', null, 'Needs you'), h('div', { class: 'work' }, work.map(w => h('div', { class: 'wrow ' + w.tone },
        h('span', { class: 'edge' }), h('div', { class: 'wmain' }, h('b', null, w.title), w.detail ? h('span', { class: 'muted small-text' }, w.detail) : null), h('div', { class: 'wacts' }, w.acts)))),
        d.lowDisks.length ? h('p', { class: 'muted small-text', style: { marginTop: '10px' } }, plural(d.lowDisks.length, 'drive') + ' under 15% free: ' + d.lowDisks.slice(0, 4).map(x => (x.name || '') + (x.drive ? ' ' + x.drive : '')).filter(Boolean).join(', ')) : null) : null,
      d.total ? h('section', { class: 'sec' }, h('h2', null, 'Fleet', h('small', null, 'lowest security score first')), fleetCells(devs)) : null,
      h('div', { class: 'cols' },
        h('section', { class: 'sec' }, h('h2', null, 'Recent activity', h('a', { href: '#/automation/runs' }, 'All runs')),
          runs.length ? h('div', { class: 'feed' }, runs.slice(0, 7).map(r => h('a', { class: 'feeditem', href: '#/automation/runs' }, h('span', { class: 'fwhen' }, fmtAgo(r.started)), h('span', { class: 'ftitle' }, r.title), h('span', { class: 'badge ' + (r.status === 'done' ? 'done' : 'running') }, r.status)))) : h('p', { class: 'muted' }, 'Nothing has run yet.')),
        h('section', { class: 'sec' }, h('h2', null, 'Makeup'),
          h('div', { class: 'makeup' }, h('div', null, h('h4', null, 'Groups'), groups.length ? hbars(groups.map(([k, v]) => ({ label: k, v }))) : h('p', { class: 'muted' }, 'No groups yet')),
            h('div', null, h('h4', null, 'Systems'), oses.length ? hbars(oses.map(([k, v]) => ({ label: k, v, color: 'var(--text2)' }))) : h('p', { class: 'muted' }, 'No data yet'))))));
  };
  // a render error must never leave the page spinning
  const safe = () => draw().catch(e => { clear(host).append(h('div', { class: 'notice bad' }, 'Could not draw this page: ' + e.message)); });
  safe(); every(15000, safe);
}
