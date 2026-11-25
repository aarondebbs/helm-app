'use strict';
/* Helm admin UI: device detail view (loaded after app.js). */

const TABS = [['overview', 'Overview'], ['screen', 'Remote screen'], ['files', 'Files'], ['chat', 'Chat'], ['updates', 'Updates'], ['security', 'Security'], ['software', 'Software'],
  ['processes', 'Processes'], ['services', 'Services'], ['terminal', 'Terminal'], ['events', 'Event logs'], ['tools', 'Tools'], ['jobs', 'History']];
const isLinux = d => !!(d && d.hello && (d.hello.os === 'linux' || d.hello.os === 'darwin')); // no remote screen, Logs instead of Event logs
const tabsFor = d => TABS.filter(([k]) => !(isLinux(d) && k === 'screen')).map(([k, l]) => [k, isLinux(d) && k === 'events' ? 'Logs' : l]);

route(/^\/d\/([^/]+)(?:\/([a-z]+))?$/, viewDevice);

async function viewDevice(id, tab) {
  tab = tab || 'overview';
  const my = routeToken;
  const host = h('div', null, h('span', { class: 'spinner' }));
  shell('devices', host);
  let dev;
  try { dev = await api('GET', '/api/devices/' + id); } catch (e) { clear(host).append('Could not load device: ' + e.message); return; }
  if (my !== routeToken) return;

  const body = h('div');
  const head = h('div');
  const drawHead = () => {
    clear(head).append(
      h('div', { class: 'pagehead', style: { marginBottom: '8px' } },
        h('div', null, h('a', { href: '#/devices', class: 'crumb' }, '← PCs'),
          h('div', { class: 'row' }, h('h1', { style: { margin: 0 } }, dev.name), deviceChip(dev), scoreBadge(dev.security)),
          h('div', { class: 'row tight', style: { marginTop: '6px' } }, dev.group ? h('span', { class: 'tag group' }, dev.group) : null, tagNodes(dev.tags),
            h('span', { class: 'muted' }, [osText(dev), dev.online && dev.stats && dev.stats.user ? '👤 ' + dev.stats.user + (dev.stats.userPresent ? '' : ' (not at the PC)') : ''].filter(Boolean).join(' · ')))),
        h('div', { class: 'row' },
          dev.approved ? h('button', { onclick: async () => { if (await groupDialog([dev])) { dev = await api('GET', '/api/devices/' + id); drawHead(); } } }, 'Group & tags') : null,
          dev.approved && dev.online ? actionButton('Scan now', async () => { await api('POST', `/api/devices/${id}/scan`, {}); toast('Security scan started', 'ok'); location.hash = `#/d/${id}/security`; }) : null,
          !dev.approved ? actionButton('Approve', async () => { await api('POST', `/api/devices/${id}/approve`, {}); dev = await api('GET', '/api/devices/' + id); drawHead(); drawBody(); }, 'primary') : null)),
      !dev.online && dev.approved ? h('div', { class: 'notice warn', style: { marginTop: '10px' } }, 'This PC is offline (last seen ' + fmtAgo(dev.lastSeen) + '). Commands are available again when it reconnects.') : null,
      h('div', { class: 'tabs' }, tabsFor(dev).map(([k, l]) => h('a', { href: `#/d/${id}/${k}`, class: tab === k ? 'active' : '' }, l))));
  };
  const drawBody = () => {
    clear(body);
    if (!dev.approved) { body.append(h('div', { class: 'panel' }, 'Approve this PC to manage it. Enrolled via "' + dev.via + '" from ' + dev.lastIp + '.')); return; }
    const fn = { overview: tabOverview, updates: tabUpdates, processes: tabProcesses, services: tabServices, terminal: tabTerminal,
      files: tabFiles, chat: tabChat, screen: tabScreen, events: tabEvents, tools: tabTools, jobs: tabJobs, security: tabSecurity, software: tabSoftware }[tab];
    if (!fn) { body.append('Unknown tab'); return; }
    fn(body, dev, id);
  };
  clear(host).append(head, body);
  drawHead(); drawBody();

  // keep the header's online state fresh without redrawing the active tab
  const t = setInterval(async () => {
    try {
      const d = await api('GET', '/api/devices/' + id);
      const flip = d.online !== dev.online || d.approved !== dev.approved;
      dev = d; if (flip) drawHead();
    } catch (e) { /* ignore */ }
  }, 6000);
  onLeave(() => clearInterval(t));
}

// ---------- shared bits ----------
function needOnline(dev, body) {
  if (dev.online) return true;
  body.append(h('div', { class: 'panel muted' }, 'This PC is offline.'));
  return false;
}
function filterBox(onInput) { const i = h('input', { type: 'search', placeholder: 'Filter…' }); i.addEventListener('input', () => onInput(i.value.toLowerCase())); return i; }
function jobProgress(el) { return job => { el.textContent = (job.progress || []).slice(-6).join('\n'); }; }
function renderTree(obj) {
  const dl = h('dl', { class: 'kv' });
  const walk = (o, prefix) => {
    for (const [k, v] of Object.entries(o)) {
      const key = prefix + k;
      if (v && typeof v === 'object' && !Array.isArray(v)) { walk(v, key + ' › '); continue; }
      let s;
      if (Array.isArray(v)) s = v.map(x => typeof x === 'object' ? JSON.stringify(x) : String(x)).join('\n'); else s = v == null ? '–' : String(v);
      dl.append(h('dt', null, key), h('dd', { style: { whiteSpace: 'pre-wrap' } }, s));
    }
  };
  walk(obj, ''); return dl;
}

// ---------- overview ----------
// Readable hardware/OS summary of an inventory result (falls back to a raw tree for unexpected shapes).
function renderInventory(m) {
  if (!m || typeof m !== 'object' || m.computerName === undefined) return renderTree(m || {});
  const gb = n => n ? (n / 1073741824).toFixed(n >= 10 * 1073741824 ? 0 : 1) + ' GB' : '';
  const kv = rows => h('dl', { class: 'kv' }, rows.filter(r => r[1] != null && r[1] !== '' && r[1] !== false).map(([k, v]) => [h('dt', null, k), h('dd', null, v)]));
  const sec = (title, node) => h('div', null, h('h4', { style: { color: 'var(--muted)', borderBottom: '1px solid var(--line)', paddingBottom: '4px' } }, title), node);
  const list = (items, fmt) => items && items.length ? h('div', { class: 'stack', style: { gap: '6px' } }, items.map(x => h('div', null, fmt(x)))) : h('span', { class: 'muted' }, 'None reported');
  const fw = (m.firewall || []).map(f => f.name + (f.enabled ? ' (on)' : ' (off)')).join(', ');
  return h('div', { class: 'grid', style: { gridTemplateColumns: 'repeat(auto-fit, minmax(300px, 1fr))', gap: '22px' } },
    sec('System', kv([['Computer', m.computerName], ['Manufacturer', m.manufacturer], ['Model', m.model], ['Serial number', m.serial], ['Firmware', m.biosVersion],
      ['Operating system', [m.osCaption, m.osVersion && !String(m.osCaption || '').includes(m.osVersion) ? m.osVersion : '', m.osBuild ? '(' + m.osBuild + ')' : ''].filter(Boolean).join(' ')], ['Architecture', m.osArch],
      ['Domain', m.partOfDomain ? m.domain : ''], ['Time zone', m.timezone], ['Last boot', m.lastBoot ? fmtTime(m.lastBoot) : ''], ['Restart pending', m.pendingReboot ? 'Yes' : ''], ['Firewall', fw]])),
    sec('Processor and memory', kv([['Processor', m.cpu], ['Cores / threads', m.cores ? m.cores + (m.threads ? ' / ' + m.threads : '') : ''], ['Memory', gb(m.ramBytes)], ['Graphics', (m.gpu || []).join(', ')],
      ['Antivirus', (m.antivirus || []).join(', ')]])),
    sec('Storage', list(m.disks, x => [h('b', null, x.model || 'Disk'), x.sizeBytes ? ' · ' + gb(x.sizeBytes) : ''])),
    sec('Network', list(m.network, x => [h('b', null, x.description || 'Adapter'), h('div', { class: 'muted small-text' }, [x.mac, (x.ips || []).join(', ')].filter(Boolean).join(' · '))])));
}
function tabOverview(body, dev, id) {
  const hello = dev.hello || {}, st = dev.stats;
  const inv = h('div', null, h('span', { class: 'spinner' }));
  const showInv = (data, at) => clear(inv).append(h('p', { class: 'muted small-text' }, 'Collected ' + fmtAgo(at) + (dev.online ? '' : ' (PC offline; showing the last stored copy)') + '. Refreshed automatically every day.'),
    data && data.pendingReboot ? h('div', { class: 'notice warn', style: { display: 'flex', gap: '12px', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap' } }, h('span', null, 'A restart is pending. Some updates are not active until this PC restarts.'),
      dev.online ? actionButton('Restart in 1 minute', async () => { if (!(await confirmDialog(`Restart ${dev.name} in 1 minute? The person using it will see a warning.`, 'Restart', true))) return; await runCmd(id, 'power', { action: 'restart', delay: 60, message: 'Helm: restarting to finish installing updates' }, { wait: 30 }); toast('Restart scheduled', 'ok'); }, 'danger') : null) : null,
    renderInventory(data || {}));
  api('GET', `/api/devices/${id}/inventory`).then(r => { if (r && r.data) showInv(r.data, r.at); else clear(inv).append(h('p', { class: 'muted' }, dev.online ? 'Not collected yet. It is gathered automatically, or press "Collect full inventory".' : 'No inventory stored yet. It is collected when the PC is online.')); }).catch(() => clear(inv).append(h('p', { class: 'muted' }, 'Could not load the stored inventory.')));
  const invBtn = actionButton('Collect full inventory', async () => {
    clear(inv).append(h('span', { class: 'spinner' }));
    try { const r = await runCmd(id, 'inventory', {}, { wait: 60 }); showInv(r, new Date().toISOString()); }
    catch (e) { clear(inv).append(h('div', { class: 'notice bad' }, e.message)); throw e; }
  });
  const power = (label, args, danger, msg) => actionButton(label, async () => {
    if (!(await confirmDialog(msg || `${label} ${dev.name}?`, label, danger))) return;
    await runCmd(id, 'power', args, { wait: 30 }); toast(label + ' sent', 'ok');
  }, danger ? 'danger' : '');
  const delay = h('select', null, [[0, 'now'], [30, 'in 30 seconds'], [60, 'in 1 minute'], [300, 'in 5 minutes']].map(([v, l]) => h('option', { value: v, selected: v === 30 }, l)));
  const pmsg = h('input', { type: 'text', placeholder: 'Message shown to the user (optional)', maxLength: 120, style: { minWidth: '16em' } });
  const force = h('input', { type: 'checkbox' });
  const pa = (a, extra) => Object.assign({ action: a, delay: Number(delay.value), message: pmsg.value, force: force.checked }, extra || {});
  const notes = h('textarea', { rows: 3, style: { width: '100%' }, maxLength: 2000 }, dev.notes || '');
  const name = h('input', { type: 'text', value: dev.name, maxLength: 80 });
  const group = h('input', { type: 'text', value: dev.group || '', maxLength: 40, placeholder: 'e.g. Reception' });
  const tagsIn = h('input', { type: 'text', value: (dev.tags || []).join(', '), placeholder: 'laptop, vip' });
  const perf = h('div');

  body.append(
    h('div', { class: 'grid', style: { gridTemplateColumns: 'repeat(auto-fit, minmax(340px, 1fr))' } },
      h('div', { class: 'panel' }, h('h3', null, 'Status'), h('dl', { class: 'kv' },
        h('dt', null, hello.os === 'linux' || hello.os === 'darwin' ? 'Operating system' : 'Windows'), h('dd', null, [hello.osVersion, hello.edition].filter(Boolean).join(' · ') || '–'),
        h('dt', null, 'Make and model'), h('dd', null, makeText(dev) || '–'),
        h('dt', null, 'Architecture'), h('dd', null, hello.arch || '–'),
        h('dt', null, 'Agent'), h('dd', null, hello.version || '–'),
        h('dt', null, 'Addresses'), h('dd', null, (hello.ips || []).join(', ') || '–'),
        h('dt', null, 'MAC'), h('dd', null, (hello.macs || []).join(', ') || '–'),
        h('dt', null, 'Remote screen'), h('dd', null, { prompt_if_present: 'Asks first if someone is signed in', always_prompt: 'Always asks first', unattended: 'Unattended (no prompt)' }[hello.consentMode] || hello.consentMode || '–'),
        h('dt', null, 'Uptime'), h('dd', null, st ? fmtDur(st.uptimeSec) : '–'),
        h('dt', null, 'CPU'), h('dd', null, st ? Math.round(st.cpu) + '%' : '–'),
        h('dt', null, 'Memory'), h('dd', null, st ? `${fmtBytes(st.memUsed)} of ${fmtBytes(st.memTotal)}` : '–'),
        h('dt', null, 'Disks'), h('dd', null, st && st.disks ? st.disks.map(d => `${d.name} ${fmtBytes(d.free)} free of ${fmtBytes(d.total)}`).join('\n') : '–'),
        h('dt', null, 'Enrolled'), h('dd', null, fmtTime(dev.createdAt) + ' via "' + dev.via + '"'))),
      h('div', { class: 'panel stack' }, h('h3', null, 'Power'),
        dev.online ? [
          h('div', { class: 'row' }, h('label', null, 'When: ', delay), pmsg, h('label', null, force, ' Force apps closed')),
          h('div', { class: 'row' }, power('Restart', pa('restart'), true), power('Shut down', pa('shutdown'), true),
            power('Cancel pending', { action: 'cancel' }, false), power('Lock', { action: 'lock' }, false),
            power('Sleep', { action: 'sleep' }, true), power('Hibernate', { action: 'hibernate' }, true), power('Sign out user', pa('logoff'), true))
        ] : [h('p', { class: 'muted' }, 'The PC is offline.'),
          dev.hello && (dev.hello.macs || []).length ? actionButton('Wake it (Wake-on-LAN)', async () => {
            const r = await api('POST', `/api/devices/${id}/wake`, {}); toast(r && r.via ? 'Magic packet sent via ' + r.via : 'Magic packet sent', 'ok');
          }) : null,
          h('p', { class: 'muted' }, 'Wake-on-LAN is relayed through another online PC on the same network and requires the PC to have it enabled in BIOS/adapter settings.')]),
      h('div', { class: 'panel stack' }, h('h3', null, 'Name, group & notes'), h('label', { class: 'field' }, h('span', null, 'Display name'), name),
        h('div', { class: 'row' }, h('label', { class: 'field' }, h('span', null, 'Group'), group), h('label', { class: 'field', style: { flex: 1 } }, h('span', null, 'Tags (comma separated)'), tagsIn)), notes,
        actionButton('Save', async () => { await api('POST', `/api/devices/${id}/edit`, { name: name.value, notes: notes.value, group: group.value, tags: parseTags(tagsIn.value) }); dev.name = name.value.trim(); dev.notes = notes.value; dev.group = group.value.trim(); dev.tags = parseTags(tagsIn.value); S.devices = null; toast('Saved', 'ok'); }))),
    dev.online ? h('div', { class: 'panel', style: { marginTop: '16px' } }, h('div', { class: 'phead' }, h('h3', null, 'Performance'), h('span', { class: 'sub' }, 'Last hour')), perf) : null,
    h('div', { class: 'panel', style: { marginTop: '16px' } }, h('div', { class: 'row spread' }, h('h3', null, 'Hardware inventory'), dev.online ? invBtn : null), inv));
  if (dev.online) {
    const my = routeToken;
    const loadPerf = async () => {
      try {
        const pts = await api('GET', `/api/devices/${id}/history`); if (my !== routeToken) return;
        clear(perf).append(h('div', { class: 'grid two' },
          h('div', { class: 'chart' }, h('div', { class: 'row spread small-text' }, h('b', null, 'CPU'), h('span', { class: 'muted' }, pts.length ? Math.round(pts[pts.length - 1].cpu) + '% now' : '')), sparkline(pts.map(p => p.cpu), { label: 'CPU usage' })),
          h('div', { class: 'chart' }, h('div', { class: 'row spread small-text' }, h('b', null, 'Memory'), h('span', { class: 'muted' }, pts.length ? Math.round(pts[pts.length - 1].mem) + '% now' : '')), sparkline(pts.map(p => p.mem), { label: 'Memory usage', color: 'var(--text2)' }))));
      } catch (e) { /* ignore */ }
    };
    loadPerf(); every(15000, loadPerf);
  }
}

// ---------- updates ----------
function tabUpdates(body, dev, id) {
  if (!needOnline(dev, body)) return;
  const wuBox = h('div'), wgBox = h('div'), log = h('pre', { class: 'out hidden' });
  let busy = false;
  const withLog = async fn => {
    if (busy) { toast('Another update operation is running from this page', 'bad'); return; }
    busy = true; log.classList.remove('hidden'); log.textContent = 'Working… (updates can take many minutes; you can leave this page)';
    try { await fn(); } finally { busy = false; }
  };
  const prog = job => { log.textContent = (job.progress || []).slice(-40).join('\n') || 'Working…'; };

  const unix = isLinux(dev), osName = dev.hello && dev.hello.os === 'darwin' ? 'macOS' : unix ? 'Linux' : 'Windows';
  const checkWU = actionButton(unix ? 'Check for updates' : 'Check for Windows updates', async () => {
    clear(wuBox).append(h('span', { class: 'spinner' }), ' Searching (this can take a few minutes)…');
    try {
      const r = await runCmd(id, 'updates.check', {}, { wait: 25, onProgress: prog });
      const ups = (r && r.updates) || [];
      const sel = new Set(ups.map(u => u.id));
      clear(wuBox).append(
        r && r.rebootPending ? h('div', { class: 'notice warn' }, 'A restart is pending on this PC.') : null,
        ups.length ? [table(unix ? [{ label: '' }, { label: 'Package' }, { label: 'Type' }, { label: 'Restart' }] : [{ label: '' }, { label: 'Update' }, { label: 'KB' }, { label: 'Size', num: true }, { label: 'Severity' }],
          ups.map(u => h('tr', null, h('td', { class: 'checkcell' }, h('input', { type: 'checkbox', checked: true, onchange: e => e.target.checked ? sel.add(u.id) : sel.delete(u.id) })),
            h('td', null, u.title),
            unix ? [h('td', null, (u.categories || [])[0] || ''), h('td', null, u.needsReboot ? 'Likely' : '')]
              : [h('td', null, (u.kb || []).map(k => 'KB' + k).join(' ')), h('td', { class: 'num' }, u.sizeMB + ' MB'), h('td', null, u.severity || '')])))]
          : h('p', null, osName + ' is up to date.'),
        ups.length ? h('div', { class: 'row', style: { marginTop: '10px' } },
          actionButton('Install selected', () => withLog(async () => {
            if (!sel.size) throw new Error('Nothing selected');
            const rr = await runCmd(id, 'updates.install', { ids: [...sel], reboot: false }, { wait: 5, onProgress: prog, keepAlive: true });
            log.textContent = 'Installed ' + (rr && rr.installed) + ' update(s).' + (rr && rr.rebootRequired ? ' A restart is required.' : '');
            toast('Updates finished', 'ok');
          }), 'primary'),
          actionButton('Install selected and restart if needed', () => withLog(async () => {
            if (!sel.size) throw new Error('Nothing selected');
            if (!(await confirmDialog('The PC will restart automatically (after a 60 second warning) if the updates need it.', 'Install', true))) return;
            const rr = await runCmd(id, 'updates.install', { ids: [...sel], reboot: true }, { wait: 5, onProgress: prog, keepAlive: true });
            log.textContent = 'Installed ' + (rr && rr.installed) + ' update(s).' + (rr && rr.rebootRequired ? ' Restarting…' : '');
          }))) : null);
    } catch (e) { clear(wuBox).append(h('div', { class: 'notice bad' }, e.message)); throw e; }
  });

  const mac = dev.hello && dev.hello.os === 'darwin', appTool = mac ? 'Homebrew' : 'winget';
  const checkWG = actionButton('Check for app updates (' + appTool + ')', async () => {
    clear(wgBox).append(h('span', { class: 'spinner' }), ' Checking…');
    try {
      const r = await runCmd(id, 'winget.list', {}, { wait: 25 });
      const pk = (r && r.packages) || [];
      const sel = new Set();
      clear(wgBox).append(pk.length ? [table([{ label: '' }, { label: 'App' }, { label: 'Id' }, { label: 'Installed' }, { label: 'Available' }],
        pk.map(p => h('tr', null, h('td', { class: 'checkcell' }, h('input', { type: 'checkbox', onchange: e => e.target.checked ? sel.add(p.id) : sel.delete(p.id) })),
          h('td', null, p.name), h('td', { class: 'mono' }, p.id), h('td', null, p.version), h('td', null, p.available)))),
        h('div', { class: 'row', style: { marginTop: '10px' } },
          actionButton('Upgrade selected', () => withLog(async () => {
            if (!sel.size) throw new Error('Nothing selected');
            const rr = await runCmd(id, 'winget.upgrade', { ids: [...sel] }, { wait: 5, onProgress: prog, keepAlive: true });
            log.textContent = JSON.stringify(rr && rr.results ? rr.results : rr, null, 1); toast('Upgrade finished', 'ok');
          }), 'primary'),
          actionButton('Upgrade all', () => withLog(async () => {
            if (!(await confirmDialog('Upgrade all ' + pk.length + ' apps? Apps that are open may be closed by their installers.', 'Upgrade all', true))) return;
            const rr = await runCmd(id, 'winget.upgrade', { all: true }, { wait: 5, onProgress: prog, keepAlive: true });
            log.textContent = JSON.stringify(rr && rr.results ? rr.results : rr, null, 1); toast('Upgrade finished', 'ok');
          })))] : h('p', null, 'All ' + appTool + '-managed apps are up to date.'),
      h('p', { class: 'muted' }, mac ? 'Only apps installed with Homebrew appear here. Apple software is under System updates; other apps update themselves.' : 'winget runs as SYSTEM here, so per-user installs may not appear.'));
    } catch (e) { clear(wgBox).append(h('div', { class: 'notice bad' }, e.message)); throw e; }
  });
  body.append(h('div', { class: 'panel' }, h('div', { class: 'row spread' }, h('h3', null, unix ? 'System updates' : 'Windows Update'), checkWU), wuBox),
    unix && !mac ? null : h('div', { class: 'panel' }, h('div', { class: 'row spread' }, h('h3', null, mac ? 'Homebrew apps' : 'Apps'), checkWG), wgBox),
    log);
  if (unix) checkWU.click(); // Linux and macOS have no slow Windows Update agent, so this opens ready
}

// ---------- processes ----------
function tabProcesses(body, dev, id) {
  if (!needOnline(dev, body)) return;
  let rows = [], filt = '', sortKey = 'memMB', desc = true;
  const out = h('div');
  const draw = () => {
    const f = rows.filter(p => !filt || (p.name + ' ' + (p.user || '') + ' ' + (p.path || '')).toLowerCase().includes(filt));
    f.sort((a, b) => { const x = a[sortKey], y = b[sortKey]; const c = typeof x === 'string' || typeof y === 'string' ? String(x || '').localeCompare(String(y || '')) : (x || 0) - (y || 0); return desc ? -c : c; });
    const th = (k, l, num) => h('th', { class: 'sort' + (num ? ' num' : ''), onclick: () => { desc = sortKey === k ? !desc : true; sortKey = k; draw(); } }, l + (sortKey === k ? (desc ? ' ▼' : ' ▲') : ''));
    clear(out).append(h('div', { class: 'tablewrap' }, h('table', null,
      h('thead', null, h('tr', null, th('name', 'Name'), th('pid', 'PID', 1), th('cpu', 'CPU s', 1), th('memMB', 'Memory MB', 1), th('user', 'User'), h('th'))),
      h('tbody', null, f.slice(0, 600).map(p => h('tr', null, h('td', { title: p.path || '' }, p.name), h('td', { class: 'num' }, p.pid), h('td', { class: 'num' }, p.cpu == null ? '' : p.cpu), h('td', { class: 'num' }, p.memMB),
        h('td', null, p.user || ''), h('td', null, actionButton('End', async () => {
          if (!(await confirmDialog(`End ${p.name} (PID ${p.pid})? Unsaved work in it will be lost.`, 'End process', true))) return;
          await runCmd(id, 'process.kill', { pid: p.pid }); toast('Ended ' + p.name, 'ok'); load();
        }, 'danger small'))))))));
  };
  const load = async () => {
    try { rows = (await runCmd(id, 'process.list', {}, { wait: 30 })) || []; draw(); } catch (e) { if (e.message !== 'cancelled') toast(e.message, 'bad'); }
  };
  body.append(h('div', { class: 'panel' }, h('div', { class: 'row spread', style: { marginBottom: '10px' } }, h('h3', null, 'Processes'),
    h('div', { class: 'row' }, filterBox(v => { filt = v; draw(); }), actionButton('Refresh', load))), out));
  clear(out).append(h('span', { class: 'spinner' })); load();
}

// ---------- services ----------
function tabServices(body, dev, id) {
  if (!needOnline(dev, body)) return;
  let rows = [], filt = '', onlyRunning = false;
  const out = h('div');
  const svc = async (name, a) => { await runCmd(id, 'service.control', { name, action: a }, { wait: 60 }); toast(`${name}: ${a} done`, 'ok'); load(); };
  const draw = () => {
    const f = rows.filter(s => (!filt || (s.name + ' ' + (s.display || '')).toLowerCase().includes(filt)) && (!onlyRunning || s.state === 'Running'));
    clear(out).append(table([{ label: 'Name' }, { label: 'Display name' }, { label: 'State' }, { label: 'Startup' }, { label: '' }],
      f.map(s => h('tr', null, h('td', { class: 'mono' }, s.name), h('td', null, s.display), h('td', null, s.state), h('td', null, s.start),
        h('td', null, h('div', { class: 'row', style: { gap: '4px' } },
          s.state === 'Running' ? [actionButton('Restart', () => svc(s.name, 'restart'), 'small'), actionButton('Stop', async () => { if (await confirmDialog('Stop ' + s.name + '?', 'Stop', true)) await svc(s.name, 'stop'); }, 'small danger')]
            : actionButton('Start', () => svc(s.name, 'start'), 'small'),
          h('select', { onchange: async e => { const v = e.target.value; e.target.value = ''; if (v) { try { await svc(s.name, v); } catch (x) { toast(x.message, 'bad'); } } } },
            h('option', { value: '' }, 'Startup…'), h('option', { value: 'auto' }, 'Automatic'), h('option', { value: 'manual' }, 'Manual'), h('option', { value: 'disable' }, 'Disabled'))))))));
  };
  const load = async () => { try { rows = (await runCmd(id, 'service.list', {}, { wait: 30 })) || []; draw(); } catch (e) { if (e.message !== 'cancelled') toast(e.message, 'bad'); } };
  body.append(h('div', { class: 'panel' }, h('div', { class: 'row spread', style: { marginBottom: '10px' } }, h('h3', null, 'Services'),
    h('div', { class: 'row' }, h('label', null, h('input', { type: 'checkbox', onchange: e => { onlyRunning = e.target.checked; draw(); } }), ' Running only'), filterBox(v => { filt = v; draw(); }), actionButton('Refresh', load))), out));
  clear(out).append(h('span', { class: 'spinner' })); load();
}

// ---------- event logs ----------
function tabEvents(body, dev, id) {
  if (!needOnline(dev, body)) return;
  const log = h('select', null, ['System', 'Application', 'Security', 'Setup'].map(x => h('option', null, x)));
  const lvl = h('select', null, [['errors', 'Errors'], ['warnings', 'Errors & warnings'], ['all', 'Everything']].map(([v, l]) => h('option', { value: v, selected: v === 'warnings' }, l)));
  const cnt = h('select', null, [25, 50, 100, 200].map(n => h('option', { value: n, selected: n === 50 }, n + ' entries')));
  const out = h('div');
  const load = actionButton('Load', async () => {
    clear(out).append(h('span', { class: 'spinner' }));
    try {
      const r = (await runCmd(id, 'eventlog', { log: log.value, level: lvl.value, count: Number(cnt.value) }, { wait: 30 })) || [];
      clear(out).append(table([{ label: 'Time' }, { label: 'Level' }, { label: 'Source' }, { label: 'ID', num: true }, { label: 'Message' }],
        r.map(e => h('tr', null, h('td', null, fmtTime(e.time)), h('td', null, e.level), h('td', null, e.provider), h('td', { class: 'num' }, e.id), h('td', { style: { whiteSpace: 'pre-wrap' } }, e.message))), { empty: 'No matching events' }));
    } catch (e) { clear(out).append(h('div', { class: 'notice bad' }, e.message)); throw e; }
  });
  body.append(h('div', { class: 'panel' }, h('div', { class: 'row', style: { marginBottom: '10px' } }, h('h3', { style: { margin: 0 } }, 'Event logs'), log, lvl, cnt, load), out));
}

// ---------- history ----------
async function tabJobs(body, dev, id) {
  const out = h('div', null, h('span', { class: 'spinner' })); body.append(h('div', { class: 'panel' }, h('h3', null, 'Recent commands (since the server started)'), out));
  try {
    const jobs = await api('GET', `/api/devices/${id}/jobs`);
    clear(out).append(table([{ label: 'Started' }, { label: 'Command' }, { label: 'Status' }, { label: 'Result' }],
      jobs.map(j => h('tr', null, h('td', null, fmtTime(j.created)), h('td', { class: 'mono' }, j.name), h('td', null, j.status), h('td', { class: 'mono' }, j.err || (j.progress || []).slice(-1)[0] || ''))), { empty: 'No commands yet' }));
  } catch (e) { clear(out).append(e.message); }
}

// ---------- tools: message, RDP, agent ----------
function tabTools(body, dev, id) {
  if (!needOnline(dev, body)) return;
  const title = h('input', { type: 'text', placeholder: 'Title (optional)', maxLength: 80 });
  const text = h('textarea', { rows: 3, maxLength: 500, placeholder: 'Message to show on the PC', style: { width: '100%' } });
  const rdp = h('div', null, h('span', { class: 'muted' }, 'Loading…'));
  const tun = h('div');
  const loadRdp = async () => {
    try {
      const r = await runCmd(id, 'rdp.status', {}, { wait: 20 });
      clear(rdp).append(h('dl', { class: 'kv' }, h('dt', null, 'Remote Desktop'), h('dd', null, r.supported ? (r.enabled ? 'Enabled' : 'Disabled') : 'Not available on Windows Home'),
        h('dt', null, 'Port'), h('dd', null, r.port), h('dt', null, 'Network Level Auth'), h('dd', null, r.nla ? 'On' : 'Off'), h('dt', null, 'Edition'), h('dd', null, r.edition)),
        r.supported ? h('div', { class: 'row' }, r.enabled ? actionButton('Disable RDP', async () => { await runCmd(id, 'rdp.disable', {}, { wait: 30 }); loadRdp(); }, 'danger') : actionButton('Enable RDP', async () => { await runCmd(id, 'rdp.enable', {}, { wait: 30 }); loadRdp(); })) : null);
    } catch (e) { clear(rdp).append(h('div', { class: 'notice bad' }, e.message)); }
  };
  const mins = h('select', null, [[15, '15 minutes'], [30, '30 minutes'], [60, '1 hour'], [240, '4 hours']].map(([v, l]) => h('option', { value: v, selected: v === 30 }, l)));
  const openTun = actionButton('Open RDP tunnel', async () => {
    const t = await api('POST', `/api/devices/${id}/rdp/open`, { minutes: Number(mins.value) });
    const addr = `${t.bind}:${t.port}`;
    clear(tun).append(h('div', { class: 'notice' }, 'Tunnel open until ' + fmtTime(t.expires) + '. One connection only. Connect your RDP client to: ', h('strong', { class: 'mono' }, addr), ' ', copyButton(() => addr),
      h('p', { class: 'muted' }, 'Sign in with a local administrator account. The tunnel listens on the server\'s ' + t.bind + ' address; reach it over Tailscale or SSH port-forwarding if that is loopback.'),
      h('div', { class: 'row' },
        h('button', { type: 'button', class: 'primary', onclick: () => {
          // A ready-made .rdp file: opens Windows Remote Desktop (or Microsoft Remote Desktop on a Mac) straight at the tunnel.
          const rdpText = ['full address:s:' + addr, 'prompt for credentials:i:1', 'screen mode id:i:1', 'compression:i:1', 'networkautodetect:i:1', 'bandwidthautodetect:i:1', 'connection type:i:7', 'bitmapcachepersistenable:i:1', 'redirectclipboard:i:1', 'audiomode:i:2', ''].join('\r\n');
          const a = h('a', { href: URL.createObjectURL(new Blob([rdpText], { type: 'application/x-rdp' })), download: (dev.name || 'pc').replace(/[^A-Za-z0-9._-]+/g, '-') + '.rdp' });
          document.body.append(a); a.click(); a.remove();
        } }, 'Download .rdp file'),
        actionButton('Close tunnel', async () => { await api('DELETE', '/api/tunnels/' + t.id); clear(tun); }, 'small'))));
  });
  const upd = actionButton('Update agent now', async () => { const r = await runCmd(id, 'agent.update', {}, { wait: 60 }); toast(r && r.message ? r.message : 'Update requested', 'ok'); });
  const uninst = actionButton('Uninstall agent', async () => {
    if (!(await confirmDialog('Uninstall the Helm agent from ' + dev.name + '? You will lose all remote access to it.', 'Uninstall', true))) return;
    await runCmd(id, 'agent.uninstall', {}, { wait: 30 }); toast('Uninstall requested', 'ok');
  }, 'danger');
  body.append(
    h('div', { class: 'panel stack' }, h('h3', null, 'Message the user'), title, text,
      h('div', null, actionButton('Show message', async () => { await runCmd(id, 'msg', { title: title.value, text: text.value }, { wait: 20 }); toast('Message shown', 'ok'); }))),
    h('div', { class: 'panel stack' }, h('h3', null, 'Remote Desktop (RDP)'), h('p', { class: 'muted', style: { margin: 0 } }, 'The fastest way to work on a PC: a real Remote Desktop connection at full speed. Enable it, open a tunnel, then open the .rdp file.'), rdp,
      h('div', { class: 'row' }, h('label', null, 'Tunnel for ', mins), openTun), tun),
    h('div', { class: 'panel stack' }, h('h3', null, 'Agent'), h('p', { class: 'muted' }, 'Version ' + ((dev.hello && dev.hello.version) || '?')), h('div', { class: 'row' }, upd, uninst)));
  loadRdp();
}

// ---------- terminal ----------
function tabTerminal(body, dev, id) {
  if (!needOnline(dev, body)) return;
  const out = h('pre', { class: 'out term' });
  const input = h('input', { type: 'text', style: { flex: 1, fontFamily: 'var(--mono)' }, placeholder: 'Type a command and press Enter', autocomplete: 'off', spellcheck: false, disabled: true });
  const shellSel = h('select', null, h('option', { value: 'powershell' }, 'PowerShell'), h('option', { value: 'cmd' }, 'Command Prompt'));
  const status = h('span', { class: 'muted' }, 'Not connected');
  const hist = []; let hi = 0, ws = null;
  const add = (txt, cls) => { const s = h('span', { class: cls || '' }, txt); out.append(s); if (out.childNodes.length > 4000) out.removeChild(out.firstChild); out.scrollTop = out.scrollHeight; };
  const stop = () => { if (ws) { ws.close(); ws = null; } };
  onLeave(stop);
  const connect = actionButton('Connect', async () => {
    stop(); clear(out); status.textContent = 'Connecting…';
    await ensureStepUp();
    const url = `${location.protocol === 'https:' ? 'wss' : 'ws'}://${location.host}/ws/ui?kind=term&device=${encodeURIComponent(id)}&csrf=${encodeURIComponent(S.csrf)}&shell=${shellSel.value}`;
    ws = new WebSocket(url);
    ws.onopen = () => { status.textContent = 'Connected (runs as SYSTEM)'; input.disabled = false; input.focus(); };
    ws.onmessage = ev => {
      if (typeof ev.data !== 'string') return;
      let m; try { m = JSON.parse(ev.data); } catch (e) { return; }
      if (m.t === 'out') add(m.d); else if (m.t === 'status') add('[' + m.msg + ']\n', 'echo'); else if (m.t === 'error') add('[error: ' + m.msg + ']\n', 'err');
    };
    ws.onclose = () => { status.textContent = 'Disconnected'; input.disabled = true; ws = null; };
    ws.onerror = () => { status.textContent = 'Connection failed (is another terminal open for this PC?)'; };
  });
  input.addEventListener('keydown', e => {
    if (e.key === 'Enter' && ws && ws.readyState === 1) {
      const line = input.value; if (line.trim()) { hist.push(line); hi = hist.length; }
      add(line + '\n', 'echo'); ws.send(JSON.stringify({ t: 'in', d: line + '\n' })); input.value = '';
    } else if (e.key === 'ArrowUp' && hist.length) { hi = Math.max(0, hi - 1); input.value = hist[hi]; e.preventDefault(); }
    else if (e.key === 'ArrowDown' && hist.length) { hi = Math.min(hist.length, hi + 1); input.value = hist[hi] || ''; e.preventDefault(); }
  });
  body.append(h('div', { class: 'panel stack' },
    h('div', { class: 'row' }, shellSel, connect, actionButton('Disconnect', async () => stop(), 'small'), status),
    out, h('div', { class: 'row', style: { flexWrap: 'nowrap' } }, input),
    h('p', { class: 'muted' }, 'Commands run as SYSTEM, without a prompt to the person at the PC. Interactive programs (editors, prompts that wait for input) are not supported.')));
}

// ---------- files ----------
function tabFiles(body, dev, id) {
  if (!needOnline(dev, body)) return;
  let cwd = '';
  const crumbs = h('div', { class: 'row' }), list = h('div');
  const unix = isLinux(dev), SEP = unix ? '/' : '\\';
  const join = (a, b) => a ? (a.endsWith(SEP) ? a + b : a + SEP + b) : b;
  const parent = p => {
    if (unix) { const t = p.replace(/\/+$/, ''); const i = t.lastIndexOf('/'); return i <= 0 ? '/' : t.slice(0, i); }
    const t = p.replace(/\\+$/, ''); const i = t.lastIndexOf('\\');
    return i < 0 ? '' : (i <= 2 && /^[A-Za-z]:$/.test(t.slice(0, i)) ? t.slice(0, i) + '\\' : t.slice(0, i));
  };
  const pathInput = h('input', { type: 'text', style: { flex: 1, minWidth: '14em', fontFamily: 'var(--mono)' }, placeholder: unix ? '/' : 'C:\\' });
  const go = async p => {
    clear(list).append(h('span', { class: 'spinner' }));
    try {
      const r = await runCmd(id, 'file.list', { path: p }, { wait: 30 });
      cwd = r.path || ''; pathInput.value = cwd;
      const ents = r.entries || [];
      clear(list).append(r.truncated ? h('div', { class: 'notice warn' }, 'Only the first 5000 entries are shown.') : null,
        table([{ label: 'Name' }, { label: 'Size', num: true }, { label: 'Modified' }, { label: '' }],
          [cwd && !(unix && cwd === '/') ? h('tr', null, h('td', { colSpan: 4 }, h('a', { href: '#', onclick: e => { e.preventDefault(); go(parent(cwd)); } }, '⬑ ..'))) : null].concat(ents.map(en => {
            const full = join(cwd, en.name);
            return h('tr', null,
              h('td', null, en.dir ? h('a', { href: '#', onclick: e => { e.preventDefault(); go(full); } }, '📁 ' + en.name) : '📄 ' + en.name),
              h('td', { class: 'num' }, en.dir || !cwd ? '' : fmtBytes(en.size)), h('td', null, en.mtime ? fmtTime(en.mtime * 1000) : ''),
              h('td', null, cwd ? h('div', { class: 'row', style: { gap: '4px' } },
                en.dir ? null : actionButton('Download', async () => { await ensureStepUp(); const a = h('a', { href: `/api/devices/${id}/download?path=${encodeURIComponent(full)}`, download: '' }); document.body.append(a); a.click(); a.remove(); }, 'small'),
                actionButton('Rename', async () => {
                  const nn = prompt('New name', en.name); if (!nn || nn === en.name) return;
                  await runCmd(id, 'file.rename', { from: full, to: join(cwd, nn) }); go(cwd);
                }, 'small'),
                actionButton('Delete', async () => { if (!(await confirmDialog('Delete ' + full + (en.dir ? ' and everything in it' : '') + '? This cannot be undone.', 'Delete', true))) return; await runCmd(id, 'file.delete', { path: full }); go(cwd); }, 'small danger')) : null));
          })), { empty: 'Empty folder' }));
    } catch (e) { clear(list).append(h('div', { class: 'notice bad' }, e.message)); }
  };
  pathInput.addEventListener('keydown', e => { if (e.key === 'Enter') go(pathInput.value.trim()); });
  const fileIn = h('input', { type: 'file' });
  const up = actionButton('Upload here', async () => {
    const f = fileIn.files[0]; if (!f) throw new Error('Choose a file first');
    if (!cwd) throw new Error('Open a folder first');
    await ensureStepUp();
    const target = join(cwd, f.name);
    const res = await fetch(`/api/devices/${id}/upload?path=${encodeURIComponent(target)}`, { method: 'POST', credentials: 'same-origin', headers: { 'X-CSRF-Token': S.csrf }, body: f });
    if (!res.ok) { let m = res.statusText; try { m = (await res.json()).error || m; } catch (x) { /* none */ } if (res.status === 409 && /exist/i.test(m) && await confirmDialog(target + ' already exists. Overwrite?', 'Overwrite', true)) {
      const r2 = await fetch(`/api/devices/${id}/upload?path=${encodeURIComponent(target)}&overwrite=1`, { method: 'POST', credentials: 'same-origin', headers: { 'X-CSRF-Token': S.csrf }, body: f });
      if (!r2.ok) throw new Error('Upload failed'); } else throw new Error(m); }
    toast('Uploaded ' + f.name, 'ok'); fileIn.value = ''; go(cwd);
  });
  body.append(h('div', { class: 'panel stack' }, h('h3', null, 'Files'),
    h('div', { class: 'row', style: { flexWrap: 'nowrap' } }, h('button', { onclick: () => go('') }, 'Drives'), pathInput, h('button', { onclick: () => go(pathInput.value.trim()) }, 'Go'),
      actionButton('New folder', async () => { if (!cwd) throw new Error('Open a folder first'); const n = prompt('Folder name'); if (!n) return; await runCmd(id, 'file.mkdir', { path: join(cwd, n) }); go(cwd); })),
    list, h('div', { class: 'row' }, fileIn, up),
    h('p', { class: 'muted' }, 'Runs as SYSTEM. Windows system folders are protected from delete/rename.')));
  go('');
}

// ---------- remote screen ----------
function tabScreen(body, dev, id) {
  if (!needOnline(dev, body)) return;
  const canvas = h('canvas', { tabIndex: 0, width: 640, height: 360 });
  const box = h('div', { class: 'screenbox' }, canvas);
  const status = h('div', { class: 'notice' }, 'Not connected. When someone is signed in at the PC they are asked to allow the session first; at the sign-in screen it connects directly.');
  const ctx = canvas.getContext('2d');
  let ws = null, chain = Promise.resolve(), viewOnly = false, live = false, lastMove = 0;
  // live numbers for the stats line: frames and bytes per second, and how long the picture takes to answer an action
  const st = { frames: 0, bytes: 0, since: performance.now(), fps: 0, kbps: 0, resp: 0, acted: 0 };
  const stats = h('span', { class: 'muted small-text screenstats' });
  const tickStats = () => { const n = performance.now(), dt = (n - st.since) / 1000; if (dt < 1) return; st.fps = Math.round(st.frames / dt); st.kbps = Math.round(st.bytes * 8 / dt / 1000); st.frames = 0; st.bytes = 0; st.since = n; stats.textContent = live ? st.fps + ' fps · ' + (st.kbps >= 1000 ? (st.kbps / 1000).toFixed(1) + ' Mbit/s' : st.kbps + ' kbit/s') + (st.resp ? ' · responds in ' + Math.round(st.resp) + ' ms' : '') : ''; };
  every(1000, tickStats);
  const send = o => { if (ws && ws.readyState === 1 && live) { if (o.t === 'md' || o.t === 'kd' || o.t === 'wh') st.acted = performance.now(); ws.send(JSON.stringify(o)); } };
  const stop = () => { if (ws) { ws.close(); ws = null; } live = false; };
  onLeave(() => { stop(); });

  const q = h('select', null, [[35, 'Low quality'], [55, 'Medium quality'], [75, 'High quality']].map(([v, l]) => h('option', { value: v, selected: v === 55 }, l)));
  const fps = h('select', null, [[10, '10 fps'], [20, '20 fps'], [30, '30 fps'], [60, 'Up to 60 fps']].map(([v, l]) => h('option', { value: v, selected: v === 30 }, l)));
  const scale = h('select', null, [[1, 'Full size'], [2, 'Half size (faster)']].map(([v, l]) => h('option', { value: v, selected: v === 1 }, l)));
  const tune = () => send({ t: 'q', q: Number(q.value), fps: Number(fps.value), scale: Number(scale.value) });
  [q, fps, scale].forEach(x => x.addEventListener('change', tune));
  const vo = h('input', { type: 'checkbox' });
  const mon = h('select', { class: 'hidden', 'aria-label': 'Monitor' });
  mon.addEventListener('change', () => send({ t: 'mon', b: Number(mon.value) }));
  const showMonitors = m => {
    if (!m.list || m.list.length < 2) { mon.classList.add('hidden'); return; }
    clear(mon).append(...m.list.map((x, i) => h('option', { value: i, selected: i === m.cur }, 'Monitor ' + (i + 1) + (x.primary ? ' (main)' : '') + ' ' + x.w + '×' + x.h)));
    mon.classList.remove('hidden');
  };
  const clipFromPC = async m => {
    if (!m.ok) { toast('Could not read the PC\u2019s clipboard', 'bad'); return; }
    if (!m.s) { toast('The PC\u2019s clipboard has no text', 'ok'); return; }
    try { await navigator.clipboard.writeText(m.s); toast('PC clipboard copied. Paste it here.', 'ok'); }
    catch (e) { const ta = h('textarea', { readOnly: true, rows: 8, style: { width: '100%' } }); ta.value = m.s; modal('PC clipboard', h('div', { class: 'stack' }, h('p', { class: 'muted' }, 'Your browser blocked automatic copying. Select the text below and copy it.'), ta)); }
  };
  const sendClip = async () => {
    try { const t = await navigator.clipboard.readText(); if (!t) { toast('Your clipboard has no text', 'ok'); return; } send({ t: 'clipset', s: t.slice(0, 262144) }); toast('Sent your clipboard to the PC. Paste it there.', 'ok'); }
    catch (e) { toast('Your browser did not allow reading the clipboard', 'bad'); }
  };

  const connect = actionButton('Connect', async () => {
    stop(); status.className = 'notice'; status.textContent = 'Connecting… waiting for permission on the PC if someone is signed in.';
    await ensureStepUp();
    viewOnly = vo.checked;
    const url = `${location.protocol === 'https:' ? 'wss' : 'ws'}://${location.host}/ws/ui?kind=screen&device=${encodeURIComponent(id)}&csrf=${encodeURIComponent(S.csrf)}` + (viewOnly ? '&viewOnly=1' : '');
    ws = new WebSocket(url); ws.binaryType = 'arraybuffer';
    ws.onmessage = ev => {
      if (typeof ev.data === 'string') {
        let m; try { m = JSON.parse(ev.data); } catch (e) { return; }
        if (m.t === 'screen') { canvas.width = m.w; canvas.height = m.h; live = true; status.className = 'notice'; status.textContent = 'Connected' + (viewOnly ? ' (view only)' : '') + '. Click the screen to send keyboard input.'; tune(); }
        else if (m.t === 'fr') { chain = chain.then(() => { st.frames++; if (st.acted) { const d = performance.now() - st.acted; st.resp = st.resp ? st.resp * .7 + d * .3 : d; st.acted = 0; } send({ t: 'ack', n: m.n }); }); }
        else if (m.t === 'monitors') { showMonitors(m); }
        else if (m.t === 'clip') { clipFromPC(m); }
        else if (m.t === 'status') { status.textContent = m.msg; }
        else if (m.t === 'error' || (m.t === 'consent' && m.ok === false)) { status.className = 'notice bad'; status.textContent = m.msg || 'Refused'; }
        return;
      }
      const buf = ev.data; st.bytes += buf.byteLength;
      chain = chain.then(() => drawTiles(buf)).catch(() => { });
    };
    ws.onclose = () => { live = false; ws = null; if (!status.classList.contains('bad')) status.textContent = 'Disconnected'; };
    ws.onerror = () => { status.className = 'notice bad'; status.textContent = 'Could not open a session (is one already open, or is the PC offline?)'; };
  });
  async function drawTiles(buf) {
    const dv = new DataView(buf); const n = dv.getUint16(0); let o = 2; const jobs = [];
    for (let i = 0; i < n; i++) {
      const x = dv.getUint16(o), y = dv.getUint16(o + 2), len = dv.getUint32(o + 8); o += 12;
      // text and interface regions arrive as PNG (exact), pictures as JPEG
      const png = len > 4 && new Uint8Array(buf, o, 2)[0] === 0x89;
      jobs.push(createImageBitmap(new Blob([new Uint8Array(buf, o, len)], { type: png ? 'image/png' : 'image/jpeg' })).then(bmp => ({ bmp, x, y })));
      o += len;
    }
    for (const t of await Promise.all(jobs)) { ctx.drawImage(t.bmp, t.x, t.y); t.bmp.close(); }
  }

  const frac = e => { const r = canvas.getBoundingClientRect(); return { x: Math.min(1, Math.max(0, (e.clientX - r.left) / r.width)), y: Math.min(1, Math.max(0, (e.clientY - r.top) / r.height)) }; };
  canvas.addEventListener('mousemove', e => { const n = performance.now(); if (n - lastMove < 14) return; lastMove = n; send(Object.assign({ t: 'mm' }, frac(e))); });
  canvas.addEventListener('mousedown', e => { canvas.focus(); e.preventDefault(); send(Object.assign({ t: 'md', b: e.button }, frac(e))); });
  canvas.addEventListener('mouseup', e => { e.preventDefault(); send(Object.assign({ t: 'mu', b: e.button }, frac(e))); });
  canvas.addEventListener('contextmenu', e => e.preventDefault());
  // Drop a file on the screen to send it to the PC.
  const dropHint = h('div', { class: 'muted small-text' }, 'Tip: drag a file onto the screen to send it to this PC.');
  canvas.addEventListener('dragover', e => { if (live && !vo.checked && e.dataTransfer && [...e.dataTransfer.types].includes('Files')) { e.preventDefault(); canvas.style.outline = '2px dashed var(--accent)'; } });
  canvas.addEventListener('dragleave', () => { canvas.style.outline = ''; });
  canvas.addEventListener('drop', async e => {
    canvas.style.outline = ''; e.preventDefault();
    if (!live || vo.checked) { toast('Connect and turn off view-only to send files', 'bad'); return; }
    const f = e.dataTransfer.files && e.dataTransfer.files[0]; if (!f) return;
    if (f.size > 512 * 1048576) { toast('That file is larger than 512 MB', 'bad'); return; }
    const dir = h('input', { type: 'text', value: sessionStorage.getItem('helm.dropdir') || (isLinux(dev) ? '/tmp' : 'C:\\Users\\Public\\Desktop'), style: { width: '100%' } });
    const ok = await modal('Send file to ' + dev.name, h('div', { class: 'stack' }, h('p', null, f.name + ' (' + Math.ceil(f.size / 1024).toLocaleString() + ' KB)'), h('label', { class: 'field' }, h('span', null, 'Save in this folder on the PC'), dir)), [{ label: 'Cancel', value: false }, { label: 'Send file', value: true }]);
    if (!ok) return;
    try {
      await ensureStepUp();
      const folder = dir.value.trim().replace(/[\\/]+$/, ''); sessionStorage.setItem('helm.dropdir', folder);
      const target = folder + '\\' + f.name;
      let res = await fetch(`/api/devices/${id}/upload?path=${encodeURIComponent(target)}`, { method: 'POST', credentials: 'same-origin', headers: { 'X-CSRF-Token': S.csrf }, body: f });
      if (res.status === 409 && await confirmDialog(target + ' already exists. Overwrite?', 'Overwrite', true)) res = await fetch(`/api/devices/${id}/upload?path=${encodeURIComponent(target)}&overwrite=1`, { method: 'POST', credentials: 'same-origin', headers: { 'X-CSRF-Token': S.csrf }, body: f });
      if (!res.ok) { let m = res.statusText; try { m = (await res.json()).error || m; } catch (x) { /* none */ } throw new Error(m); }
      toast('Sent ' + f.name + ' to ' + folder, 'ok');
    } catch (err) { toast(err.message || 'Upload failed', 'bad'); }
  });
  canvas.addEventListener('wheel', e => { e.preventDefault(); send({ t: 'wh', dx: e.deltaX, dy: e.deltaY }); }, { passive: false });
  const key = t => e => { e.preventDefault(); send({ t, code: e.code, key: e.key, c: e.ctrlKey, a: e.altKey, m: e.metaKey }); };
  canvas.addEventListener('keydown', key('kd')); canvas.addEventListener('keyup', key('ku'));

  body.append(h('div', { class: 'panel stack' },
    h('div', { class: 'row' }, connect, actionButton('Disconnect', async () => stop(), 'small'), h('label', null, vo, ' View only'), q, fps, scale, mon,
      h('button', { class: 'small', onclick: () => send({ t: 'cad' }) }, 'Ctrl+Alt+Del'),
      h('button', { class: 'small', onclick: () => send({ t: 'refresh' }) }, 'Refresh'),
      h('button', { class: 'small', onclick: sendClip }, 'Send my clipboard'),
      h('button', { class: 'small', onclick: () => send({ t: 'clipget' }) }, 'Get PC clipboard'), dropHint,
      h('button', { class: 'small', onclick: () => { if (box.requestFullscreen) box.requestFullscreen(); } }, 'Full screen'), stats),
    status, box,
    h('p', { class: 'muted' }, 'Streams the PC\'s console session (including the sign-in screen). The frame rate and quality you pick are the most it will use; Helm measures how long each frame takes to reach you and lowers them by itself when the connection is slow, then raises them again when it recovers. Text and menus are sent exactly (lossless), pictures as JPEG, and anything that was sent softly sharpens a moment after it stops moving. Clipboard transfer is text only. For a full-speed session use an RDP tunnel from the Tools tab.')));
}

// ---------- security ----------
async function tabSecurity(body, dev, id) {
  const my = routeToken;
  const host = h('div', null, h('span', { class: 'spinner' }));
  body.append(host);
  const f = { sev: 'all', kind: 'all' };
  let v = null, cve = null, last = '';
  const startScan = actionButton('Scan now', async () => { await api('POST', `/api/devices/${id}/scan`, {}); toast('Scan started', 'ok'); load(); }, 'primary');
  const draw = () => {
    const sig = JSON.stringify([v, f, dev.online]); if (sig === last) return; last = sig;
    clear(host);
    if (!v || !v.hasData) {
      if (v && v.status === 'running') { host.append(h('div', { class: 'panel' }, emptyState('🛡️', 'Scanning…', 'Collecting software, settings, ports and updates. This page updates automatically.'))); return; }
      host.append(h('div', { class: 'panel' }, emptyState('🛡️', v && v.status === 'failed' ? 'The scan could not collect any data' : 'This PC has not been scanned yet', v && v.errors && v.errors.length ? v.errors.join(' · ') : dev.online ? 'A scan checks installed software for known vulnerabilities, missing system updates, risky settings and open ports. It takes a minute or two.' : 'The PC is offline. It will be scanned automatically when it is back.', dev.online ? startScan : null)));
      return;
    }
    const running = v.status === 'running';
    const c = v.counts, serious = c.critical + c.high;
    const notes = [];
    if (running) notes.push(h('div', { class: 'notice', style: { marginBottom: '12px' } }, h('span', { class: 'spinner' }), ' Rescanning… these results are from the previous scan and will update when it finishes.'));
    if (v.errors && v.errors.length) notes.push(h('div', { class: 'notice warn', style: { marginBottom: '12px' } }, h('b', null, 'Some checks did not complete: '), v.errors.join(' · ')));
    if (v.unavailable) notes.push(h('div', { class: 'notice warn', style: { marginBottom: '12px' } }, h('b', null, 'Vulnerability data unavailable. '), `${plural(v.unavailable, 'program')} could not be checked because Helm cannot download the NVD database right now (the server needs internet access to services.nvd.nist.gov). Patches, settings and ports are still checked.`));
    if (v.pending) notes.push(h('div', { class: 'notice', style: { marginBottom: '12px' } }, h('span', { class: 'spinner' }), ` Looking up vulnerability data for ${plural(v.pending, 'program')}. Results appear here automatically.`));
    host.append(notes,
      h('div', { class: 'panel' }, h('div', { class: 'scorehero' }, scoreRing(v.score),
        h('div', { style: { flex: 1, minWidth: '240px' } },
          h('h2', { style: { margin: 0 } }, serious ? plural(serious, 'serious problem') + ' found' : v.score >= 80 ? 'Looking healthy' : 'Some issues to review'),
          h('div', { class: 'muted', style: { margin: '4px 0 12px' } }, 'Last scan ' + fmtAgo(v.at) + ' · ' + plural(v.software.length, 'program') + ' checked (' + v.assessed + ' matched to vulnerability data)'),
          h('div', { class: 'row' }, SEV_ORDER.map(k => h('div', { class: 'row tight' }, sevBadge(k), h('b', null, String(c[k])))), h('span', { style: { flex: 1 } }), dev.online && !running ? startScan : null)))),
      drawFindings());
  };
  const drawFindings = () => {
    const list = v.findings.filter(x => (f.sev === 'all' || x.severity === f.sev) && (f.kind === 'all' || x.kind === f.kind));
    const pill = (key, val, label) => h('button', { class: 'pill' + (f[key] === val ? ' on' : ''), onclick: () => { f[key] = val; last = ''; draw(); } }, label);
    const cfg = v.checks || [], ports = (v.ports || []).filter(p => p.address && !/^(127\.|::1)/.test(p.address));
    return h('div', { style: { marginTop: '16px' } },
      h('div', { class: 'toolbar' }, h('div', { class: 'pills' }, pill('sev', 'all', 'All'), SEV_ORDER.map(s => pill('sev', s, cap(s)))),
        h('div', { class: 'pills' }, [['all', 'Everything'], ['cve', 'Vulnerable software'], ['patch', 'Patches'], ['config', 'Configuration'], ['port', 'Open ports']].map(([k, l]) => pill('kind', k, l)))),
      h('div', { class: 'panel flush' }, list.length ? list.map(x => h('div', { class: 'finding' }, h('div', null, sevBadge(x.severity)),
        h('div', null, h('div', { class: 'ft' }, x.title, x.cve ? h('a', { href: 'https://nvd.nist.gov/vuln/detail/' + encodeURIComponent(x.cve), target: '_blank', rel: 'noopener noreferrer', style: { marginLeft: '8px', fontWeight: 400 } }, 'NVD ↗') : null,
          x.score ? h('span', { class: 'muted', style: { fontWeight: 400 } }, '  CVSS ' + x.score.toFixed(1)) : null, x.exploited ? h('span', { class: 'badge kev', style: { marginLeft: '8px' } }, 'actively exploited') : null),
          x.detail ? h('div', { class: 'fd' }, x.detail) : null, x.fix ? h('div', { class: 'ff' }, '→ ' + x.fix) : null), h('div')))
        : emptyState('✅', 'Nothing to show', v.findings.length ? 'No findings match these filters.' : 'No problems were found on this PC.')),
      h('p', { class: 'muted small-text' }, 'Vulnerability matches are potential: Helm compares installed versions to published affected ranges and cannot see vendor backports.'),
      h('details', { class: 'panel flush fold', style: { marginTop: '16px' } }, h('summary', null, `Configuration audit (${cfg.filter(x => x.status === 'pass').length} of ${cfg.filter(x => x.status !== 'na').length} passed)`),
        table(['Check', 'Category', 'Result', 'Detail'].map(x => ({ label: x })), cfg.map(x => h('tr', null, h('td', null, x.title), h('td', { class: 'muted' }, x.category), h('td', null, h('span', { class: 'badge ' + x.status }, x.status === 'na' ? 'n/a' : x.status)), h('td', { class: 'muted wrap' }, x.detail || ''))), { empty: 'No configuration data' })),
      h('details', { class: 'panel flush fold', style: { marginTop: '16px' } }, h('summary', null, `Network-facing ports (${ports.length})`),
        table(['Port', 'Address', 'Process', 'Note'].map(x => ({ label: x })), ports.map(p => h('tr', null, h('td', { class: 'mono' }, p.port + '/' + (p.proto || 'tcp')), h('td', { class: 'mono' }, p.address), h('td', null, p.process || '–'), h('td', { class: 'muted' }, riskNote(p.port)))), { empty: 'No ports are listening beyond this PC.' })));
  };
  const riskNote = port => ({ 21: 'FTP: unencrypted', 23: 'Telnet: unencrypted', 135: 'RPC', 139: 'NetBIOS', 445: 'SMB file sharing', 1433: 'SQL Server', 3306: 'MySQL', 3389: 'Remote Desktop', 5432: 'PostgreSQL', 5900: 'VNC', 5985: 'WinRM', 6379: 'Redis', 27017: 'MongoDB' })[port] || '';
  const load = async () => {
    try {
      [v, cve] = await Promise.all([api('GET', `/api/devices/${id}/scan`), api('GET', '/api/settings').then(s => s.cve).catch(() => null)]);
      if (my === routeToken) draw();
    } catch (e) { clear(host).append('Could not load: ' + e.message); }
  };
  load(); every(4000, () => { if (!v || v.status === 'running' || v.pending) load(); });
}

// ---------- software ----------
async function tabSoftware(body, dev, id) {
  const my = routeToken;
  const host = h('div', null, h('span', { class: 'spinner' })); body.append(host);
  let v, q = '';
  const draw = () => {
    const vuln = {};
    for (const x of v.findings) if (x.kind === 'cve') { const k = x.software + '|' + x.version; (vuln[k] = vuln[k] || []).push(x); }
    const f = v.software.filter(s => !q || (s.name + ' ' + s.publisher).toLowerCase().includes(q)).sort((a, b) => a.name.toLowerCase().localeCompare(b.name.toLowerCase()));
    const search = h('input', { type: 'search', placeholder: 'Search installed software…', value: q, 'aria-label': 'Search software', style: { width: '100%' } });
    search.addEventListener('input', () => { q = search.value.toLowerCase(); const p = search.selectionStart; draw(); const n = $('input[aria-label="Search software"]'); if (n) { n.focus(); n.setSelectionRange(p, p); } });
    clear(host).append(h('div', { class: 'toolbar' }, h('div', { class: 'grow' }, search), h('span', { class: 'muted' }, plural(f.length, 'program')),
      dev.online ? actionButton('Install from catalog…', () => installFromCatalog(dev), 'primary') : null),
      h('div', { class: 'panel flush' }, table(['Software', 'Version', 'Publisher', 'Installed', 'Vulnerabilities'].map(x => ({ label: x })), f.map(s => {
        const vs = vuln[s.name + '|' + s.version] || [];
        const worst = vs.reduce((a, x) => sevRank2(x.severity) > sevRank2(a) ? x.severity : a, '');
        return h('tr', null, h('td', null, h('b', null, s.name)), h('td', { class: 'mono' }, s.version), h('td', { class: 'muted' }, s.publisher), h('td', { class: 'muted nowrap' }, s.installDate || ''),
          h('td', null, vs.length ? [sevBadge(worst), h('span', { class: 'muted' }, ' ' + plural(vs.length, 'CVE'))] : h('span', { class: 'muted' }, '–')));
      }), { empty: 'No software found' })));
  };
  const sevRank2 = s => ({ critical: 4, high: 3, medium: 2, low: 1 })[s] || 0;
  try {
    v = await api('GET', `/api/devices/${id}/scan`); if (my !== routeToken) return;
    if (!v || !v.haveSoftware) {
      clear(host).append(h('div', { class: 'panel' }, emptyState('📦', 'No software inventory yet', 'Software is collected by a security scan.', dev.online ? actionButton('Scan now', async () => { await api('POST', `/api/devices/${id}/scan`, {}); location.hash = `#/d/${id}/security`; }, 'primary') : null)));
      return;
    }
    draw();
  } catch (e) { clear(host).append('Could not load: ' + e.message); }
}

async function installFromCatalog(dev) {
  const pk = await api('GET', '/api/packages');
  if (!pk.length) { toast('Your catalog is empty. Add software on the Software page first.', 'bad'); location.hash = '#/software'; return; }
  const sel = h('select', null, pk.map(p => h('option', { value: p.id }, p.name)));
  const ok = await modal('Install software on ' + dev.name, h('div', { class: 'stack' }, h('label', { class: 'field' }, h('span', null, 'Package'), sel)), [{ label: 'Cancel', value: false }, { label: 'Install', value: true, cls: 'primary' }]);
  if (!ok) return;
  try { const run = await api('POST', '/api/deploy', { packageId: sel.value, action: 'install', target: { devices: [dev.id] } }); await showRun(run.id, 'Installing'); } catch (e) { toast(e.message, 'bad'); }
}
