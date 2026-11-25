'use strict';
/* Helm 1.0: modules (RMM, Antivirus, EDR), device onboarding, the device side pane and the antivirus page.
   Loaded after device.js. */

const MODULES = [
  { key: 'rmm', name: 'RMM', tag: 'Remote management', text: 'Remote screen, files, terminal, software and Windows updates, services and chat with the person at the PC.' },
  { key: 'av', name: 'Antivirus', tag: 'Malware protection', text: 'Scans, daily threat-intelligence updates, threat history. Uses Microsoft Defender, ClamAV or XProtect and keeps them current.' },
  { key: 'edr', name: 'EDR', tag: 'Detection and response', text: 'Process, network and start-up telemetry with suspicious-activity flags, and one-click network isolation.' },
];
const PRESETS = [['RMM only', ['rmm']], ['RMM + Antivirus', ['rmm', 'av']], ['Antivirus + EDR', ['av', 'edr']], ['Everything', ['rmm', 'av', 'edr']]];
const hasMod = (d, m) => (d.modules || []).includes(m);

// A pick-your-plan control: three cards that switch on and off. get() returns the chosen module keys.
function modulePicker(initial) {
  const on = new Set(initial || ['rmm']);
  const wrap = h('div', { class: 'stack' });
  const cards = h('div', { class: 'modgrid' });
  const draw = () => {
    clear(cards).append(MODULES.map(m => {
      const box = h('input', { type: 'checkbox', checked: on.has(m.key), onchange: e => { e.target.checked ? on.add(m.key) : on.delete(m.key); draw(); } });
      return h('label', { class: 'modcard' + (on.has(m.key) ? ' on' : '') }, box,
        h('span', { class: 'modname' }, h('b', null, m.name), h('span', { class: 'muted small-text' }, m.tag)),
        h('span', { class: 'modtext' }, m.text), h('span', { class: 'modtick', 'aria-hidden': 'true' }, on.has(m.key) ? '✓' : ''));
    }));
  };
  draw();
  wrap.append(h('div', { class: 'row tight' }, h('span', { class: 'muted small-text' }, 'Quick pick:'), PRESETS.map(([l, v]) => h('button', { type: 'button', class: 'small ghost', onclick: () => { on.clear(); v.forEach(x => on.add(x)); draw(); } }, l))), cards);
  return { node: wrap, get: () => MODULES.map(m => m.key).filter(k => on.has(k)) };
}

// ---------- onboarding ----------
function onboardPanel(dev, onDone) {
  const hello = dev.hello || {};
  const name = h('input', { type: 'text', value: dev.name, maxLength: 80 });
  const group = h('input', { type: 'text', value: dev.group || '', maxLength: 40, placeholder: 'e.g. Reception' });
  const tags = h('input', { type: 'text', value: (dev.tags || []).join(', '), placeholder: 'laptop, vip' });
  const pick = modulePicker(['rmm']);
  const go = actionButton('Finish setup', async () => {
    const modules = pick.get();
    if (!modules.length) throw new Error('Pick at least one module.');
    await api('POST', `/api/devices/${dev.id}/onboard`, { modules, name: name.value, group: group.value, tags: parseTags(tags.value) });
    S.devices = null; toast(name.value.trim() + ' is set up', 'ok'); onDone();
  }, 'primary');
  return h('div', { class: 'onboard stack' },
    h('div', { class: 'row', style: { gap: '14px' } }, deviceArt(dev, 56), h('div', null, h('h2', { style: { margin: 0 } }, 'A new PC has connected'),
      h('div', { class: 'muted' }, [hello.hostname || dev.name, osText(dev), dev.lastIp].filter(Boolean).join(' · ')))),
    h('div', { class: 'notice' }, 'This PC is connected but cannot be managed until you choose what it gets. You can change the plan later.'),
    h('h3', { style: { margin: '6px 0 0' } }, '1. Choose a plan'), pick.node,
    h('h3', { style: { margin: '6px 0 0' } }, '2. Name it (optional)'),
    h('div', { class: 'row' }, h('label', { class: 'field', style: { flex: 2 } }, h('span', null, 'Display name'), name), h('label', { class: 'field' }, h('span', null, 'Group'), group), h('label', { class: 'field' }, h('span', null, 'Tags'), tags)),
    h('div', { class: 'row' }, go, actionButton('Not mine: remove it', async () => {
      if (!(await confirmDialog('Remove ' + dev.name + '? The agent on it loses access to this console.', 'Remove', true))) return;
      await api('DELETE', '/api/devices/' + dev.id); S.devices = null; location.hash = '#/devices';
    }, 'danger')));
}

// ---------- the device side pane ----------
const SECTIONS = [
  ['Overview', null, [['overview', 'Overview']]],
  ['Manage', ['rmm'], [['screen', 'Remote screen'], ['files', 'Files'], ['terminal', 'Terminal'], ['chat', 'Chat'], ['software', 'Software'], ['updates', 'Updates'], ['services', 'Services'], ['tools', 'Tools']]],
  ['Antivirus', ['av'], [['antivirus', 'Protection']]],
  ['EDR', ['edr'], [['edr', 'Detection & response']]],
  ['Monitor', ['rmm', 'edr'], [['processes', 'Processes'], ['events', 'Event logs']]],
  ['Security', null, [['security', 'Findings']]],
  ['This PC', null, [['jobs', 'History'], ['plan', 'Plan & modules']]],
];
function sectionsFor(dev) {
  if (!dev.approved || !dev.onboarded) return [['Set up', [['overview', 'Choose a plan']]]];
  const unix = isLinux(dev);
  return SECTIONS.map(([g, need, items]) => [g, items.filter(([k]) => (!need || need.some(m => hasMod(dev, m))) && !(unix && k === 'screen')).map(([k, l]) => [k, unix && k === 'events' ? 'Logs' : l])]).filter(([, items]) => items.length);
}

// Terminal and remote screen run in a browser tab of their own, so the pane stays usable next to them.
const SESSION_TABS = ['terminal', 'screen'];
function sessionLauncher(body, dev, id, kind) {
  const label = kind === 'screen' ? 'remote screen' : 'terminal';
  body.append(h('div', { class: 'panel stack' }, h('h3', { style: { margin: 0 } }, kind === 'screen' ? 'Remote screen' : 'Terminal'),
    h('p', { class: 'muted', style: { margin: 0 } }, 'The ' + label + ' opens in its own browser tab, so you can keep this pane open beside it.'),
    h('div', null, h('a', { class: 'btn primary', href: `#/session/${id}/${kind}`, target: '_blank', rel: 'noopener' }, 'Open ' + label + ' in a new tab ↗'))));
}

let PANE = null; // { id, tab, dev, base }

const TAB_FN = () => ({ overview: tabOverview, updates: tabUpdates, processes: tabProcesses, services: tabServices, terminal: (b, d, i) => sessionLauncher(b, d, i, 'terminal'), files: tabFiles, chat: tabChat, screen: (b, d, i) => sessionLauncher(b, d, i, 'screen'),
  events: tabEvents, tools: tabTools, jobs: tabJobs, security: tabSecurity, software: tabSoftware, antivirus: tabAntivirus, edr: tabEdr, plan: tabPlan });

// Called by the router on a hash change: when the pane for this PC is already open, only the section changes.
window.paneSwitch = (id, tab) => {
  if (!PANE || PANE.id !== id || !document.querySelector('.dpane')) return false;
  PANE.tab = tab; PANE.redraw(true);
  return true;
};

async function openDevicePane(id, tab) {
  tab = tab || 'overview';
  viewDevices(); // the PC list stays behind the pane
  const root = $('#app');
  const scrim = h('div', { class: 'dscrim', onclick: () => { location.hash = '#/devices'; } });
  const pane = h('aside', { class: 'dpane', role: 'dialog', 'aria-label': 'PC details', 'data-id': id }, h('div', { class: 'dloading' }, h('span', { class: 'spinner' })));
  root.append(scrim, pane);
  const onKey = e => { if (e.key === 'Escape' && !document.querySelector('#modal-root > *')) location.hash = '#/devices'; };
  document.addEventListener('keydown', onKey);
  const my = routeToken;
  let dev;
  try { dev = await api('GET', '/api/devices/' + id); } catch (e) { clear(pane).append(h('div', { class: 'panel' }, 'Could not load this PC: ' + e.message)); return; }
  if (my !== routeToken) return;

  const head = h('div', { class: 'dhead' }), nav = h('nav', { class: 'dnav', 'aria-label': 'Sections' }), main = h('div', { class: 'dmain' });
  const st = { id, tab, dev, base: 0 };
  PANE = st;
  const drawHead = () => {
    const s = st.dev;
    clear(head).append(
      h('div', { class: 'row spread', style: { flexWrap: 'nowrap', alignItems: 'flex-start' } },
        h('div', { class: 'row', style: { gap: '12px', flexWrap: 'nowrap', minWidth: 0 } }, deviceArt(s, 44),
          h('div', { style: { minWidth: 0 } }, h('h2', { class: 'dtitle' }, s.name),
            h('div', { class: 'row tight' }, deviceChip(s), vendorChip(s), scoreBadge(s.security), s.group ? h('span', { class: 'tag group' }, s.group) : null, tagNodes(s.tags),
              (s.modules || []).map(m => h('span', { class: 'chip plain mod-' + m }, (MODULES.find(x => x.key === m) || {}).name || m)))),
          ),
        h('div', { class: 'row tight', style: { flexWrap: 'nowrap' } },
          s.approved && s.online ? actionButton('Scan now', async () => { await api('POST', `/api/devices/${id}/scan`, {}); toast('Security scan started', 'ok'); location.hash = `#/d/${id}/security`; }, 'small') : null,
          s.approved ? h('button', { class: 'small', onclick: async () => { if (await groupDialog([s])) { st.dev = await api('GET', '/api/devices/' + id); drawHead(); } } }, 'Group & tags') : null,
          h('button', { class: 'ghost icon', 'aria-label': 'Close', title: 'Close (Esc)', onclick: () => { location.hash = '#/devices'; } }, '✕'))),
      !s.online && s.approved ? h('div', { class: 'notice warn', style: { marginTop: '10px' } }, 'Offline since ' + fmtAgo(s.lastSeen) + '. Commands work again when it reconnects.') : null);
  };
  const drawNav = () => {
    clear(nav).append(sectionsFor(st.dev).map(([g, items]) => h('div', { class: 'dgroup' }, h('div', { class: 'dgname' }, g),
      items.map(([k, l]) => SESSION_TABS.includes(k)
        ? h('a', { href: `#/session/${id}/${k}`, target: '_blank', rel: 'noopener', class: 'newtab' }, l, h('span', { class: 'ext', 'aria-hidden': 'true' }, '↗'))
        : h('a', { href: `#/d/${id}/${k}`, class: st.tab === k ? 'active' : '', 'aria-current': st.tab === k ? 'page' : null }, l)))));
  };
  const drawBody = () => {
    const fresh = h('div', { class: 'dbody-in' });
    main.replaceChildren(fresh);
    if (!st.dev.approved || !st.dev.onboarded) { fresh.append(onboardPanel(st.dev, async () => { st.dev = await api('GET', '/api/devices/' + id); st.tab = 'overview'; location.hash = `#/d/${id}`; st.redraw(true); })); return; }
    const sec = sectionsFor(st.dev).flatMap(([, items]) => items.map(([k]) => k));
    if (!sec.includes(st.tab)) { fresh.append(h('div', { class: 'panel' }, emptyState('🔒', 'Not part of this PC’s plan', 'Add the module under Plan & modules to use it.', h('a', { class: 'btn', href: `#/d/${id}/plan` }, 'Plan & modules')))); return; }
    const fn = TAB_FN()[st.tab];
    if (!fn) { fresh.append('Unknown section'); return; }
    fn(fresh, st.dev, id);
  };
  st.redraw = tabOnly => {
    if (tabOnly) { cleanups.splice(st.base).forEach(f => { try { f(); } catch (e) { /* ignore */ } }); }
    drawNav(); drawBody();
    if (!tabOnly) drawHead();
    main.scrollTop = 0;
  };
  clear(pane).append(head, h('div', { class: 'dbody' }, nav, main));
  requestAnimationFrame(() => pane.classList.add('in'));

  const t = setInterval(async () => {
    try {
      const d = await api('GET', '/api/devices/' + id);
      const flip = d.online !== st.dev.online || d.approved !== st.dev.approved || JSON.stringify(d.modules) !== JSON.stringify(st.dev.modules);
      st.dev = d; if (flip) { drawHead(); drawNav(); }
    } catch (e) { /* ignore */ }
  }, 6000);
  onLeave(() => { clearInterval(t); document.removeEventListener('keydown', onKey); PANE = null; });
  st.base = cleanups.length; // everything registered after this belongs to the open section
  drawHead(); drawNav(); drawBody();
}

// Replace the top-tab device page with the side pane.
route(/^\/d\/([^/]+)(?:\/([a-z]+))?$/, (id, tab) => openDevicePane(id, tab));
routes.splice(routes.findIndex(r => r[1] === viewDevice), 1); // the old full-page route goes away

// ---------- Antivirus tab ----------
// Installs whatever the PC's plan needs (antivirus engine, firewall tool) and shows what happened.
function setupButton(dev, id, mods, after) {
  const out = h('pre', { class: 'out hidden' });
  const btn = actionButton('Set up components', async () => {
    if (!dev.online) throw new Error('This PC is offline.');
    out.classList.remove('hidden'); out.textContent = 'Working… installing can take a few minutes.';
    const r = await runCmd(id, 'module.install', { modules: mods }, { wait: 3000, onProgress: j => { out.textContent = (j.progress || []).slice(-4).join('\n') || 'Working…'; }, keepAlive: true });
    const comps = ((r && r.result) || r || {}).components || [];
    out.textContent = comps.map(c => (c.ok ? 'Ready: ' : 'Problem: ') + c.module.toUpperCase() + '\n  ' + (c.steps || []).join('\n  ') + (c.note ? '\n  ' + c.note : '')).join('\n') || 'Nothing to do.';
    if (after) after();
  });
  return h('div', { class: 'stack' }, h('div', { class: 'row tight' }, btn, h('span', { class: 'muted' }, 'Helm does this by itself when a plan is chosen. Use this to retry.')), out);
}

async function tabAntivirus(body, dev, id) {
  const box = h('div', { class: 'stack' }, h('span', { class: 'spinner' }));
  body.append(box);
  if (dev.online) body.append(setupButton(dev, id, ['av'], () => setTimeout(() => load(), 1500)));
  const load = async () => {
    let rows; try { rows = (await api('GET', '/api/av')).rows; } catch (e) { clear(box).append(h('div', { class: 'notice bad' }, e.message)); return; }
    const row = rows.find(r => r.id === id) || {};
    const sigLine = [row.engine, row.signatures && row.signatures.slice(0, 60)].filter(Boolean).join(' · ') || 'not read yet';
    const chip = { current: ['ok', 'Up to date'], stale: ['bad', 'Out of date'], missing: ['bad', 'No engine'], unknown: ['warn', 'Checking'], error: ['bad', 'Error'] }[row.state || 'unknown'];
    const threats = h('div'), out = h('pre', { class: 'out hidden' });
    const scanBtn = (label, kind, cls) => actionButton(label, async () => {
      if (!dev.online) throw new Error('This PC is offline.');
      out.classList.remove('hidden'); out.textContent = 'Scanning… this can take a while.';
      try { const r = await runCmd(id, 'av.scan', { kind }, { wait: 80, onProgress: j => { out.textContent = (j.progress || []).slice(-3).join('\n') || 'Scanning…'; }, keepAlive: true });
        out.textContent = r && r.infected ? (r.infected.length ? r.infected.join('\n') : 'Scan finished. No threats found.') : 'Scan finished.' + (r && r.recent && r.recent.length ? ' Recent detections are listed below.' : ' No threats found.'); loadThreats(); }
      catch (e) { out.textContent = e.message; throw e; }
    }, cls);
    const path = h('input', { type: 'text', placeholder: isLinux(dev) ? '/home/user/Downloads' : 'C:\\Users\\Public\\Downloads', style: { flex: 1, minWidth: '14em', fontFamily: 'var(--mono)' } });
    const loadThreats = async () => {
      if (!dev.online) { clear(threats).append(h('p', { class: 'muted' }, 'Offline.')); return; }
      try { const r = await runCmd(id, 'av.threats', {}, { wait: 40 }); const l = Array.isArray(r) ? r : (r ? [r] : []);
        clear(threats).append(table(['When', 'Threat', 'Where', 'Result'].map(x => ({ label: x })), l.map(t => h('tr', null, h('td', null, t.InitialDetectionTime ? fmtTime(t.InitialDetectionTime) : ''), h('td', null, String(t.ThreatID || '')), h('td', null, [].concat(t.Resources || []).join(', ').slice(0, 120)), h('td', null, t.ActionSuccess ? 'Cleaned' : 'Needs attention'))), { empty: isLinux(dev) && row.engine !== 'Microsoft Defender' ? 'ClamAV reports threats when a scan finds them (shown above).' : 'No threats recorded.' })); }
      catch (e) { clear(threats).append(h('p', { class: 'muted' }, e.message)); }
    };
    clear(box).append(
      h('div', { class: 'panel stack' }, h('div', { class: 'row spread' }, h('h3', { style: { margin: 0 } }, 'Protection'), h('span', { class: 'chip ' + chip[0] }, chip[1])),
        h('dl', { class: 'kv' }, h('dt', null, 'Engine'), h('dd', null, sigLine),
          h('dt', null, 'Real-time protection'), h('dd', null, row.enabled ? (row.realtime ? 'On' : 'Off') : 'Not available'),
          h('dt', null, 'Intelligence updated'), h('dd', null, row.updatedAt && row.updatedAt.indexOf('0001') !== 0 ? fmtAgo(row.updatedAt) + ' (Helm updates it every day)' : 'Not yet'),
          row.hint ? [h('dt', null, 'Note'), h('dd', null, row.hint)] : null),
        row.err ? h('div', { class: 'notice bad' }, row.err) : null,
        h('div', { class: 'row' }, actionButton('Update intelligence now', async () => { await runCmd(id, 'av.update', {}, { wait: 80, keepAlive: true }); await runCmd(id, 'av.status', {}, { wait: 40 }); toast('Updated', 'ok'); load(); }, 'primary'), actionButton('Recheck', async () => { await runCmd(id, 'av.status', {}, { wait: 40 }); load(); }))),
      h('div', { class: 'panel stack' }, h('h3', { style: { margin: 0 } }, 'Scan'),
        h('div', { class: 'row' }, scanBtn('Quick scan', 'quick', 'primary'), scanBtn('Full scan', 'full')),
        h('div', { class: 'row', style: { flexWrap: 'nowrap' } }, path, actionButton('Scan this folder', async () => { if (!path.value.trim()) throw new Error('Type a folder first.'); const r = await runCmd(id, 'av.scan', { kind: 'path', path: path.value.trim() }, { wait: 80, keepAlive: true }); out.classList.remove('hidden'); out.textContent = r && r.infected ? (r.infected.join('\n') || 'No threats found.') : 'Scan finished.'; })),
        out),
      h('div', { class: 'panel' }, h('h3', null, 'Threat history'), threats));
    loadThreats();
  };
  load();
}

// ---------- EDR tab ----------
function tabEdr(body, dev, id) {
  if (!needOnline(dev, body)) return;
  body.append(setupButton(dev, id, ['edr']));
  const iso = h('div'), view = h('div', { class: 'stack' }, h('span', { class: 'spinner' }));
  const mins = h('select', null, [[30, '30 minutes'], [120, '2 hours'], [480, '8 hours'], [1440, '24 hours']].map(([v, l]) => h('option', { value: v, selected: v === 120 }, l)));
  const snap = async () => {
    clear(view).append(h('span', { class: 'spinner' }));
    try {
      const r = await runCmd(id, 'edr.snapshot', {}, { wait: 80, keepAlive: true });
      const flagged = (r.processes || []).filter(p => p.flags && p.flags.length), conns = (r.connections || []);
      const listen = conns.filter(c => c.state === 'Listen'), est = conns.filter(c => c.state !== 'Listen');
      clear(iso).append(r.isolated ? h('div', { class: 'notice bad row spread' }, h('span', null, h('b', null, 'This PC is isolated.'), ' It can only reach the Helm server.'), actionButton('Release now', async () => { await runCmd(id, 'edr.release', {}, { wait: 60 }); toast('Released', 'ok'); snap(); }, 'primary'))
        : h('div', { class: 'row' }, h('label', null, 'Isolate for ', mins), actionButton('Isolate this PC', async () => {
          if (!(await confirmDialog('Cut ' + dev.name + ' off from every network except this console? Use this when it may be infected. It releases itself after the time you chose.', 'Isolate', true))) return;
          await ensureStepUp(); await runCmd(id, 'edr.isolate', { minutes: Number(mins.value) }, { wait: 80 }); toast('Isolated', 'ok'); snap();
        }, 'danger')));
      clear(view).append(
        h('div', { class: 'row' }, h('span', { class: 'chip ' + (flagged.length ? 'bad' : 'ok') }, flagged.length ? flagged.length + (flagged.length === 1 ? ' process' : ' processes') + ' flagged' : 'Nothing suspicious found'), h('span', { class: 'muted small-text' }, `${r.total} processes · ${listen.length} listening ports · ${est.length} connections · checked just now`), actionButton('Check again', async () => snap(), 'small')),
        h('div', { class: 'panel flush' }, h('div', { class: 'phead' }, h('h3', null, 'Flagged processes')),
          table(['Process', 'PID', 'Why', 'Path'].map(x => ({ label: x })), flagged.map(p => h('tr', null, h('td', null, p.name), h('td', { class: 'num' }, p.pid), h('td', null, p.flags.join('; ')), h('td', { title: p.cmdline || '' }, (p.path || '').slice(0, 90)))), { empty: 'No flags. Flags cover programs running from temp or download folders, deleted executables, look-alike system names, encoded PowerShell and reverse-shell patterns.' })),
        h('div', { class: 'panel flush' }, h('div', { class: 'phead' }, h('h3', null, 'Network')),
          table(['Process', 'Local', 'Remote', 'State'].map(x => ({ label: x })), conns.slice(0, 200).map(c => h('tr', null, h('td', null, c.proc || c.pid || ''), h('td', null, c.local), h('td', null, c.remote || ''), h('td', null, c.state))), { empty: 'No connections' })),
        h('div', { class: 'panel flush' }, h('div', { class: 'phead' }, h('h3', null, 'Start-up and persistence'), h('span', { class: 'sub' }, 'Things that run again after a restart')),
          table([{ label: 'Entry' }], (r.persistence || []).slice(0, 300).map(x => h('tr', null, h('td', null, x))), { empty: 'Nothing found' })));
    } catch (e) { clear(view).append(h('div', { class: 'notice bad' }, e.message)); }
  };
  body.append(h('div', { class: 'stack' }, iso, view));
  snap();
}

// ---------- Plan & modules tab ----------
function tabPlan(body, dev, id) {
  const pick = modulePicker(dev.modules || ['rmm']);
  body.append(h('div', { class: 'panel stack' }, h('h3', { style: { margin: 0 } }, 'Plan & modules'),
    h('p', { class: 'muted', style: { margin: 0 } }, 'The agent on the PC is always the same. Switching a module on or off only changes what this console is allowed to do with it.'), pick.node,
    actionButton('Save plan', async () => {
      const modules = pick.get(); if (!modules.length) throw new Error('Pick at least one module.');
      await api('POST', `/api/devices/${id}/modules`, { modules }); dev.modules = modules; S.devices = null; toast('Plan saved', 'ok'); location.hash = `#/d/${id}`;
    }, 'primary')),
    h('div', { class: 'panel stack' }, h('h3', { style: { margin: 0 } }, 'Remove this PC'),
      h('p', { class: 'muted', style: { margin: 0 } }, 'Uninstalls the agent when the PC is online, then forgets the PC.'),
      actionButton('Remove ' + dev.name, async () => {
        if (!(await confirmDialog('Remove ' + dev.name + ' from Helm?', 'Remove', true))) return;
        if (dev.online) { try { await ensureStepUp(); await runCmd(id, 'agent.uninstall', {}, { wait: 30 }); } catch (e) { /* offline or already gone */ } }
        await api('DELETE', '/api/devices/' + id); S.devices = null; location.hash = '#/devices';
      }, 'danger')));
}

// ---------- Antivirus page: engine versions across the fleet ----------
route(/^\/av$/, viewAV);
async function viewAV() {
  const box = h('div', { class: 'stack' }, h('span', { class: 'spinner' }));
  shell('av', [pageHead('Antivirus', 'Threat intelligence for every PC that has the Antivirus module'), box]);
  const my = routeToken;
  const load = async () => {
    let r; try { r = await api('GET', '/api/av'); } catch (e) { clear(box).append(h('div', { class: 'notice bad' }, e.message)); return; }
    if (my !== routeToken) return;
    const c = r.counts || {}, total = (r.rows || []).length;
    const stateChip = s => ({ current: h('span', { class: 'chip ok' }, 'Up to date'), stale: h('span', { class: 'chip bad' }, 'Out of date'), missing: h('span', { class: 'chip bad' }, 'No engine'), unknown: h('span', { class: 'chip warn' }, 'Checking'), error: h('span', { class: 'chip bad' }, 'Error') }[s]);
    const tile = (n, l, cls) => h('div', { class: 'tile ' + cls }, h('div', { class: 'tl' }, l), h('div', { class: 'tv' }, String(n)));
    clear(box).append(
      h('div', { class: 'panel stack' }, h('div', { class: 'row spread' }, h('div', null, h('h3', { style: { margin: 0 } }, 'Intelligence updates itself'),
        h('p', { class: 'muted', style: { margin: '4px 0 0', maxWidth: '70ch' } }, 'New threats appear every day, so Helm tells every PC to fetch fresh definitions from its antivirus vendor at least every ' + r.everyHours + ' hours and reads the engine version back. ' + r.engines)),
        actionButton('Update all now', async () => { const x = await api('POST', '/api/av/update', {}); toast('Updating ' + plural(x.started, 'PC'), 'ok'); setTimeout(load, 4000); }, 'primary')),
        h('div', { class: 'row tight muted small-text' }, r.lastUpdate && r.lastUpdate.indexOf('0001') !== 0 ? 'Last fleet update ' + fmtAgo(r.lastUpdate) : 'No update has run yet')),
      total ? h('div', { class: 'tiles' }, tile(c.current || 0, 'Up to date', 'ok'), tile(c.stale || 0, 'Out of date', (c.stale ? 'bad' : 'ok')), tile((c.missing || 0) + (c.error || 0), 'Need attention', (c.missing || c.error ? 'bad' : 'ok')), tile(c.unknown || 0, 'Checking', 'info')) : null,
      h('div', { class: 'panel flush' }, h('div', { class: 'phead' }, h('h3', null, 'Engine versions')),
        table(['PC', 'Engine', 'Version', 'Real-time', 'Updated', 'State', ''].map(x => ({ label: x })), (r.rows || []).map(x => h('tr', null,
          h('td', null, h('a', { href: '#/d/' + x.id + '/antivirus' }, x.name), x.online ? null : h('span', { class: 'muted' }, ' offline')), h('td', null, x.engine || '–'), h('td', { title: x.signatures || '' }, (x.signatures || '–').slice(0, 40)),
          h('td', null, x.enabled ? (x.realtime ? 'On' : 'Off') : '–'), h('td', null, x.updatedAt && x.updatedAt.indexOf('0001') !== 0 ? fmtAgo(x.updatedAt) : 'Never'), h('td', null, stateChip(x.state)),
          h('td', null, x.online ? actionButton('Update', async () => { await api('POST', `/api/devices/${x.id}/cmd`, { name: 'av.update', args: {}, wait: 0 }); toast('Updating ' + x.name, 'ok'); setTimeout(load, 4000); }, 'small') : null))),
          { empty: 'No PC has the Antivirus module yet. Add it under Plan & modules on a PC.' })));
  };
  load(); every(20000, load);
}

// ---------- stand-alone session page (terminal / remote screen in its own tab) ----------
route(/^\/session\/([^/]+)\/(terminal|screen)$/, async (id, kind) => {
  const app = clear($('#app'));
  const body = h('div', { class: 'sessionbody' });
  app.append(h('div', { class: 'sessionpage' }, h('div', { class: 'sessionbar' }, h('span', { class: 'spinner' })), body));
  let dev;
  try { dev = await api('GET', '/api/devices/' + id); } catch (e) { body.append(h('div', { class: 'notice bad' }, e.message)); return; }
  if (!dev.approved || !hasMod(dev, 'rmm')) { body.append(h('div', { class: 'notice warn' }, 'This PC’s plan does not include remote management.')); return; }
  const title = (kind === 'screen' ? 'Remote screen' : 'Terminal') + ' · ' + dev.name;
  document.title = title + ' · Helm';
  clear($('.sessionbar')).append(h('div', { class: 'row', style: { gap: '10px' } }, deviceArt(dev, 28), h('b', null, title), deviceChip(dev)),
    h('div', { class: 'row tight' }, h('a', { class: 'btn small', href: '#/d/' + id }, 'PC details'), h('button', { class: 'small', onclick: () => window.close() }, 'Close tab')));
  (kind === 'screen' ? tabScreen : tabTerminal)(body, dev, id);
});
