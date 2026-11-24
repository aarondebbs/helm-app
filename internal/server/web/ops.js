'use strict';
/* Helm console: automation (scripts, schedules, runs) and software (deployment, inventory). (Loaded after app.js.) */

function describeTarget(t) {
  if (!t) return '–';
  if (t.all) return 'All PCs';
  if (t.group) return 'Group: ' + t.group;
  if (t.tag) return 'Tag: ' + t.tag;
  return plural((t.devices || []).length, 'PC');
}

// ---------- runs ----------
async function showRun(runId, title) {
  let run = await api('GET', '/api/runs/' + runId);
  const body = h('div', { class: 'stack' });
  let closed = false;
  const draw = () => {
    const done = run.results.filter(r => r.status !== 'running').length;
    clear(body).append(
      h('div', { class: 'row spread' }, h('div', null, h('span', { class: 'badge ' + (run.status === 'done' ? 'done' : 'running') }, run.status === 'done' ? 'finished' : 'running'),
        h('span', { class: 'muted' }, `  ${done} of ${run.results.length} PCs done`)), h('span', { class: 'muted small-text' }, 'Started ' + fmtTime(run.started))),
      h('div', { class: 'bar' }, h('i', { style: { width: pct(done, run.results.length) + '%' } })),
      h('div', { class: 'stack', style: { gap: '8px', maxHeight: '50vh', overflow: 'auto' } }, run.results.map(r => h('details', { class: 'panel flush fold', open: r.status === 'error' || run.results.length === 1 },
        h('summary', null, h('span', { class: 'badge ' + r.status }, r.status), '  ', h('b', null, r.name), r.err ? h('span', { class: 'muted' }, ' · ' + r.err) : null),
        (r.output || r.err) ? h('pre', { class: 'out', style: { margin: '0 14px 14px', maxHeight: '240px' } }, (r.output || '') + (r.output && r.err ? '\n' : '') + (r.err && !r.output ? r.err : '')) : null))));
  };
  draw();
  const poll = (async () => {
    while (!closed && run.status !== 'done') {
      await sleep(2500);
      try { run = await api('GET', '/api/runs/' + runId); } catch (e) { return; }
      if (!closed) draw();
    }
  })();
  await modal(title || run.title, body, [{ label: 'Close', value: null }], { wide: true });
  closed = true; await poll;
}

// ---------- script dialogs ----------
const SCRIPT_TEMPLATES = [
  ['Clean temporary files', 'powershell', 'Get-ChildItem "$env:SystemRoot\\Temp" -Recurse -Force -ErrorAction SilentlyContinue | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue\n"Temp folder cleaned"'],
  ['Flush DNS cache', 'cmd', 'ipconfig /flushdns'],
  ['List local administrators', 'powershell', 'Get-LocalGroupMember -Group Administrators | Format-Table Name, ObjectClass -AutoSize | Out-String'],
  ['Disk usage summary', 'powershell', 'Get-PSDrive -PSProvider FileSystem | Select-Object Name, @{n="UsedGB";e={[math]::Round($_.Used/1GB,1)}}, @{n="FreeGB";e={[math]::Round($_.Free/1GB,1)}} | Format-Table -AutoSize | Out-String'],
  ['Restart Print Spooler', 'powershell', 'Restart-Service -Name Spooler -Force\nGet-Service Spooler | Out-String'],
  ['Last boot time', 'powershell', '(Get-CimInstance Win32_OperatingSystem).LastBootUpTime'],
];

async function scriptEditor(existing) {
  const s = Object.assign({ name: '', desc: '', shell: 'powershell', body: '', timeout: 120 }, existing || {});
  const name = h('input', { type: 'text', maxLength: 80, value: s.name, placeholder: 'e.g. Clear browser caches' });
  const desc = h('input', { type: 'text', maxLength: 300, value: s.desc, placeholder: 'What does it do?' });
  const shellSel = h('select', null, h('option', { value: 'powershell', selected: s.shell !== 'cmd' }, 'PowerShell'), h('option', { value: 'cmd', selected: s.shell === 'cmd' }, 'Command Prompt'));
  const timeout = h('input', { type: 'number', min: 5, max: 10800, value: s.timeout, style: { width: '7em' } });
  const body = h('textarea', { class: 'code', rows: 12, spellcheck: false, style: { width: '100%' } }, s.body);
  const tpl = h('select', { onchange: e => { const t = SCRIPT_TEMPLATES[e.target.value]; if (t) { name.value = name.value || t[0]; shellSel.value = t[1]; body.value = t[2]; } e.target.value = ''; } },
    h('option', { value: '' }, 'Start from a template…'), SCRIPT_TEMPLATES.map((t, i) => h('option', { value: i }, t[0])));
  const form = h('div', { class: 'stack' }, existing ? null : tpl, h('label', { class: 'field' }, h('span', null, 'Name'), name), h('label', { class: 'field' }, h('span', null, 'Description'), desc),
    h('div', { class: 'row' }, h('label', { class: 'field' }, h('span', null, 'Shell'), shellSel), h('label', { class: 'field' }, h('span', null, 'Timeout (seconds)'), timeout)),
    h('label', { class: 'field' }, h('span', null, 'Script'), body), h('div', { class: 'notice warn' }, 'Scripts run as SYSTEM on the PC, with full control of it. Only run scripts you trust.'));
  const ok = await modal(existing ? 'Edit script' : 'New script', form, [{ label: 'Cancel', value: false }, { label: 'Save script', value: true, cls: 'primary' }], { wide: true });
  if (!ok) return null;
  try {
    const saved = await api(existing ? 'PUT' : 'POST', '/api/scripts' + (existing ? '/' + existing.id : ''), { name: name.value, desc: desc.value, shell: shellSel.value, body: body.value, timeout: Number(timeout.value) });
    toast('Script saved', 'ok'); return saved;
  } catch (e) { toast(e.message, 'bad'); return null; }
}

// Run a library script or ad-hoc commands. target is optional; if missing the user picks one.
async function runScriptDialog(target, scriptId) {
  const [scripts, devs] = await Promise.all([api('GET', '/api/scripts'), getDevices()]);
  const picker = target ? null : targetPicker(devs);
  const sel = h('select', null, h('option', { value: '' }, 'Ad-hoc script (type below)'), scripts.map(s => h('option', { value: s.id, selected: s.id === scriptId }, s.name)));
  const shellSel = h('select', null, h('option', { value: 'powershell' }, 'PowerShell'), h('option', { value: 'cmd' }, 'Command Prompt'));
  const body = h('textarea', { class: 'code', rows: 8, spellcheck: false, style: { width: '100%' }, placeholder: 'PowerShell or cmd commands' });
  const adhoc = h('div', { class: 'stack' }, h('label', { class: 'field' }, h('span', null, 'Shell'), shellSel), body);
  const sync = () => adhoc.classList.toggle('hidden', !!sel.value);
  sel.addEventListener('change', sync); sync();
  const form = h('div', { class: 'stack' }, h('label', { class: 'field' }, h('span', null, 'Script'), sel), adhoc,
    target ? h('p', { class: 'muted', style: { margin: 0 } }, 'Runs on ' + plural(target.devices ? target.devices.length : 0, 'selected PC') + '.') : h('div', { class: 'field' }, h('span', null, 'Run on'), picker.el),
    h('div', { class: 'notice warn' }, 'Runs as SYSTEM, without a prompt to the person at the PC. PCs that are offline are skipped.'));
  const ok = await modal('Run script', form, [{ label: 'Cancel', value: false }, { label: 'Run now', value: true, cls: 'primary' }], { wide: true });
  if (!ok) return;
  const t = target || picker.get();
  if (picker && !picker.valid()) { toast('Choose at least one PC', 'bad'); return; }
  try {
    const run = await api('POST', '/api/run/script', { scriptId: sel.value, body: body.value, shell: shellSel.value, timeout: 300, target: t });
    await showRun(run.id, 'Script results');
  } catch (e) { toast(e.message, 'bad'); }
}

// ---------- schedule dialog ----------
const ACTIONS = { script: 'Run a script', scan: 'Security scan', 'updates.install': 'Install system updates (Windows Update, apt/dnf, macOS)', 'winget.upgrade_all': 'Update apps (winget on Windows, Homebrew on Mac)', restart: 'Restart' };
const DAYS = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'];
function describeWhen(s) {
  if (s.kind === 'interval') return s.every % 60 === 0 && s.every >= 60 ? `Every ${s.every / 60} hour${s.every === 60 ? '' : 's'}` : `Every ${s.every} minutes`;
  if (s.kind === 'daily') return 'Daily at ' + s.at;
  return (s.days || []).map(d => DAYS[d]).join(', ') + ' at ' + s.at;
}

async function scheduleEditor(existing) {
  const [scripts, devs] = await Promise.all([api('GET', '/api/scripts'), getDevices()]);
  const s = Object.assign({ name: '', action: 'scan', scriptId: '', kind: 'daily', every: 60, at: '03:00', days: [1, 2, 3, 4, 5], enabled: true, target: { all: true } }, existing || {});
  const name = h('input', { type: 'text', maxLength: 80, value: s.name, placeholder: 'e.g. Nightly security scan' });
  const action = h('select', null, Object.entries(ACTIONS).map(([k, l]) => h('option', { value: k, selected: k === s.action }, l)));
  const script = h('select', null, scripts.map(x => h('option', { value: x.id, selected: x.id === s.scriptId }, x.name)));
  const scriptField = h('label', { class: 'field' }, h('span', null, 'Script'), script);
  const kind = h('select', null, [['interval', 'Every N minutes/hours'], ['daily', 'Every day'], ['weekly', 'On certain weekdays']].map(([k, l]) => h('option', { value: k, selected: k === s.kind }, l)));
  const every_ = h('input', { type: 'number', min: 5, max: 43200, value: s.every, style: { width: '7em' } });
  const at = h('input', { type: 'time', value: s.at });
  const days = new Set(s.days);
  const dayRow = h('div', { class: 'pills' }, DAYS.map((d, i) => { const b = h('button', { type: 'button', class: 'pill' + (days.has(i) ? ' on' : ''), onclick: () => { days.has(i) ? days.delete(i) : days.add(i); b.classList.toggle('on'); } }, d); return b; }));
  const timing = h('div', { class: 'stack' });
  const sync = () => {
    scriptField.classList.toggle('hidden', action.value !== 'script');
    clear(timing).append(kind.value === 'interval' ? h('label', { class: 'field' }, h('span', null, 'Every (minutes)'), every_) : [h('label', { class: 'field' }, h('span', null, 'At (server time)'), at), kind.value === 'weekly' ? dayRow : null]);
  };
  action.addEventListener('change', sync); kind.addEventListener('change', sync); sync();
  const picker = targetPicker(devs, s.target.group ? { mode: 'group', group: s.target.group } : s.target.tag ? { mode: 'tag', tag: s.target.tag } : (s.target.devices && s.target.devices.length) ? { mode: 'devices', devices: s.target.devices } : { mode: 'all' });
  const form = h('div', { class: 'stack' }, h('label', { class: 'field' }, h('span', null, 'Name'), name), h('label', { class: 'field' }, h('span', null, 'What to do'), action), scriptField,
    h('label', { class: 'field' }, h('span', null, 'How often'), kind), timing, h('div', { class: 'field' }, h('span', null, 'Run on'), picker.el),
    h('div', { class: 'row spread' }, h('span', null, 'Enabled'), toggle(s.enabled, v => { s.enabled = v; })),
    h('div', { class: 'muted small-text' }, 'Tasks only run on PCs that are online at that moment. Restarts show a 60 second warning to the user.'));
  const ok = await modal(existing ? 'Edit schedule' : 'New schedule', form, [{ label: 'Cancel', value: false }, { label: 'Save', value: true, cls: 'primary' }], { wide: true });
  if (!ok) return false;
  try {
    await api(existing ? 'PUT' : 'POST', '/api/schedules' + (existing ? '/' + existing.id : ''), { name: name.value, action: action.value, scriptId: action.value === 'script' ? script.value : '', kind: kind.value,
      every: Number(every_.value), at: at.value, days: [...days].sort(), enabled: s.enabled, target: picker.get() });
    toast('Schedule saved', 'ok'); return true;
  } catch (e) { toast(e.message, 'bad'); return false; }
}

// ---------- automation page ----------
route(/^\/automation(?:\/([a-z]+))?$/, viewAutomation);
function viewAutomation(tab) {
  tab = tab || 'schedules';
  const host = h('div', null, h('span', { class: 'spinner' }));
  const heads = {
    scripts: [actionButton('Run a script…', () => runScriptDialog()), actionButton('New script', async () => { if (await scriptEditor()) load(); }, 'primary')],
    schedules: [actionButton('New schedule', async () => { if (await scheduleEditor()) load(); }, 'primary')], runs: [] };
  shell('automation', [pageHead('Automation', 'Scripts, scheduled tasks and everything that has run', heads[tab] || []),
    h('div', { class: 'tabs' }, [['schedules', 'Schedules'], ['scripts', 'Script library'], ['runs', 'Run history']].map(([k, l]) => h('a', { href: '#/automation/' + k, class: tab === k ? 'active' : '' }, l))), host]);
  const my = routeToken;
  const load = async () => {
    try {
      if (tab === 'scripts') {
        const list = await api('GET', '/api/scripts'); if (my !== routeToken) return;
        clear(host).append(list.length ? h('div', { class: 'panel flush' }, table(['Name', 'Shell', 'Updated', ''].map(x => ({ label: x })), list.map(sc => h('tr', null,
          h('td', null, h('b', null, sc.name), sc.desc ? h('div', { class: 'muted small-text' }, sc.desc) : null), h('td', null, sc.shell === 'cmd' ? 'Command Prompt' : 'PowerShell'), h('td', { class: 'muted nowrap' }, fmtAgo(sc.updatedAt)),
          h('td', { class: 'right nowrap' }, h('div', { class: 'row tight', style: { justifyContent: 'flex-end' } },
            actionButton('Run', () => runScriptDialog(null, sc.id), 'small primary'), actionButton('Edit', async () => { if (await scriptEditor(sc)) load(); }, 'small'),
            actionButton('Delete', async () => { if (await confirmDialog('Delete "' + sc.name + '"? Schedules that use it are removed too.', 'Delete', true)) { await api('DELETE', '/api/scripts/' + sc.id); load(); } }, 'small danger')))))))
          : h('div', { class: 'panel' }, emptyState('📜', 'No saved scripts', 'Save scripts you use often, then run them on any PC, group or tag, or put them on a schedule.', actionButton('Create your first script', async () => { if (await scriptEditor()) load(); }, 'primary'))));
      } else if (tab === 'schedules') {
        const list = await api('GET', '/api/schedules'); if (my !== routeToken) return;
        const scripts = await api('GET', '/api/scripts'); const sn = Object.fromEntries(scripts.map(x => [x.id, x.name]));
        clear(host).append(list.length ? h('div', { class: 'panel flush' }, table(['', 'Task', 'Runs on', 'When', 'Next run', 'Last run', ''].map(x => ({ label: x })), list.map(sc => h('tr', null,
          h('td', null, toggle(sc.enabled, async v => { try { await api('PUT', '/api/schedules/' + sc.id, Object.assign({}, sc, { enabled: v })); load(); } catch (e) { toast(e.message, 'bad'); load(); } })),
          h('td', null, h('b', null, sc.name), h('div', { class: 'muted small-text' }, sc.action === 'script' ? 'Script: ' + (sn[sc.scriptId] || '(deleted)') : ACTIONS[sc.action])),
          h('td', null, describeTarget(sc.target)), h('td', null, describeWhen(sc)), h('td', { class: 'nowrap' }, sc.enabled ? fmtShort(sc.nextRun) : h('span', { class: 'muted' }, 'paused')), h('td', { class: 'muted nowrap' }, fmtAgo(sc.lastRun)),
          h('td', { class: 'right nowrap' }, h('div', { class: 'row tight', style: { justifyContent: 'flex-end' } },
            actionButton('Run now', async () => { if (sc.action === 'restart' && !(await confirmDialog('Restart every PC this schedule targets?', 'Restart', true))) return; const r = await api('POST', `/api/schedules/${sc.id}/run`, {}); showRun(r.id, sc.name); }, 'small'),
            actionButton('Edit', async () => { if (await scheduleEditor(sc)) load(); }, 'small'),
            actionButton('Delete', async () => { if (await confirmDialog('Delete schedule "' + sc.name + '"?', 'Delete', true)) { await api('DELETE', '/api/schedules/' + sc.id); load(); } }, 'small danger')))))))
          : h('div', { class: 'panel' }, emptyState('🗓️', 'No schedules yet', 'Automate scans, updates and restarts. Example: scan every machine every night, or install system updates every Sunday at 3 AM. Each machine uses its own updater, and steps that do not apply to its system are skipped.', actionButton('Create a schedule', async () => { if (await scheduleEditor()) load(); }, 'primary'))));
      } else {
        const list = await api('GET', '/api/runs'); if (my !== routeToken) return;
        clear(host).append(h('div', { class: 'panel flush' }, table(['Started', 'Task', 'Type', 'Trigger', 'Result', 'Status'].map(x => ({ label: x })), list.map(r => {
          const ok = r.results.filter(x => x.status === 'ok').length, bad = r.results.filter(x => x.status === 'error').length, sk = r.results.filter(x => x.status === 'skipped').length;
          return h('tr', { class: 'clickable', onclick: () => showRun(r.id, r.title) }, h('td', { class: 'nowrap' }, fmtShort(r.started)), h('td', null, h('b', null, r.title)), h('td', { class: 'muted' }, r.kind), h('td', { class: 'muted' }, r.trigger),
            h('td', null, `${ok} ok` + (bad ? ` · ${bad} failed` : '') + (sk ? ` · ${sk} skipped` : '')), h('td', null, h('span', { class: 'badge ' + (r.status === 'done' ? 'done' : 'running') }, r.status)));
        }), { empty: 'Nothing has run yet.' })));
      }
    } catch (e) { clear(host).append('Could not load: ' + e.message); }
  };
  load();
  if (tab === 'runs') every(8000, load);
}

// ---------- software page ----------
const POPULAR = [['7-Zip', '7zip.7zip'], ['Google Chrome', 'Google.Chrome'], ['Mozilla Firefox', 'Mozilla.Firefox'], ['VLC media player', 'VideoLAN.VLC'], ['Notepad++', 'Notepad++.Notepad++'], ['Adobe Acrobat Reader', 'Adobe.Acrobat.Reader.64-bit'], ['Zoom', 'Zoom.Zoom']];

async function uploadPackage(file, name, args) {
  const url = `/api/packages/upload?name=${encodeURIComponent(name)}&filename=${encodeURIComponent(file.name)}&args=${encodeURIComponent(args)}`;
  const send = () => fetch(url, { method: 'POST', credentials: 'same-origin', headers: { 'X-CSRF-Token': S.csrf, 'Content-Type': 'application/octet-stream' }, body: file });
  let res = await send();
  if (res.status === 428) { await askStepUp(); res = await send(); }
  let data = null; try { data = await res.json(); } catch (e) { /* empty */ }
  if (!res.ok) throw new Error((data && data.error) || 'upload failed');
  return data;
}

async function deployDialog(pkg) {
  const devs = await getDevices();
  const picker = targetPicker(devs);
  let actVal = 'install';
  const act = pkg.type === 'winget' || pkg.type === 'apt' ? segmented([['install', 'Install'], ['uninstall', 'Uninstall']], 'install', v => { actVal = v; }) : null;
  const form = h('div', { class: 'stack' }, h('div', null, h('b', null, pkg.name), h('div', { class: 'muted small-text' }, pkg.type === 'apt' ? 'apt: ' + pkg.wingetId : pkg.type === 'winget' ? 'winget: ' + pkg.wingetId + (pkg.version ? ' @ ' + pkg.version : '') : `${pkg.filename} · ${fmtBytes(pkg.size)} · SHA-256 ${pkg.sha256.slice(0, 16)}…`)),
    act, h('div', { class: 'field' }, h('span', null, 'Deploy to'), picker.el),
    h('div', { class: 'notice warn' }, 'Installs run silently as SYSTEM. Offline PCs are skipped; run it again later for those.'));
  const ok = await modal('Deploy software', form, [{ label: 'Cancel', value: false }, { label: 'Deploy', value: true, cls: 'primary' }], { wide: true });
  if (!ok) return;
  if (!picker.valid()) { toast('Choose at least one PC', 'bad'); return; }
  try { const run = await api('POST', '/api/deploy', { packageId: pkg.id, action: actVal, target: picker.get() }); await showRun(run.id, 'Deployment'); } catch (e) { toast(e.message, 'bad'); }
}

async function addPackageDialog(preset) {
  const name = h('input', { type: 'text', maxLength: 80, placeholder: 'e.g. Google Chrome', value: preset ? preset[0] : '' });
  const wid = h('input', { type: 'text', placeholder: 'e.g. Google.Chrome', value: preset ? preset[1] : '', class: 'mono' });
  const ver = h('input', { type: 'text', placeholder: 'latest', maxLength: 40 });
  const file = h('input', { type: 'file', accept: '.msi,.exe,.deb,.pkg' });
  const fname = h('input', { type: 'text', maxLength: 80, placeholder: 'Name shown in Helm' });
  const args = h('input', { type: 'text', placeholder: 'e.g. /S  or  /VERYSILENT /NORESTART', maxLength: 200, class: 'mono' });
  let mode = preset ? 'winget' : 'winget';
  const idLabel = h('span', null, 'winget package ID'), idHint = h('span', { class: 'hint' }, 'Find IDs at winget.run or with "winget search" on any PC.');
  const wBox = h('div', { class: 'stack' }, h('label', { class: 'field' }, h('span', null, 'Name'), name), h('label', { class: 'field' }, idLabel, wid, idHint), h('label', { class: 'field' }, h('span', null, 'Version (optional)'), ver));
  const uBox = h('div', { class: 'stack hidden' }, h('label', { class: 'field' }, h('span', null, 'Installer (.msi, .exe, .deb or .pkg, max 1 GB)'), file), h('label', { class: 'field' }, h('span', null, 'Name'), fname),
    h('label', { class: 'field' }, h('span', null, 'Silent install arguments'), args, h('span', { class: 'hint' }, 'MSI files install silently automatically; for .exe installers enter the vendor\'s silent switch.')));
  const seg = segmented([['winget', 'Windows: winget'], ['apt', 'Linux: apt package'], ['upload', 'Upload .msi / .exe / .deb / .pkg']], mode, v => { mode = v; wBox.classList.toggle('hidden', v === 'upload'); uBox.classList.toggle('hidden', v !== 'upload'); idLabel.textContent = v === 'apt' ? 'apt package name' : 'winget package ID'; idHint.textContent = v === 'apt' ? 'The Debian/Ubuntu package name, for example htop or nginx. Version is ignored.' : 'Find IDs at winget.run or with "winget search" on any PC.'; wid.placeholder = v === 'apt' ? 'htop' : ''; });
  const ok = await modal('Add software', h('div', { class: 'stack' }, seg, wBox, uBox), [{ label: 'Cancel', value: false }, { label: 'Add', value: true, cls: 'primary' }], { wide: true });
  if (!ok) return false;
  try {
    if (mode === 'winget') await api('POST', '/api/packages', { name: name.value, wingetId: wid.value, version: ver.value });
    else if (mode === 'apt') await api('POST', '/api/packages', { name: name.value, wingetId: wid.value, os: 'linux' });
    else {
      if (!file.files[0]) throw new Error('Choose an installer file');
      toast('Uploading…'); await uploadPackage(file.files[0], fname.value || file.files[0].name, args.value);
    }
    toast('Added to the catalog', 'ok'); return true;
  } catch (e) { toast(e.message, 'bad'); return false; }
}

route(/^\/software(?:\/([a-z]+))?$/, viewSoftware);
function viewSoftware(tab) {
  tab = tab || 'catalog';
  const host = h('div', null, h('span', { class: 'spinner' }));
  shell('software', [pageHead('Software', 'Deploy applications and see what is installed across your PCs', tab === 'catalog' ? actionButton('Add software', async () => { if (await addPackageDialog()) load(); }, 'primary') : h('a', { class: 'btn', href: '/api/reports/software', download: '' }, 'Export CSV')),
    h('div', { class: 'tabs' }, [['catalog', 'Deployment catalog'], ['inventory', 'Installed everywhere']].map(([k, l]) => h('a', { href: '#/software/' + k, class: tab === k ? 'active' : '' }, l))), host]);
  const my = routeToken;
  let q = '';
  const load = async () => {
    try {
      if (tab === 'catalog') {
        const list = await api('GET', '/api/packages'); if (my !== routeToken) return;
        const have = new Set(list.map(p => p.wingetId));
        clear(host).append(
          list.length ? h('div', { class: 'panel flush' }, table(['Software', 'Source', 'Added', ''].map(x => ({ label: x })), list.map(p => h('tr', null,
            h('td', null, h('b', null, p.name)), h('td', { class: 'muted' }, p.type === 'apt' ? 'Linux apt · ' + p.wingetId : p.type === 'winget' ? 'winget · ' + p.wingetId : `Upload · ${p.filename} (${fmtBytes(p.size)})`), h('td', { class: 'muted nowrap' }, fmtAgo(p.createdAt)),
            h('td', { class: 'right nowrap' }, h('div', { class: 'row tight', style: { justifyContent: 'flex-end' } }, actionButton('Deploy…', () => deployDialog(p), 'small primary'),
              actionButton('Remove', async () => { if (await confirmDialog('Remove "' + p.name + '" from the catalog?' + (p.type === 'upload' ? ' The uploaded file is deleted.' : ''), 'Remove', true)) { await api('DELETE', '/api/packages/' + p.id); load(); } }, 'small danger')))))))
            : h('div', { class: 'panel' }, emptyState('📦', 'Your catalog is empty', 'Add apps to install or remove on PCs in one click. Popular choices are below.')),
          h('div', { class: 'panel', style: { marginTop: '16px' } }, h('div', { class: 'phead' }, h('h3', null, 'Quick add'), h('span', { class: 'sub' }, 'Popular apps installed with winget')),
            h('div', { class: 'pills' }, POPULAR.filter(p => !have.has(p[1])).map(p => actionButton('+ ' + p[0], async () => { await api('POST', '/api/packages', { name: p[0], wingetId: p[1] }); toast(p[0] + ' added', 'ok'); load(); }, 'pill')))),
          h('p', { class: 'muted small-text', style: { marginTop: '12px' } }, 'winget needs to be available on the PC (Windows 10 1809+ with App Installer). Uploaded installers are checked against their SHA-256 on the PC before they run.'));
      } else {
        const rows = await api('GET', '/api/software'); if (my !== routeToken) return;
        const draw = () => {
          const f = rows.filter(r => !q || (r.name + ' ' + r.publisher).toLowerCase().includes(q));
          const search = h('input', { type: 'search', placeholder: 'Search installed software…', value: q, 'aria-label': 'Search software', style: { width: '100%' } });
          search.addEventListener('input', () => { q = search.value.toLowerCase(); const p = search.selectionStart; draw(); const n = $('input[aria-label="Search software"]'); if (n) { n.focus(); n.setSelectionRange(p, p); } });
          clear(host).append(h('div', { class: 'toolbar' }, h('div', { class: 'grow' }, search), h('span', { class: 'muted' }, plural(f.length, 'program version'))),
            rows.length ? h('div', { class: 'panel flush' }, table(['Software', 'Version', 'Publisher', 'PCs', 'Known vulnerabilities'].map(x => ({ label: x })), f.slice(0, 500).map(r => h('tr', { class: 'clickable', onclick: () => affectedDialog({ severity: r.worst || 'info', title: r.name + ' ' + r.version, devices: r.devices }) },
              h('td', null, h('b', null, r.name)), h('td', { class: 'mono' }, r.version), h('td', { class: 'muted' }, r.publisher), h('td', null, String(r.devices.length)),
              h('td', null, r.cves ? [sevBadge(r.worst), h('span', { class: 'muted' }, ' ' + plural(r.cves, 'CVE')), r.exploited ? h('span', { class: 'badge kev', style: { marginLeft: '6px' } }, 'exploited') : null] : h('span', { class: 'muted' }, '–'))))))
              : h('div', { class: 'panel' }, emptyState('📋', 'No inventory yet', 'Software is collected by security scans. Run one from the Security page.', h('a', { class: 'btn primary', href: '#/security' }, 'Go to Security'))));
        };
        draw();
      }
    } catch (e) { clear(host).append('Could not load: ' + e.message); }
  };
  load();
}
