'use strict';
/* Helm console: core helpers, shell, routing, login, devices, enrollment, activity.
   All dynamic content is inserted with textContent / createTextNode (never innerHTML)
   because device-reported data is untrusted. */

// ---------- tiny DOM helper ----------
// Native append() turns null/false into the text "null"/"false" and stringifies arrays; make it
// skip empty values and accept (nested) arrays so conditional children are easy to write.
(function () {
  const native = Element.prototype.append;
  Element.prototype.append = function (...kids) {
    return native.apply(this, kids.flat(Infinity).filter(k => k != null && k !== false));
  };
})();
function append(el, kids) {
  for (const k of kids.flat(Infinity)) {
    if (k == null || k === false) continue;
    el.append(k instanceof Node ? k : document.createTextNode(String(k)));
  }
  return el;
}
function h(tag, props, ...kids) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(props || {})) {
    if (v == null || v === false) continue;
    if (k === 'class') el.className = v;
    else if (k.startsWith('on')) el.addEventListener(k.slice(2), v);
    else if (k === 'style' && typeof v === 'object') { for (const [sk, sv] of Object.entries(v)) { if (sk.startsWith('--')) el.style.setProperty(sk, sv); else el.style[sk] = sv; } }
    else if (k in el && k !== 'list') el[k] = v;
    else el.setAttribute(k, v === true ? '' : v);
  }
  return append(el, kids);
}
const SVGNS = 'http://www.w3.org/2000/svg';
function svg(tag, attrs, ...kids) {
  const el = document.createElementNS(SVGNS, tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v == null || v === false) continue;
    if (k === 'style' && typeof v === 'object') Object.assign(el.style, v); else el.setAttribute(k, v);
  }
  for (const c of kids.flat(Infinity)) if (c != null && c !== false) el.append(c instanceof Node ? c : document.createTextNode(String(c)));
  return el;
}
const $ = (sel, root) => (root || document).querySelector(sel);
function clear(el) { while (el.firstChild) el.removeChild(el.firstChild); return el; }
const sleep = ms => new Promise(r => setTimeout(r, ms));

// ---------- formatting ----------
function fmtBytes(n) {
  if (n == null || isNaN(n)) return '–';
  const u = ['B', 'KB', 'MB', 'GB', 'TB']; let i = 0; n = Number(n);
  while (n >= 1024 && i < u.length - 1) { n /= 1024; i++; }
  return (n >= 100 || i === 0 ? n.toFixed(0) : n.toFixed(1)) + ' ' + u[i];
}
// Go serialises a zero time.Time as 0001-01-01…; treat that as "never".
const isZero = t => !t || String(t).startsWith('0001-');
function fmtAgo(t) {
  if (isZero(t)) return 'never';
  const s = Math.max(0, (Date.now() - new Date(t).getTime()) / 1000);
  if (s < 60) return 'just now';
  if (s < 3600) return Math.floor(s / 60) + ' min ago';
  if (s < 86400) return Math.floor(s / 3600) + ' h ago';
  return Math.floor(s / 86400) + ' d ago';
}
function fmtDur(sec) {
  sec = Number(sec) || 0;
  const d = Math.floor(sec / 86400), hh = Math.floor(sec % 86400 / 3600), m = Math.floor(sec % 3600 / 60);
  return (d ? d + 'd ' : '') + (hh ? hh + 'h ' : '') + m + 'm';
}
const fmtTime = t => isZero(t) ? '–' : new Date(t).toLocaleString();
const fmtShort = t => isZero(t) ? '–' : new Date(t).toLocaleString([], { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' });
function fmtSpan(a, b) {
  if (isZero(a) || isZero(b)) return '';
  const s = Math.max(0, Math.round((new Date(b) - new Date(a)) / 1000));
  return s < 60 ? s + 's' : s < 3600 ? Math.floor(s / 60) + 'm ' + (s % 60) + 's' : Math.floor(s / 3600) + 'h ' + Math.floor(s % 3600 / 60) + 'm';
}
const pct = (a, b) => b ? Math.round(a / b * 100) : 0;
const plural = (n, w) => n + ' ' + w + (n === 1 ? '' : 's');
const cap = s => s ? s[0].toUpperCase() + s.slice(1) : s;

// safe localStorage (can throw or be empty in some contexts)
const store = {
  get(k, d) { try { const v = localStorage.getItem('helm.' + k); return v == null ? d : JSON.parse(v); } catch (e) { return d; } },
  set(k, v) { try { localStorage.setItem('helm.' + k, JSON.stringify(v)); } catch (e) { /* ignore */ } },
};

// ---------- state, toasts, modals ----------
const S = { csrf: '', user: '', devices: null, devicesAt: 0, alerts: 0, version: '' };
let routeToken = 0;           // bumped on every navigation to cancel stale async work
let cleanups = [];            // functions run when leaving a view
const onLeave = fn => cleanups.push(fn);
function every(ms, fn) { const t = setInterval(fn, ms); onLeave(() => clearInterval(t)); return t; }

function toast(msg, kind) {
  const t = h('div', { class: 'toast ' + (kind || '') }, msg);
  $('#toast-root').append(t);
  setTimeout(() => t.remove(), kind === 'bad' ? 9000 : 4500);
}

function modal(title, body, buttons, opt) {
  return new Promise(resolve => {
    const root = $('#modal-root');
    const close = v => { backdrop.remove(); document.removeEventListener('keydown', onKey); resolve(v); };
    const onKey = e => { if (e.key === 'Escape') close(buttons && buttons.length ? false : null); };
    const foot = h('div', { class: 'row', style: { justifyContent: 'flex-end', marginTop: '20px' } },
      (buttons || [{ label: 'Close', value: null }]).map(b =>
        h('button', { class: b.cls || '', onclick: () => close(typeof b.value === 'function' ? b.value() : b.value) }, b.label)));
    const backdrop = h('div', { class: 'backdrop' }, h('div', { class: 'modal' + (opt && opt.wide ? ' wide' : ''), role: 'dialog', 'aria-modal': 'true', 'aria-label': title }, h('h2', null, title), body, foot));
    root.append(backdrop);
    document.addEventListener('keydown', onKey);
    const first = backdrop.querySelector('input,select,textarea,button.primary');
    if (first) first.focus();
  });
}
const confirmDialog = (msg, okLabel, danger) =>
  modal('Please confirm', h('p', null, msg), [{ label: 'Cancel', value: false }, { label: okLabel || 'OK', value: true, cls: danger ? 'danger' : 'primary' }]);

// ---------- API ----------
let stepUpPending = null;
async function rawFetch(method, path, body) {
  const opt = { method, credentials: 'same-origin', headers: {} };
  if (body !== undefined) { opt.headers['Content-Type'] = 'application/json'; opt.body = JSON.stringify(body); }
  if (S.csrf) opt.headers['X-CSRF-Token'] = S.csrf;
  const res = await fetch(path, opt);
  let data = null;
  try { data = await res.json(); } catch (e) { /* empty body */ }
  return { res, data };
}

function askStepUp() {
  if (stepUpPending) return stepUpPending;
  stepUpPending = (async () => {
    for (;;) {
      const me = (await rawFetch('GET', '/api/me')).data, usePw = !!me && me.totp === false;
      const code = usePw ? h('input', { type: 'password', autocomplete: 'current-password', placeholder: 'Password' })
        : h('input', { type: 'text', inputMode: 'numeric', autocomplete: 'one-time-code', maxLength: 6, placeholder: '123456', style: { fontSize: '1.4rem', letterSpacing: '.3em', width: '9em', textAlign: 'center' } });
      const body = h('div', { class: 'stack' },
        h('p', { class: 'muted', style: { margin: 0 } }, usePw ? 'Two-step verification is off. Confirm with your password.' : 'This action needs a fresh code from your authenticator app. If you just signed in, wait for the next code to appear.'), code);
      code.addEventListener('keydown', e => { if (e.key === 'Enter') $('#modal-root button.primary').click(); });
      const ok = await modal(usePw ? 'Confirm with your password' : 'Confirm with your authenticator', body, [{ label: 'Cancel', value: false }, { label: 'Confirm', value: true, cls: 'primary' }]);
      if (!ok) throw new Error('cancelled');
      const { res, data } = await rawFetch('POST', '/api/stepup', usePw ? { password: code.value } : { code: code.value });
      if (res.ok) return true;
      toast((data && data.error) || 'Code rejected', 'bad');
    }
  })().finally(() => { stepUpPending = null; });
  return stepUpPending;
}

async function ensureStepUp() {
  const { data } = await rawFetch('GET', '/api/me');
  if (!data || !data.stepUp) await askStepUp();
}

async function api(method, path, body, retried) {
  const { res, data } = await rawFetch(method, path, body);
  if (res.status === 428 && !retried) { await askStepUp(); return api(method, path, body, true); }
  if (res.status === 401 && path !== '/api/login' && (!data || data.error === 'not signed in')) { showLogin(); throw new Error('signed out'); }
  if (!res.ok) throw new Error((data && data.error) || res.statusText || 'request failed');
  return data;
}

// Run a device command and wait for it, polling long-running jobs.
async function runCmd(id, name, args, opt) {
  opt = opt || {};
  const my = routeToken;
  let job = await api('POST', `/api/devices/${id}/cmd`, { name, args, wait: opt.wait || 25 });
  while (job.status === 'running') {
    if (opt.onProgress) opt.onProgress(job);
    await sleep(2000);
    if (my !== routeToken && !opt.keepAlive) throw new Error('cancelled');
    job = await api('GET', '/api/jobs/' + job.id);
  }
  if (job.status === 'error') throw new Error(job.err || 'command failed');
  return job.data === undefined ? null : job.data;
}

// Wrap an async action on a button: disables it and shows errors as toasts.
function action(btn, fn) {
  return async () => {
    btn.disabled = true;
    try { await fn(); } catch (e) { if (e.message !== 'cancelled') toast(e.message, 'bad'); }
    finally { btn.disabled = false; }
  };
}
function actionButton(label, fn, cls) {
  const b = h('button', { class: cls || '' }, label);
  b.addEventListener('click', action(b, fn));
  return b;
}
function copyButton(getText, label) {
  const b = h('button', { class: 'small' }, label || 'Copy');
  b.addEventListener('click', async () => {
    try { await navigator.clipboard.writeText(getText()); toast('Copied', 'ok'); }
    catch (e) { toast('Copy failed: select the text manually', 'bad'); }
  });
  return b;
}
function downloadFile(url) { const a = h('a', { href: url, download: '' }); document.body.append(a); a.click(); a.remove(); }

// Devices list with a short cache; used by pickers, search and several pages.
async function getDevices(force) {
  if (!force && S.devices && Date.now() - S.devicesAt < 8000) return S.devices;
  S.devices = await api('GET', '/api/devices'); S.devicesAt = Date.now();
  return S.devices;
}

// ---------- icons ----------
const ICON = {
  dash: 'M3 3h7v9H3zM14 3h7v5h-7zM14 12h7v9h-7zM3 16h7v5H3z',
  devices: 'M4 5h16v11H4zM8 21h8M12 16v5',
  shield: 'M12 3l8 3v6c0 5-3.5 8-8 9-4.5-1-8-4-8-9V6z',
  box: 'M21 8l-9-5-9 5v8l9 5 9-5zM3 8l9 5 9-5M12 13v8',
  zap: 'M13 2L4 14h7l-1 8 9-12h-7z',
  bell: 'M6 8a6 6 0 0112 0c0 7 3 8 3 8H3s3-1 3-8M10 21a2 2 0 004 0',
  video: 'M3 6h12v12H3zM15 10l6-3v10l-6-3',
  file: 'M6 3h9l4 4v14H6zM14 3v5h5M9 13h6M9 17h6',
  plus: 'M12 5v14M5 12h14',
  list: 'M8 6h13M8 12h13M8 18h13M3 6h.01M3 12h.01M3 18h.01',
  gear: 'M12 15a3 3 0 100-6 3 3 0 000 6zM19.4 15a1.7 1.7 0 00.3 1.8l.1.1a2 2 0 11-2.8 2.8l-.1-.1a1.7 1.7 0 00-1.8-.3 1.7 1.7 0 00-1 1.5V21a2 2 0 11-4 0v-.1a1.7 1.7 0 00-1.1-1.5 1.7 1.7 0 00-1.8.3l-.1.1a2 2 0 11-2.8-2.8l.1-.1a1.7 1.7 0 00.3-1.8 1.7 1.7 0 00-1.5-1H3a2 2 0 110-4h.1a1.7 1.7 0 001.5-1.1 1.7 1.7 0 00-.3-1.8l-.1-.1a2 2 0 112.8-2.8l.1.1a1.7 1.7 0 001.8.3H9a1.7 1.7 0 001-1.5V3a2 2 0 114 0v.1a1.7 1.7 0 001 1.5 1.7 1.7 0 001.8-.3l.1-.1a2 2 0 112.8 2.8l-.1.1a1.7 1.7 0 00-.3 1.8V9a1.7 1.7 0 001.5 1H21a2 2 0 110 4h-.1a1.7 1.7 0 00-1.5 1z',
  search: 'M11 19a8 8 0 100-16 8 8 0 000 16zM21 21l-4.3-4.3',
  menu: 'M3 6h18M3 12h18M3 18h18',
  out: 'M9 21H5a2 2 0 01-2-2V5a2 2 0 012-2h4M16 17l5-5-5-5M21 12H9',
  sun: 'M12 16a4 4 0 100-8 4 4 0 000 8zM12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2 12h2M20 12h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4',
  moon: 'M21 12.8A9 9 0 1111.2 3a7 7 0 009.8 9.8z',
  check: 'M5 12l5 5L20 7',
  lock: 'M5 11h14v10H5zM8 11V7a4 4 0 018 0v4',
  refresh: 'M21 12a9 9 0 11-3-6.7L21 8M21 3v5h-5',
  alert: 'M12 3l10 18H2zM12 10v5M12 18h.01',
  x: 'M6 6l12 12M18 6L6 18',
  pulse: 'M3 12h4l3-8 4 16 3-8h4',
  disk: 'M4 7c0-1.7 3.6-3 8-3s8 1.3 8 3-3.6 3-8 3-8-1.3-8-3zM4 7v10c0 1.7 3.6 3 8 3s8-1.3 8-3V7M4 12c0 1.7 3.6 3 8 3s8-1.3 8-3',
  download: 'M12 3v12M7 10l5 5 5-5M4 21h16',
};
function icon(name) { return svg('svg', { viewBox: '0 0 24 24', class: 'ico', 'aria-hidden': 'true' }, svg('path', { d: ICON[name] || '' })); }

// ---------- shared UI components ----------
const SEV_ORDER = ['critical', 'high', 'medium', 'low'];
const sevBadge = s => h('span', { class: 'badge ' + (s || 'info') }, s || 'info');
function scoreBadge(sec) {
  if (!sec || !sec.hasData || sec.score == null) return h('span', { class: 'score none', title: sec && sec.status === 'running' ? 'Scanning…' : 'Not scanned yet' }, '–');
  const cls = sec.score >= 80 ? 'good' : sec.score >= 50 ? 'fair' : 'poor';
  return h('span', { class: 'score ' + cls, title: 'Security score ' + sec.score + '/100' }, String(sec.score));
}
function sevBar(counts) {
  const c = counts || {}; const total = SEV_ORDER.reduce((a, k) => a + (c[k] || 0), 0);
  const cls = { critical: 'c', high: 'h', medium: 'm', low: 'l' };
  return h('div', { class: 'sevbar', title: SEV_ORDER.map(k => (c[k] || 0) + ' ' + k).join(', ') },
    total ? SEV_ORDER.map(k => c[k] ? h('i', { class: cls[k], style: { width: (c[k] / total * 100) + '%' } }) : null) : null);
}
function barNode(p) { return h('div', { class: 'bar' }, h('i', { class: p >= 90 ? 'hot' : p >= 75 ? 'mid' : '', style: { width: Math.min(100, p) + '%' } })); }
function emptyState(big, title, text, btn) {
  return h('div', { class: 'empty' }, h('div', { class: 'big' }, big), h('h3', null, title), text ? h('p', null, text) : null, btn || null);
}
function pageHead(title, sub, actions) {
  return h('div', { class: 'pagehead' }, h('div', null, h('h1', null, title), sub ? h('div', { class: 'sub' }, sub) : null), actions ? h('div', { class: 'row' }, actions) : null);
}
function panel(title, sub, right, ...body) {
  return h('div', { class: 'panel' }, (title || right) ? h('div', { class: 'phead' }, h('div', null, h('h3', null, title), sub ? h('div', { class: 'sub' }, sub) : null), right ? h('div', { class: 'row' }, right) : null) : null, body);
}
function toggle(checked, onchange) {
  const i = h('input', { type: 'checkbox', checked: !!checked });
  if (onchange) i.addEventListener('change', () => onchange(i.checked));
  return h('label', { class: 'toggle' }, i, h('i'));
}
function segmented(options, value, onchange) {
  const wrap = h('div', { class: 'seg', role: 'group' });
  const draw = () => { clear(wrap).append(options.map(([v, l]) => h('button', { class: v === value ? 'on' : '', type: 'button', onclick: () => { value = v; draw(); onchange(v); } }, l))); };
  draw(); return wrap;
}

// SVG donut. segs: [{v, color, label}]
function donut(segs, centerText, centerSub) {
  const total = segs.reduce((a, s) => a + s.v, 0), R = 54, C = 2 * Math.PI * R;
  const g = svg('svg', { viewBox: '0 0 150 150', role: 'img', 'aria-label': segs.map(s => s.label + ' ' + s.v).join(', ') });
  g.append(svg('circle', { cx: 75, cy: 75, r: R, fill: 'none', 'stroke-width': 18, style: { stroke: 'var(--panel2)' } }));
  let off = 0;
  if (total) for (const s of segs) {
    if (!s.v) continue;
    const len = s.v / total * C;
    g.append(svg('circle', { cx: 75, cy: 75, r: R, fill: 'none', 'stroke-width': 18, 'stroke-dasharray': `${len} ${C - len}`, 'stroke-dashoffset': -off, transform: 'rotate(-90 75 75)', style: { stroke: s.color } }));
    off += len;
  }
  g.append(svg('text', { x: 75, y: centerSub ? 76 : 83, 'text-anchor': 'middle', 'font-size': 28, 'font-weight': 700, style: { fill: 'var(--text)' } }, centerText),
    centerSub ? svg('text', { x: 75, y: 96, 'text-anchor': 'middle', 'font-size': 11, style: { fill: 'var(--muted)' } }, centerSub) : null);
  return g;
}
function legend(segs) { return h('div', { class: 'legend' }, segs.map(s => h('span', { style: { '--c': s.color } }, `${s.label} · ${s.v}`))); }

// Big circular score.
function scoreRing(score, size) {
  const R = 46, C = 2 * Math.PI * R; const has = score != null;
  const color = !has ? 'var(--line2)' : score >= 80 ? 'var(--ok)' : score >= 50 ? 'var(--sev-m)' : 'var(--crit)';
  const g = svg('svg', { viewBox: '0 0 108 108', class: 'ring', role: 'img', 'aria-label': has ? 'Security score ' + score + ' of 100' : 'Not scanned' });
  if (size) { g.style.width = size + 'px'; g.style.height = size + 'px'; }
  g.append(svg('circle', { cx: 54, cy: 54, r: R, fill: 'none', 'stroke-width': 9, style: { stroke: 'var(--panel2)' } }),
    has ? svg('circle', { cx: 54, cy: 54, r: R, fill: 'none', 'stroke-width': 9, 'stroke-linecap': 'round', 'stroke-dasharray': `${score / 100 * C} ${C}`, transform: 'rotate(-90 54 54)', style: { stroke: color } }) : null,
    svg('text', { x: 54, y: has ? 61 : 60, 'text-anchor': 'middle', 'font-size': has ? 30 : 24, style: { fill: has ? color : 'var(--muted)' } }, has ? String(score) : '–'));
  return g;
}

// Sparkline from an array of numbers (0..max).
function sparkline(values, opt) {
  opt = opt || {}; const W = opt.w || 300, H = opt.h || 56, max = opt.max || 100;
  const g = svg('svg', { viewBox: `0 0 ${W} ${H}`, preserveAspectRatio: 'none', role: 'img', 'aria-label': opt.label || 'trend' });
  g.style.height = H + 'px';
  g.append(svg('line', { x1: 0, x2: W, y1: H - .5, y2: H - .5, style: { stroke: 'var(--line)' } }));
  if (values.length < 2) { g.append(svg('text', { x: W / 2, y: H / 2, 'text-anchor': 'middle', 'font-size': 11, style: { fill: 'var(--muted)' } }, 'Collecting data…')); return g; }
  const pts = values.map((v, i) => [i / (values.length - 1) * W, H - 3 - Math.min(1, Math.max(0, v / max)) * (H - 6)]);
  const line = pts.map((p, i) => (i ? 'L' : 'M') + p[0].toFixed(1) + ' ' + p[1].toFixed(1)).join('');
  const color = opt.color || 'var(--accent)';
  g.append(svg('path', { d: line + `L${W} ${H}L0 ${H}Z`, style: { fill: color, opacity: .12 } }),
    svg('path', { d: line, fill: 'none', 'stroke-width': 1.8, 'stroke-linejoin': 'round', 'vector-effect': 'non-scaling-stroke', style: { stroke: color } }));
  return g;
}

// Horizontal bars. rows: [{label, v, color}]
function hbars(rows, max) {
  max = max || Math.max(1, ...rows.map(r => r.v));
  return h('div', { class: 'stack', style: { gap: '10px' } }, rows.map(r => h('div', null,
    h('div', { class: 'row spread small-text', style: { marginBottom: '4px' } }, h('span', null, r.label), h('b', null, r.v)),
    h('div', { class: 'bar' }, h('i', { style: { width: (r.v / max * 100) + '%', background: r.color || 'var(--accent)' } })))));
}

// Table helper (also used by device.js)
function table(cols, rows, opts) {
  opts = opts || {};
  return h('div', { class: 'tablewrap' }, h('table', null,
    h('thead', null, h('tr', null, cols.map(c => h('th', { class: c.num ? 'num' : '' }, c.label)))),
    h('tbody', null, rows.length ? rows : h('tr', null, h('td', { colSpan: cols.length, class: 'muted' }, opts.empty || 'Nothing to show')))));
}

// Choose what a task runs on: all PCs / a group / a tag / specific PCs.
function targetPicker(devices, initial) {
  devices = (devices || []).filter(d => d.approved);
  const groups = [...new Set(devices.map(d => d.group).filter(Boolean))].sort();
  const tags = [...new Set(devices.flatMap(d => d.tags || []))].sort();
  const t = Object.assign({ mode: 'all', group: groups[0] || '', tag: tags[0] || '', devices: [] }, initial || {});
  const body = h('div', { class: 'stack', style: { gap: '8px' } });
  const sel = new Set(t.devices);
  const count = h('span', { class: 'muted small-text' });
  const modes = [['all', 'All PCs']]; if (groups.length) modes.push(['group', 'A group']); if (tags.length) modes.push(['tag', 'A tag']); modes.push(['devices', 'Specific PCs']);
  const draw = () => {
    clear(body);
    if (t.mode === 'group') body.append(h('select', { onchange: e => { t.group = e.target.value; upd(); } }, groups.map(g => h('option', { value: g, selected: g === t.group }, g))));
    if (t.mode === 'tag') body.append(h('select', { onchange: e => { t.tag = e.target.value; upd(); } }, tags.map(g => h('option', { value: g, selected: g === t.tag }, g))));
    if (t.mode === 'devices') body.append(h('div', { class: 'devlist' }, devices.map(d => h('label', null, h('input', { type: 'checkbox', checked: sel.has(d.id), onchange: e => { e.target.checked ? sel.add(d.id) : sel.delete(d.id); upd(); } }), d.name, d.online ? null : h('span', { class: 'muted' }, ' (offline)')))));
    upd();
  };
  const get = () => t.mode === 'all' ? { all: true } : t.mode === 'group' ? { group: t.group } : t.mode === 'tag' ? { tag: t.tag } : { devices: [...sel] };
  const matches = () => t.mode === 'all' ? devices.length : t.mode === 'group' ? devices.filter(d => d.group === t.group).length : t.mode === 'tag' ? devices.filter(d => (d.tags || []).includes(t.tag)).length : sel.size;
  const upd = () => { count.textContent = plural(matches(), 'PC') + ' selected'; };
  const el = h('div', { class: 'stack', style: { gap: '8px' } }, segmented(modes, t.mode, v => { t.mode = v; draw(); }), body, count);
  draw();
  return { el, get, valid: () => matches() > 0 };
}

// Tag editor: comma separated input.
const parseTags = s => [...new Set(s.split(/[,\n]/).map(x => x.trim().toLowerCase()).filter(Boolean))];
const tagNodes = tags => (tags || []).map(t => h('span', { class: 'tag' }, t));

// ---------- theme (light / dark) ----------
const currentTheme = () => document.documentElement.getAttribute('data-theme') === 'dark' ? 'dark' : 'light';
function setTheme(t) { document.documentElement.setAttribute('data-theme', t); store.set('theme', t); }
function themeButton() {
  const b = h('button', { class: 'iconbtn', type: 'button' });
  const draw = () => { clear(b).append(icon(currentTheme() === 'dark' ? 'sun' : 'moon')); b.title = currentTheme() === 'dark' ? 'Switch to light mode' : 'Switch to dark mode'; b.setAttribute('aria-label', b.title); };
  b.addEventListener('click', () => { setTheme(currentTheme() === 'dark' ? 'light' : 'dark'); draw(); });
  draw(); return b;
}

// ---------- layout ----------
const LOGO = () => {
  const s = svg('svg', { viewBox: '0 0 32 32' });
  s.append(svg('circle', { cx: 16, cy: 16, r: 13, fill: 'none', stroke: 'currentColor', 'stroke-width': 3 }),
    svg('circle', { cx: 16, cy: 16, r: 4, fill: 'currentColor' }),
    svg('path', { d: 'M16 3v6M16 23v6M3 16h6M23 16h6', stroke: 'currentColor', 'stroke-width': 3 }));
  return s;
};

const NAV = [
  ['Overview', [['#/', 'Dashboard', 'dash', 'dashboard'], ['#/devices', 'Devices', 'devices', 'devices']]],
  ['Protect', [['#/security', 'Security', 'shield', 'security'], ['#/alerts', 'Alerts', 'bell', 'alerts']]],
  ['Manage', [['#/software', 'Software', 'box', 'software'], ['#/automation', 'Automation', 'zap', 'automation'], ['#/sessions', 'Sessions', 'video', 'sessions']]],
  ['Admin', [['#/reports', 'Reports', 'file', 'reports'], ['#/enroll', 'Add a PC', 'plus', 'enroll'], ['#/activity', 'Activity log', 'list', 'activity'], ['#/settings', 'Settings', 'gear', 'settings']]],
];

let alertBadge = null;
function setAlertCount(n) { S.alerts = n; if (alertBadge) { alertBadge.textContent = n > 99 ? '99+' : String(n); alertBadge.classList.toggle('hidden', !n); } }
async function refreshAlertCount() {
  try { const a = await api('GET', '/api/alerts'); setAlertCount(a.filter(x => isZero(x.resolved) && !x.acked).length); } catch (e) { /* ignore */ }
}

function globalSearch() {
  const input = h('input', { type: 'search', placeholder: 'Search PCs, tags, groups…', 'aria-label': 'Search' });
  const box = h('div', { class: 'gsearch' }, svg('svg', { viewBox: '0 0 24 24' }, svg('path', { d: ICON.search })), input);
  let results = null, items = [], idx = -1;
  const close = () => { if (results) { results.remove(); results = null; } items = []; idx = -1; };
  const go = href => { close(); input.value = ''; input.blur(); location.hash = href; };
  const draw = async () => {
    const q = input.value.trim().toLowerCase(); close();
    if (!q) return;
    let devs = [];
    try { devs = await getDevices(); } catch (e) { return; }
    const m = [];
    for (const d of devs) {
      const hay = [d.name, d.group, (d.tags || []).join(' '), d.hello && d.hello.hostname, d.hello && (d.hello.ips || []).join(' '), d.stats && d.stats.user, d.hello && d.hello.user].join(' ').toLowerCase();
      if (hay.includes(q)) m.push(['#/d/' + d.id, d.name, d.group || (d.online ? 'online' : 'offline')]);
    }
    for (const [, links] of NAV) for (const [href, label] of links) if (label.toLowerCase().includes(q)) m.push([href, label, 'page']);
    items = m.slice(0, 8);
    results = h('div', { class: 'gresults' }, items.length ? items.map(([href, label, kind]) => h('a', { href, onclick: e => { e.preventDefault(); go(href); } }, label, h('span', { class: 'kind' }, kind))) : h('div', { class: 'muted', style: { padding: '12px 14px' } }, 'No matches'));
    box.append(results); idx = -1;
  };
  input.addEventListener('input', draw);
  input.addEventListener('keydown', e => {
    if (e.key === 'Escape') { close(); input.blur(); }
    else if (e.key === 'ArrowDown' || e.key === 'ArrowUp') {
      e.preventDefault(); if (!items.length) return;
      idx = (idx + (e.key === 'ArrowDown' ? 1 : -1) + items.length) % items.length;
      [...results.children].forEach((c, i) => c.classList.toggle('sel', i === idx));
    } else if (e.key === 'Enter' && items.length) go(items[Math.max(0, idx)][0]);
  });
  input.addEventListener('blur', () => setTimeout(close, 150));
  document.addEventListener('keydown', e => { if (e.key === '/' && !/^(INPUT|TEXTAREA|SELECT)$/.test(document.activeElement.tagName)) { e.preventDefault(); input.focus(); } });
  return box;
}

function userMenu() {
  const m = h('div', { class: 'menu hidden' },
    h('div', { class: 'menu-head' }, h('b', null, S.user), h('span', { class: 'muted small-text' }, 'Administrator')),
    h('a', { href: '#/account', onclick: () => m.classList.add('hidden') }, icon('gear'), 'My account'),
    h('button', { class: 'ghost', onclick: logout }, icon('out'), 'Sign out'));
  const b = h('button', { class: 'userbtn', 'aria-label': 'Account menu', onclick: e => { e.stopPropagation(); m.classList.toggle('hidden'); } },
    h('span', { class: 'avatar' }, (S.user || '?')[0]), h('span', { class: 'uname' }, S.user));
  document.addEventListener('click', () => m.classList.add('hidden'));
  return h('div', { class: 'usermenu' }, b, m);
}

function shell(active, content) {
  const app = clear($('#app'));
  const side = h('aside', { class: 'sidebar', id: 'sidebar' },
    h('div', { class: 'brand' }, LOGO(), h('span', null, 'Helm')),
    NAV.map(([group, links]) => [h('div', { class: 'navgroup' }, group), links.map(([href, label, ic, key]) => {
      const a = h('a', { href, class: 'navlink' + (active === key ? ' active' : ''), onclick: () => side.classList.remove('open') }, icon(ic), label);
      if (key === 'alerts') { alertBadge = h('span', { class: 'count' + (S.alerts ? '' : ' hidden') }, String(S.alerts)); a.append(alertBadge); }
      return a;
    })]),
    h('div', { class: 'sidefoot' }, h('span', null, 'Helm console'), h('span', { id: 'ver' }, S.version ? 'v' + S.version : '')));
  const bodyEl = h('div', { class: 'container' }, content);
  app.append(h('div', { class: 'app' }, side, h('div', { class: 'main' },
    h('div', { class: 'topbar' }, h('button', { class: 'ghost icon menu-btn', 'aria-label': 'Menu', onclick: () => side.classList.toggle('open') }, icon('menu')), globalSearch(), h('div', { class: 'spacer' }), h('a', { class: 'btn primary', href: '#/enroll' }, icon('plus'), 'Add a PC'), themeButton(), userMenu()),
    bodyEl)));
  refreshAlertCount();
  return bodyEl;
}

// ---------- login ----------
function showLogin(msg) {
  cleanups.forEach(f => { try { f(); } catch (e) { /* ignore */ } }); cleanups = [];
  routeToken++; S.csrf = ''; S.devices = null;
  const user = h('input', { type: 'text', autocomplete: 'username', value: 'admin', required: true });
  const pw = h('input', { type: 'password', autocomplete: 'current-password', required: true });
  const code = h('input', { type: 'text', inputMode: 'numeric', autocomplete: 'one-time-code', maxLength: 6, placeholder: '6-digit code', required: true });
  const codeField = h('label', { class: 'field' }, h('span', null, 'Authenticator code'), code);
  const gbox = h('div', { class: 'stack', style: { marginBottom: '18px' } });
  fetch('/api/auth/config').then(r => r.json()).then(c => {
    if (c && c.totp === false) { codeField.classList.add('hidden'); code.required = false; }
    if (c && c.google) gbox.append(h('a', { class: 'btn', href: '/api/auth/google/start', style: { justifyContent: 'center', padding: '9px' } }, 'Sign in with Google'), h('div', { class: 'muted small-text' }, 'Or use your password and authenticator code.'));
    else gbox.style.display = 'none';
  }).catch(() => { gbox.style.display = 'none'; });
  const ssoErr = new URLSearchParams(location.search).get('sso_error');
  if (ssoErr) { msg = ssoErr; history.replaceState(null, '', location.pathname + location.hash); }
  const err = h('div', { class: 'notice bad hidden' });
  const btn = h('button', { class: 'primary', type: 'submit', style: { justifyContent: 'center', padding: '10px' } }, 'Sign in');
  const form = h('form', { class: 'stack', onsubmit: async e => {
    e.preventDefault(); btn.disabled = true; err.classList.add('hidden');
    try {
      const { res, data } = await rawFetch('POST', '/api/login', { user: user.value, password: pw.value, code: code.value });
      if (!res.ok) throw new Error((data && data.error) || 'Sign-in failed');
      S.csrf = data.csrf; S.user = data.user; boot2();
    } catch (ex) { err.textContent = ex.message; err.classList.remove('hidden'); code.value = ''; }
    finally { btn.disabled = false; }
  } },
    h('label', { class: 'field' }, h('span', null, 'User'), user),
    h('label', { class: 'field' }, h('span', null, 'Password'), pw),
    codeField,
    err, btn);
  if (msg) { err.textContent = msg; err.classList.remove('hidden'); }
  const point = (t, d) => h('li', null, icon('check'), h('div', null, h('b', { style: { color: '#fff' } }, t), h('div', null, d)));
  clear($('#app')).append(h('div', { class: 'loginpage' },
    h('div', { class: 'loginhero' },
      h('div', { class: 'brand' }, LOGO(), h('span', null, 'Helm')),
      h('div', null, h('h2', null, 'Every PC, Mac and server in one console.'),
        h('ul', null, point('Security at a glance', 'Vulnerability scanning, patch status and a clear score for every machine.'),
          point('Manage remotely', 'Terminal, files, services, updates and software deployment without a VPN.'),
          point('Self-hosted', 'Your server, your data. Sign-in is protected by a strong password and two-step verification.'))),
      h('small', null, 'Helm management console')),
    h('div', { class: 'loginform', style: { position: 'relative' } }, h('div', { class: 'themefloat' }, themeButton()),
      h('div', { class: 'login' }, h('h1', null, 'Sign in'), h('div', { class: 'tagline' }, 'Use your administrator account'), h('div', { class: 'panel' }, gbox, form)))));
  user.value ? pw.focus() : user.focus();
}

async function logout() {
  try { await api('POST', '/api/logout', {}); } catch (e) { /* already out */ }
  showLogin();
}

// ---------- router ----------
const routes = [];
function route(re, fn) { routes.push([re, fn]); }

function navigate() {
  cleanups.forEach(f => { try { f(); } catch (e) { /* ignore */ } }); cleanups = [];
  routeToken++;
  const path = location.hash.replace(/^#/, '') || '/';
  for (const [re, fn] of routes) {
    const m = path.match(re);
    if (m) { window.scrollTo(0, 0); fn(...m.slice(1).map(x => x == null ? x : decodeURIComponent(x))); return; }
  }
  location.hash = '#/';
}

async function boot() {
  const { res, data } = await rawFetch('GET', '/api/me');
  if (!res.ok) { showLogin(); return; }
  S.csrf = data.csrf; S.user = data.user; boot2();
}
function boot2() {
  navigate();
  if (!S.version) api('GET', '/api/info').then(i => { S.version = i.version || ''; const v = $('#ver'); if (v && S.version) v.textContent = 'v' + S.version; }).catch(() => { /* optional */ });
}
window.addEventListener('hashchange', () => { if (S.csrf) navigate(); });
setInterval(() => { if (S.csrf) refreshAlertCount(); }, 30000);

// ---------- devices ----------
function deviceChip(d) {
  if (!d.approved) return h('span', { class: 'chip warn' }, 'Pending approval');
  return d.online ? h('span', { class: 'chip on' }, 'Online') : h('span', { class: 'chip off' }, 'Offline · ' + fmtAgo(d.lastSeen));
}
const OS_LABEL = { windows: 'Win', linux: 'Linux', darwin: 'macOS' };
const osKey = d => (d && d.hello && d.hello.os) || 'windows';
const osBadge = d => h('span', { class: 'osbadge', title: osKey(d) }, OS_LABEL[osKey(d)] || osKey(d));
const osText = d => { const hl = d.hello || {}; return [hl.osVersion || hl.os, hl.edition].filter(Boolean).join(' · '); };

// Acronis-style quick view: a right-hand drawer with the essentials and the most common actions.
function openDrawer(d, refresh) {
  const close = () => { bd.remove(); dr.remove(); document.removeEventListener('keydown', onKey); };
  const onKey = e => { if (e.key === 'Escape') close(); };
  const st = d.stats, hello = d.hello || {}, sec = d.security;
  const cDisk = st && st.disks && (st.disks.find(x => /^(C:|\/$)/i.test(x.name)) || st.disks[0]);
  const kv = rows => h('dl', { class: 'kv' }, rows.filter(r => r[1] != null && r[1] !== '').map(([k, v]) => [h('dt', null, k), h('dd', null, v)]));
  const metric = (label, p) => h('div', { class: 'metric', style: { gridTemplateColumns: '70px 1fr 42px' } }, h('span', null, label), barNode(p), h('b', null, p + '%'));
  const dr = h('aside', { class: 'drawer', role: 'dialog', 'aria-label': d.name },
    h('header', null, h('div', { style: { minWidth: 0 } }, h('div', { class: 'row tight' }, h('span', { class: 'statusdot' + (d.online ? ' on' : '') }), h('h2', { style: { margin: 0, wordBreak: 'break-word' } }, d.name)),
      h('div', { class: 'muted', style: { marginTop: '4px' } }, osBadge(d), osText(d))),
      h('div', { class: 'row tight' }, scoreBadge(sec), h('button', { class: 'iconbtn', 'aria-label': 'Close', onclick: close }, icon('x')))),
    h('div', { class: 'dbody' },
      h('div', null, h('h4', null, 'Status'), kv([['State', d.approved ? (d.online ? 'Online' : 'Offline · seen ' + fmtAgo(d.lastSeen)) : 'Pending approval'], ['User', (st && st.user) || hello.user], ['Group', d.group], ['Tags', (d.tags || []).join(', ')],
        ['IP', (hello.ips || [])[0] || d.lastIp], ['Agent', hello.version], ['Uptime', st && st.uptimeSec ? fmtDur(st.uptimeSec) : '']])),
      d.online && st ? h('div', null, h('h4', null, 'Live'), h('div', { class: 'stack', style: { gap: '8px' } }, metric('CPU', Math.round(st.cpu)), metric('Memory', pct(st.memUsed, st.memTotal)),
        cDisk ? metric('Disk ' + cDisk.name, pct(cDisk.total - cDisk.free, cDisk.total)) : null)) : null,
      h('div', null, h('h4', null, 'Security'), sec && sec.counts ? h('div', { class: 'stack', style: { gap: '8px' } }, sevBar(sec.counts), h('div', { class: 'muted small-text' }, SEV_ORDER.map(k => (sec.counts[k] || 0) + ' ' + k).join(' · ')), h('div', { class: 'muted small-text' }, 'Last scan ' + (sec.status === 'running' ? 'running…' : fmtAgo(sec.at)))) : h('div', { class: 'muted' }, 'Not scanned yet.')),
      d.notes ? h('div', null, h('h4', null, 'Notes'), h('div', { class: 'muted' }, d.notes)) : null),
    h('footer', null, h('a', { class: 'btn primary', href: '#/d/' + d.id, onclick: close }, 'Open details'),
      d.online ? actionButton('Scan now', async () => { await api('POST', `/api/devices/${d.id}/scan`, {}); toast('Scan started on ' + d.name, 'ok'); }) : null,
      d.online ? h('a', { class: 'btn', href: '#/d/' + d.id + '/terminal', onclick: close }, 'Terminal') : null,
      h('a', { class: 'btn', href: '#/d/' + d.id + '/security', onclick: close }, 'Security')));
  const bd = h('div', { class: 'drawer-bd', onclick: close });
  document.body.append(bd, dr); document.addEventListener('keydown', onKey);
  dr.querySelector('button.iconbtn').focus();
  if (refresh) onLeave(close);
}

function deviceCard(d, selected, onSel) {
  const st = d.stats, hello = d.hello || {};
  const cDisk = st && st.disks && (st.disks.find(x => /^C:/i.test(x.name)) || st.disks[0]);
  return h('div', { class: 'card', onclick: () => openDrawer(d, true) },
    h('div', { class: 'devtop' },
      h('div', { style: { minWidth: 0 } }, h('div', { class: 'row tight' }, h('span', { class: 'statusdot' + (d.online ? ' on' : '') }), h('div', { class: 'title' }, d.name)), h('div', { class: 'meta' }, osBadge(d), osText(d))),
      h('div', { class: 'row tight' }, scoreBadge(d.security),
        h('input', { type: 'checkbox', checked: selected.has(d.id), title: 'Select', 'aria-label': 'Select ' + d.name, onclick: e => e.stopPropagation(), onchange: e => onSel(d.id, e.target.checked) }))),
    h('div', null, d.group ? h('span', { class: 'tag group' }, d.group) : null, tagNodes(d.tags), !d.online ? h('span', { class: 'muted small-text' }, ' ' + fmtAgo(d.lastSeen)) : null),
    h('div', { class: 'meta' }, [st && st.user ? '👤 ' + st.user : (hello.user ? 'Last user: ' + hello.user : ''), (hello.ips || [])[0]].filter(Boolean).join(' · ')),
    d.online && st ? h('div', { class: 'stack', style: { gap: '5px' } },
      h('div', { class: 'metric' }, h('span', null, 'CPU'), barNode(st.cpu), h('b', null, Math.round(st.cpu) + '%')),
      h('div', { class: 'metric' }, h('span', null, 'Memory'), barNode(pct(st.memUsed, st.memTotal)), h('b', null, pct(st.memUsed, st.memTotal) + '%')),
      cDisk ? h('div', { class: 'metric' }, h('span', null, 'Disk ' + cDisk.name), barNode(pct(cDisk.total - cDisk.free, cDisk.total)), h('b', null, pct(cDisk.total - cDisk.free, cDisk.total) + '%')) : null) : null,
    d.security && d.security.counts && (d.security.counts.critical + d.security.counts.high) > 0 ? h('div', { class: 'row tight' }, sevBar(d.security.counts), h('span', { class: 'muted small-text nowrap' }, (d.security.counts.critical + d.security.counts.high) + ' serious')) : null);
}

route(/^\/devices$/, viewDevices);
function viewDevices() {
  const selected = new Set();
  let devices = [], last = '';
  const f = Object.assign({ q: '', status: 'all', group: '', tag: '', sort: 'name', view: 'list' }, store.get('devfilter', {}));
  const pendingBox = h('div'), content = h('div'), bulk = h('div', { class: 'bulkbar hidden' });
  const search = h('input', { type: 'search', placeholder: 'Search by name, user, IP, tag…', value: f.q, 'aria-label': 'Search devices' });
  const pills = h('div', { class: 'pills' });
  const groupSel = h('select', { 'aria-label': 'Group' }), tagSel = h('select', { 'aria-label': 'Tag' });
  const sortSel = h('select', { 'aria-label': 'Sort' }, [['name', 'Sort: name'], ['status', 'Sort: status'], ['score', 'Sort: security (worst first)'], ['seen', 'Sort: last seen']].map(([v, l]) => h('option', { value: v, selected: v === f.sort }, l)));
  const viewSeg = segmented([['list', 'List'], ['grid', 'Cards']], f.view, v => { f.view = v; save(); draw(true); });
  const save = () => store.set('devfilter', f);
  const approved = () => devices.filter(d => d.approved);

  const visible = () => {
    const q = f.q.trim().toLowerCase();
    let r = approved().filter(d => {
      if (f.status === 'online' && !d.online) return false;
      if (f.status === 'offline' && d.online) return false;
      if (f.status === 'risk' && !(d.security && (d.security.counts.critical + d.security.counts.high) > 0)) return false;
      if (f.group && (f.group === '__none' ? d.group : d.group !== f.group)) return false;
      if (f.tag && !(d.tags || []).includes(f.tag)) return false;
      if (!q) return true;
      return [d.name, d.group, (d.tags || []).join(' '), d.notes, d.lastIp, d.hello && d.hello.hostname, d.hello && (d.hello.ips || []).join(' '), d.stats && d.stats.user, d.hello && d.hello.user].join(' ').toLowerCase().includes(q);
    });
    const byName = (a, b) => a.name.toLowerCase().localeCompare(b.name.toLowerCase());
    if (f.sort === 'name') r.sort(byName);
    else if (f.sort === 'status') r.sort((a, b) => (b.online - a.online) || byName(a, b));
    else if (f.sort === 'score') r.sort((a, b) => ((a.security ? a.security.score : 101) - (b.security ? b.security.score : 101)) || byName(a, b));
    else r.sort((a, b) => new Date(b.lastSeen) - new Date(a.lastSeen));
    return r;
  };

  const drawFilters = () => {
    const groups = [...new Set(approved().map(d => d.group).filter(Boolean))].sort();
    const tags = [...new Set(approved().flatMap(d => d.tags || []))].sort();
    if (f.group && f.group !== '__none' && !groups.includes(f.group)) f.group = '';
    if (f.tag && !tags.includes(f.tag)) f.tag = '';
    const n = k => approved().filter(d => k === 'all' || (k === 'online' ? d.online : k === 'offline' ? !d.online : d.security && (d.security.counts.critical + d.security.counts.high) > 0)).length;
    clear(pills).append([['all', 'All'], ['online', 'Online'], ['offline', 'Offline'], ['risk', 'At risk']].map(([k, l]) =>
      h('button', { class: 'pill' + (f.status === k ? ' on' : ''), onclick: () => { f.status = k; save(); drawFilters(); draw(true); } }, `${l} · ${n(k)}`)));
    clear(groupSel).append(h('option', { value: '' }, 'All groups'), groups.map(g => h('option', { value: g, selected: g === f.group }, g)), approved().some(d => !d.group) && groups.length ? h('option', { value: '__none', selected: f.group === '__none' }, 'No group') : null);
    clear(tagSel).append(h('option', { value: '' }, 'All tags'), tags.map(g => h('option', { value: g, selected: g === f.tag }, g)));
    groupSel.classList.toggle('hidden', !groups.length); tagSel.classList.toggle('hidden', !tags.length);
  };
  search.addEventListener('input', () => { f.q = search.value; save(); draw(true); });
  groupSel.addEventListener('change', () => { f.group = groupSel.value; save(); draw(true); });
  tagSel.addEventListener('change', () => { f.tag = tagSel.value; save(); draw(true); });
  sortSel.addEventListener('change', () => { f.sort = sortSel.value; save(); draw(true); });

  const doBulk = async (label, name, args, danger) => {
    const t = devices.filter(d => selected.has(d.id) && d.online && d.approved);
    if (!t.length) throw new Error('No selected PC is online');
    if (!(await confirmDialog(`${label} on ${plural(t.length, 'PC')}: ${t.map(x => x.name).join(', ')}?`, label, danger))) return;
    const results = await Promise.allSettled(t.map(d => runCmd(d.id, name, args, { keepAlive: true })));
    const ok = results.filter(r => r.status === 'fulfilled').length;
    toast(`${label}: ${ok} succeeded, ${results.length - ok} failed`, ok === results.length ? 'ok' : 'bad');
  };
  const bulkBtn = (label, name, args, danger) => actionButton(label, () => doBulk(label, name, args, danger), danger ? 'danger' : '');
  const renderBulk = () => {
    clear(bulk).classList.toggle('hidden', selected.size === 0);
    if (!selected.size) return;
    const ids = [...selected];
    bulk.append(h('strong', null, selected.size + ' selected'),
      actionButton('Scan now', async () => { await api('POST', '/api/run/scan', { target: { devices: ids } }); toast('Security scan started', 'ok'); }),
      actionButton('Run script…', async () => { await runScriptDialog({ devices: ids }); }),
      actionButton('Group / tags…', async () => { if (await groupDialog(devices.filter(d => selected.has(d.id)))) { S.devices = null; await refresh(); } }),
      bulkBtn('Restart', 'power', { action: 'restart', delay: 30, message: 'Restarting (Helm)' }, true),
      bulkBtn('Shut down', 'power', { action: 'shutdown', delay: 30, message: 'Shutting down (Helm)' }, true),
      bulkBtn('Lock', 'power', { action: 'lock' }, false),
      bulkBtn('Install Windows updates', 'updates.install', { reboot: false }, true),
      h('button', { onclick: () => { selected.clear(); renderBulk(); draw(true); } }, 'Clear'));
  };
  const onSel = (id, on) => { on ? selected.add(id) : selected.delete(id); renderBulk(); };

  const listRow = d => {
    const st = d.stats, hello = d.hello || {};
    return h('tr', { class: 'clickable', onclick: () => openDrawer(d, true) },
      h('td', { class: 'checkcell', onclick: e => e.stopPropagation() }, h('input', { type: 'checkbox', checked: selected.has(d.id), 'aria-label': 'Select ' + d.name, onchange: e => onSel(d.id, e.target.checked) })),
      h('td', null, h('div', { class: 'row tight' }, h('span', { class: 'statusdot' + (d.online ? ' on' : '') }), h('a', { href: '#/d/' + d.id, onclick: e => e.stopPropagation() }, h('b', null, d.name))), h('div', null, tagNodes(d.tags))),
      h('td', null, d.group ? h('span', { class: 'tag group' }, d.group) : h('span', { class: 'muted' }, '–')),
      h('td', { class: 'muted' }, osBadge(d), osText(d)),
      h('td', null, (st && st.user) || hello.user || ''),
      h('td', { class: 'num' }, d.online && st ? Math.round(st.cpu) + '%' : '–'),
      h('td', { class: 'num' }, d.online && st ? pct(st.memUsed, st.memTotal) + '%' : '–'),
      h('td', null, h('div', { class: 'row tight' }, scoreBadge(d.security), d.security ? sevBar(d.security.counts) : null)),
      h('td', { class: 'muted nowrap' }, d.online ? 'now' : fmtAgo(d.lastSeen)));
  };

  const draw = force => {
    const sig = JSON.stringify([devices.map(d => [d.id, d.name, d.online, d.approved, d.stats, d.lastSeen, d.group, d.tags, d.security]), f]);
    if (!force && sig === last) return; last = sig;
    const pend = devices.filter(d => !d.approved);
    clear(pendingBox).append(pend.length ? h('div', { class: 'notice warn', style: { marginBottom: '16px' } }, h('b', null, plural(pend.length, 'PC') + ' waiting for approval'),
      h('div', { class: 'stack', style: { marginTop: '10px', gap: '8px' } }, pend.map(d => h('div', { class: 'row spread' },
        h('div', null, h('b', null, d.name), h('span', { class: 'muted' }, ` · enrolled via "${d.via || '?'}" from ${d.lastIp}`)),
        h('div', { class: 'row tight' },
          actionButton('Approve', async () => { await api('POST', `/api/devices/${d.id}/approve`, {}); toast('Approved ' + d.name, 'ok'); refresh(); }, 'primary small'),
          actionButton('Reject', async () => { if (await confirmDialog('Reject and remove ' + d.name + '?', 'Remove', true)) { await api('DELETE', '/api/devices/' + d.id); refresh(); } }, 'danger small')))))) : null);
    drawFilters();
    const r = visible();
    clear(content);
    if (!approved().length) { content.append(h('div', { class: 'panel' }, emptyState('🖥️', 'No PCs yet', 'Create an enrollment token and install command to add your first PC.', h('a', { class: 'btn primary', href: '#/enroll' }, 'Add a PC')))); return; }
    if (!r.length) { content.append(h('div', { class: 'panel' }, emptyState('🔎', 'No PCs match', 'Try a different search or clear the filters.'))); return; }
    if (f.view === 'list') {
      const allOn = r.every(d => selected.has(d.id));
      content.append(h('div', { class: 'panel flush' }, h('div', { class: 'tablewrap' }, h('table', null,
        h('thead', null, h('tr', null, h('th', { class: 'checkcell' }, h('input', { type: 'checkbox', checked: allOn, 'aria-label': 'Select all', onchange: e => { r.forEach(d => e.target.checked ? selected.add(d.id) : selected.delete(d.id)); renderBulk(); draw(true); } })),
          ['Device', 'Group', 'Operating system', 'User'].map(x => h('th', null, x)), h('th', { class: 'num' }, 'CPU'), h('th', { class: 'num' }, 'Memory'), h('th', null, 'Security'), h('th', null, 'Seen'))),
        h('tbody', null, r.map(listRow))))));
    } else content.append(h('div', { class: 'grid' }, r.map(d => deviceCard(d, selected, onSel))));
  };
  const refresh = async () => { try { devices = await getDevices(true); draw(); } catch (e) { /* handled by api() */ } };

  shell('devices', [
    pageHead('Devices', 'Every PC you manage', h('a', { class: 'btn primary', href: '#/enroll' }, icon('plus'), 'Add a PC')),
    pendingBox,
    h('div', { class: 'toolbar' }, h('div', { class: 'grow' }, search), groupSel, tagSel, sortSel, viewSeg),
    h('div', { style: { marginBottom: '14px' } }, pills),
    content, bulk]);
  refresh(); every(5000, refresh);
}

// Edit the group and tags of one or many devices.
async function groupDialog(devs) {
  const all = await getDevices();
  const groups = [...new Set(all.map(d => d.group).filter(Boolean))];
  const single = devs.length === 1 ? devs[0] : null;
  const list = h('datalist', { id: 'grouplist' }, groups.map(g => h('option', { value: g })));
  const group = h('input', { type: 'text', list: 'grouplist', maxLength: 40, placeholder: devs.length > 1 ? 'Leave empty to keep each PC\'s group' : 'e.g. Reception, Warehouse', value: single ? single.group || '' : '' });
  const tags = h('input', { type: 'text', placeholder: 'e.g. laptop, vip, finance', value: single ? (single.tags || []).join(', ') : '' });
  const mode = h('select', null, h('option', { value: 'add' }, 'Add these tags'), h('option', { value: 'set' }, 'Replace tags with these'));
  const body = h('div', { class: 'stack' }, h('p', { class: 'muted', style: { margin: 0 } }, devs.length === 1 ? devs[0].name : plural(devs.length, 'PC') + ' selected'),
    h('label', { class: 'field' }, h('span', null, 'Group'), group, list), h('label', { class: 'field' }, h('span', null, 'Tags (comma separated)'), tags),
    devs.length > 1 ? mode : null);
  const ok = await modal('Group & tags', body, [{ label: 'Cancel', value: false }, { label: 'Save', value: true, cls: 'primary' }]);
  if (!ok) return false;
  const newTags = parseTags(tags.value), g = group.value.trim();
  try {
    for (const d of devs) {
      const t = devs.length > 1 && mode.value === 'add' ? [...new Set([...(d.tags || []), ...newTags])] : newTags;
      await api('POST', `/api/devices/${d.id}/edit`, { name: d.name, notes: d.notes || '', group: devs.length > 1 && !g ? d.group || '' : g, tags: t });
    }
    toast('Saved', 'ok'); return true;
  } catch (e) { toast(e.message, 'bad'); return false; }
}

// ---------- enrollment ----------
route(/^\/enroll$/, viewEnroll);
function viewEnroll() {
  const out = h('div'); const list = h('div');
  const label = h('input', { type: 'text', placeholder: "e.g. Dad's laptop", maxLength: 80 });
  const hours = h('select', null, [[1, '1 hour'], [24, '24 hours'], [72, '3 days'], [168, '7 days'], [720, '30 days']].map(([v, l]) => h('option', { value: v, selected: v === 24 }, l)));
  const uses = h('select', null, [[1, '1 PC (single use)'], [5, '5 PCs'], [25, '25 PCs'], [0, 'Unlimited']].map(([v, l]) => h('option', { value: v }, l)));
  const consent = h('select', null, [['prompt_if_present', 'Ask the person at the PC if someone is using it (recommended)'], ['always_prompt', 'Always ask before a remote screen session'], ['unattended', 'Never ask (unattended access)']].map(([v, l]) => h('option', { value: v }, l)));
  let info = { baseUrl: location.origin, msi: false, releases: {} };

  // Download a personalised installer (token baked in) for one platform.
  const fetchInstaller = async (osName, token, fallbackName) => {
    const res = await fetch('/api/installer', { method: 'POST', credentials: 'same-origin', headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': S.csrf || '' }, body: JSON.stringify({ token, consent: consent.value, os: osName }) });
    if (res.status === 428) { await askStepUp(); throw new Error('Confirmed. Click Download again.'); }
    if (!res.ok) { let m = 'download failed'; try { m = (await res.json()).error || m; } catch (e) { /* not json */ } throw new Error(m); }
    const url = URL.createObjectURL(await res.blob()), a = h('a', { href: url, download: ((res.headers.get('Content-Disposition') || '').match(/filename="([^"]+)"/) || [])[1] || fallbackName });
    document.body.append(a); a.click(); a.remove(); setTimeout(() => URL.revokeObjectURL(url), 10000);
  };
  const cmdBlock = (text) => h('div', null, h('pre', { class: 'out' }, text), h('div', { style: { marginTop: '8px' } }, copyButton(() => text)));
  const dlRow = (title, text, btn) => h('div', { class: 'notice', style: { marginBottom: '14px' } }, h('div', { class: 'row spread' }, h('div', { style: { maxWidth: '60ch' } }, h('b', null, title), h('div', { class: 'muted small-text' }, text)), btn));
  let osTab = store.get('enrollos', 'windows');

  const create = actionButton('Create install command', async () => {
    const r = await api('POST', '/api/tokens', { label: label.value.trim(), hours: Number(hours.value), maxUses: Number(uses.value) });
    const base = info.baseUrl, has = n => (info.dist || []).includes(n);
    const props = `SERVER=${base} TOKEN=${r.token}` + (consent.value !== 'prompt_if_present' ? ` CONSENT=${consent.value}` : '');
    const flags = `--server ${base} --token ${r.token}` + (consent.value !== 'prompt_if_present' ? ` --consent ${consent.value}` : '');
    const panes = {
      windows: () => [
        info.installer ? dlRow('Easiest: download a ready-to-run installer', 'Double-click it on the PC and approve the admin prompt. The token is already inside. Keep the file private until it has been used.',
          actionButton('Download installer (.msi)', () => fetchInstaller('windows', r.token, 'Helm-Agent.msi'), 'primary')) : null,
        h('p', { class: 'muted' }, 'Or run this in an elevated Command Prompt or PowerShell on the PC:'),
        info.msi ? cmdBlock(`msiexec /i ${base}/dl/Helm-Agent.msi /qn ${props}`) : cmdBlock(`msiexec /i Helm-Agent.msi /qn ${props}`)],
      linux: () => [
        dlRow('Download a ready-to-run script', 'Debian, Ubuntu and Raspberry Pi OS (64-bit x86 or ARM). Run it with sudo. The token is already inside.',
          actionButton('Download script (.sh)', () => fetchInstaller('linux', r.token, 'install-linux.sh'), 'primary')),
        h('p', { class: 'muted' }, 'Or paste this one-liner on the machine (as a user with sudo):'),
        cmdBlock(`curl -fsSL ${base}/dl/install-linux.sh | sudo bash -s -- ${flags}`)],
      macos: () => [
        dlRow('Download a ready-to-run script', 'macOS 12 or newer, Intel or Apple silicon. Run it in Terminal with sudo. The token is already inside.',
          actionButton('Download script (.sh)', () => fetchInstaller('macos', r.token, 'install-macos.sh'), 'primary')),
        h('p', { class: 'muted' }, 'Or paste this one-liner in Terminal:'),
        cmdBlock(`curl -fsSL ${base}/dl/install-macos.sh | sudo bash -s -- ${flags}`),
        has('Helm-Agent-macos-arm64.pkg') || has('Helm-Agent-macos-amd64.pkg') ? h('div', { style: { marginTop: '18px' } },
          h('h4', null, 'Prefer a double-click installer?'),
          h('p', { class: 'muted' }, 'Download the package for the Mac’s chip and the enrollment file below, keep both in the same folder, then open the package. Apple silicon = M1 or newer.'),
          h('div', { class: 'row' },
            has('Helm-Agent-macos-arm64.pkg') ? h('a', { class: 'btn', href: '/dl/Helm-Agent-macos-arm64.pkg', download: '' }, icon('download'), 'Package (Apple silicon)') : null,
            has('Helm-Agent-macos-amd64.pkg') ? h('a', { class: 'btn', href: '/dl/Helm-Agent-macos-amd64.pkg', download: '' }, icon('download'), 'Package (Intel)') : null,
            actionButton('Enrollment file (helm-enroll.conf)', () => fetchInstaller('macos-conf', r.token, 'helm-enroll.conf')))) : null],
    };
    const paneBox = h('div');
    const drawPane = () => clear(paneBox).append(panes[osTab]());
    clear(out).append(h('div', { class: 'panel', style: { marginTop: '16px' } },
      h('div', { class: 'phead' }, h('h3', null, 'Install on the device'), h('span', { class: 'chip warn plain' }, 'Token shown once')),
      h('div', { class: 'ostabs' }, segmented([['windows', 'Windows'], ['linux', 'Linux'], ['macos', 'macOS']], osTab, v => { osTab = v; store.set('enrollos', v); drawPane(); })),
      paneBox,
      h('p', { class: 'muted', style: { marginTop: '14px' } }, 'The device appears under Devices as “Pending approval” until you approve it. Token: ', h('code', null, r.token), ' · valid until ', fmtTime(r.info.expiresAt))));
    drawPane();
    loadTokens();
  });

  const loadTokens = async () => {
    const toks = await api('GET', '/api/tokens');
    clear(list).append(table(['Label', 'Created', 'Expires', 'Used', ''].map(x => ({ label: x })), toks.map(t => {
      const dead = t.revoked || new Date(t.expiresAt) < new Date() || (t.maxUses > 0 && t.uses >= t.maxUses);
      return h('tr', null, h('td', null, t.label || '(no label)'), h('td', null, fmtTime(t.createdAt)), h('td', null, fmtTime(t.expiresAt)),
        h('td', null, t.uses + (t.maxUses ? ' / ' + t.maxUses : ''), dead ? h('span', { class: 'muted' }, t.revoked ? ' (revoked)' : ' (expired/used up)') : null),
        h('td', null, dead ? null : actionButton('Revoke', async () => { await api('DELETE', '/api/tokens/' + t.id); loadTokens(); }, 'danger small')));
    }), { empty: 'No tokens yet' }));
  };

  shell('enroll', [pageHead('Add a device', 'Enroll a Windows PC, Mac or Linux machine with a one-time token'),
    h('div', { class: 'panel stack' },
      h('p', { style: { margin: 0 } }, 'Each PC enrolls with a token. Tokens expire and can be single-use. The token is removed from the PC after it has enrolled.'),
      h('div', { class: 'row' }, h('label', { class: 'field' }, h('span', null, 'Label'), label), h('label', { class: 'field' }, h('span', null, 'Valid for'), hours), h('label', { class: 'field' }, h('span', null, 'Can enroll'), uses)),
      h('label', { class: 'field' }, h('span', null, 'Remote screen consent on that PC'), consent),
      h('div', null, create)),
    out, h('div', { class: 'panel flush', style: { marginTop: '16px' } }, h('div', { class: 'phead' }, h('h3', null, 'Tokens')), list)]);
  api('GET', '/api/info').then(i => { info = i; }).catch(() => { });
  loadTokens().catch(() => { });
}

// ---------- activity ----------
route(/^\/activity$/, viewActivity);
async function viewActivity() {
  const body = h('div', { class: 'panel flush' }, h('div', { style: { padding: '20px' } }, h('span', { class: 'spinner' })));
  shell('activity', [pageHead('Activity log', 'Everything done through this console, newest first', h('a', { class: 'btn', href: '/api/reports/audit', download: '' }, 'Export CSV')), body]);
  try {
    const [rows, devs] = await Promise.all([api('GET', '/api/audit?limit=300'), getDevices()]);
    const names = Object.fromEntries(devs.map(d => [d.id, d.name]));
    const q = h('input', { type: 'search', placeholder: 'Filter…', style: { margin: '12px 20px' } });
    const tb = h('div');
    const draw = () => {
      const f = q.value.toLowerCase();
      clear(tb).append(table(['Time', 'Action', 'PC', 'Detail', 'From'].map(x => ({ label: x })), rows.filter(r => !f || JSON.stringify(r).toLowerCase().includes(f) || (names[r.device] || '').toLowerCase().includes(f))
        .map(r => h('tr', null, h('td', { class: 'nowrap' }, fmtTime(r.time)), h('td', null, h('span', { class: 'badge' }, r.action)), h('td', null, r.device ? (names[r.device] || r.device) : ''), h('td', { class: 'mono wrap' }, r.detail || ''), h('td', { class: 'muted' }, r.ip || ''))), { empty: 'No matching entries' }));
    };
    q.addEventListener('input', draw);
    clear(body).append(q, tb); draw();
  } catch (e) { clear(body).append(h('div', { style: { padding: '20px' } }, 'Could not load activity: ' + e.message)); }
}

boot();
