'use strict';
/* Helm console: the pictures and small live pieces used by the PC list. */

// One drawing per kind of machine, in the console's own line style. The agent reports the kind (Hello.chassis).
const ART = {
  laptop: '<rect x="9" y="10" width="30" height="20" rx="2.5"/><path d="M5 35h38l-3 3.5H8z"/><path d="M20 33h8" opacity=".5"/>',
  desktop: '<rect x="6" y="8" width="36" height="24" rx="2.5"/><path d="M19 38h10M24 32v6"/><circle cx="24" cy="20" r="2.2" class="fill"/>',
  pi: '<rect x="6" y="10" width="36" height="28" rx="3"/><rect x="17" y="17" width="9" height="9" rx="1.5" class="fill"/><path d="M10 14h16" stroke-dasharray="1.6 1.9" opacity=".7"/><rect x="32" y="15" width="7" height="6" rx="1"/><rect x="32" y="25" width="7" height="6" rx="1"/><circle cx="11" cy="33" r="1.2" class="fill"/><circle cx="15" cy="33" r="1.2"/>',
  vm: '<path d="M24 6l15 8v18l-15 8-15-8V14z" stroke-dasharray="3 2.4"/><path d="M24 22l15-8M24 22L9 14M24 22v18" opacity=".6"/>',
  server: '<rect x="8" y="8" width="32" height="13" rx="2.5"/><rect x="8" y="27" width="32" height="13" rx="2.5"/><circle cx="14" cy="14.5" r="1.4" class="fill"/><circle cx="14" cy="33.5" r="1.4" class="fill"/><path d="M22 14.5h13M22 33.5h13" opacity=".6"/>',
};
const KIND_LABEL = { laptop: 'Laptop', desktop: 'Desktop', pi: 'Raspberry Pi', vm: 'Virtual machine', server: 'Server' };
const deviceKind = d => { const k = d && d.hello && d.hello.chassis; return ART[k] ? k : (osKey(d) === 'windows' ? 'desktop' : 'desktop'); };

// The logo you uploaded for this PC's maker (Dell, Lenovo...), or for its system (Windows...), if there is one.
function makerLogo(d) {
  const m = S.makerLogos || {}, hh = (d && d.hello) || {};
  const v = String(hh.vendor || '').toLowerCase(), o = ({ windows: 'windows', linux: 'linux', darwin: 'macos', macos: 'macos' })[String(hh.os || '').toLowerCase()];
  return m[v] || (o && m[o]) || '';
}

function deviceArt(d, size) {
  const k = deviceKind(d), box = h('span', { class: 'dart' + (d.online ? ' on' : ''), title: makeText(d) || KIND_LABEL[k] || 'Computer', style: { '--s': (size || 40) + 'px' } });
  const logo = makerLogo(d);
  if (logo) { box.classList.add('haslogo'); box.append(h('img', { class: 'dlogo', src: logo, alt: '' }), h('i', { class: 'dstat' })); return box; }
  const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
  svg.setAttribute('viewBox', '0 0 48 48'); svg.setAttribute('aria-hidden', 'true'); svg.innerHTML = ART[k];
  box.append(svg, h('i', { class: 'dstat' }));
  return box;
}

// A small meter whose width and number change in place, so a live update glides instead of redrawing.
function liveMeter(label) {
  const fill = h('i'), num = h('b', null, '–'), node = h('span', { class: 'lmeter' }, h('em', null, label), h('span', { class: 'lbar' }, fill), num);
  return { node, set(p, off) {
    node.classList.toggle('idle', off || p == null);
    if (off || p == null) { fill.style.width = '0%'; num.textContent = '–'; return; }
    fill.style.width = Math.min(100, p) + '%'; fill.className = p >= 90 ? 'hot' : p >= 75 ? 'mid' : ''; num.textContent = p + '%';
  } };
}

// Maker and model as plain text, e.g. "Dell · Latitude 5420". Shown wherever a PC's picture is.
const makeText = d => { const h = (d && d.hello) || {}; return [h.vendor, h.model && h.model !== h.vendor ? h.model : ''].filter(Boolean).join(' · '); };
const vendorChip = d => { const v = d && d.hello && d.hello.vendor; return v ? h('span', { class: 'chip plain vendor', title: makeText(d) }, v) : null; };
