'use strict';
/* Applies the saved look (mode, accent, density) before the page paints, to avoid a flash of the wrong theme. */
var HELM_ACCENTS = {
  teal:     { name: 'Teal',     l: ['#0d7a70', '#09605a', '#dcf1ee', '#ffffff', '#a6d8d1'], d: ['#5fd0c4', '#8be4da', '#11302e', '#04201c', '#1e5d57'] },
  blue:     { name: 'Blue',     l: ['#2563c9', '#1c4fa3', '#e0eafa', '#ffffff', '#b3caf0'], d: ['#7aa7ff', '#a3c2ff', '#14233f', '#06142e', '#264a85'] },
  violet:   { name: 'Violet',   l: ['#6d4fd6', '#573eb3', '#ece7fb', '#ffffff', '#cdc1f2'], d: ['#a89bff', '#c4baff', '#1f1a3d', '#10092e', '#40367f'] },
  rose:     { name: 'Rose',     l: ['#c2305a', '#a02449', '#fbe6ec', '#ffffff', '#efb4c5'], d: ['#ff8aa8', '#ffa8be', '#3a1520', '#2e0612', '#7a2d44'] },
  amber:    { name: 'Amber',    l: ['#a8620a', '#874f07', '#f9edd8', '#ffffff', '#e5c58f'], d: ['#f2b84b', '#f7cc78', '#352509', '#2a1a00', '#7a5a1f'] },
  graphite: { name: 'Graphite', l: ['#3d4a52', '#2b363d', '#e6eaec', '#ffffff', '#b9c3c8'], d: ['#b8c7d0', '#d3dee5', '#222b31', '#10181c', '#46555e'] },
};
function helmLook() {
  var look = { mode: 'dark', accent: 'teal', density: 'comfortable' };
  try {
    var t = JSON.parse(localStorage.getItem('helm.theme')); if (t === 'dark' || t === 'light' || t === 'system') look.mode = t;
    var l = JSON.parse(localStorage.getItem('helm.look')) || {};
    if (HELM_ACCENTS[l.accent]) look.accent = l.accent;
    if (l.density === 'compact' || l.density === 'comfortable') look.density = l.density;
  } catch (e) { /* no storage */ }
  return look;
}
function helmApplyLook() {
  var look = helmLook(), root = document.documentElement;
  var dark = look.mode === 'system' ? matchMedia('(prefers-color-scheme: dark)').matches : look.mode === 'dark';
  root.setAttribute('data-theme', dark ? 'dark' : 'light');
  root.setAttribute('data-density', look.density);
  var v = HELM_ACCENTS[look.accent][dark ? 'd' : 'l'], names = ['--accent', '--accent-hover', '--accent-soft', '--accent-text', '--accent-line'];
  // The side pane is always ink-dark, so it takes the light variant of the accent in both modes.
  root.style.setProperty('--side-accent', HELM_ACCENTS[look.accent].d[0]);
  root.style.setProperty('--side-accent-soft', HELM_ACCENTS[look.accent].d[2]);
  for (var i = 0; i < names.length; i++) {
    if (look.accent === 'teal') root.style.removeProperty(names[i]); else root.style.setProperty(names[i], v[i]);
  }
}
helmApplyLook();
try { matchMedia('(prefers-color-scheme: dark)').addEventListener('change', helmApplyLook); } catch (e) { /* old browser */ }
