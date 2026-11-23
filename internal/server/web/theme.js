'use strict';
/* Applies the saved (or system) colour theme before the page paints, to avoid a light flash in dark mode. */
(function () {
  var t = null;
  try { t = JSON.parse(localStorage.getItem('helm.theme')); } catch (e) { /* no storage */ }
  if (t !== 'dark' && t !== 'light') t = window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
  document.documentElement.setAttribute('data-theme', t);
})();
