'use strict';
/* Applies the saved (or system) colour theme before the page paints, to avoid a light flash in dark mode. */
(function () {
  var t = null;
  try { t = JSON.parse(localStorage.getItem('helm.theme')); } catch (e) { /* no storage */ }
  if (t !== 'dark' && t !== 'light') t = 'dark';
  document.documentElement.setAttribute('data-theme', t);
})();
