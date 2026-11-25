// Helm service worker: keeps the app shell available offline. It never touches /api, /ws or downloads.
const CACHE = 'helm-shell-v21';
const SHELL = ['/', '/style.css', '/ui.css', '/theme.js', '/app.js', '/device.js', '/modules.js', '/pcs.js', '/pages.js', '/home.js', '/inbox.js', '/changelog.js', '/ops.js', '/Inter.woff2', '/icon-192.png'];
self.addEventListener('install', e => { e.waitUntil(caches.open(CACHE).then(c => c.addAll(SHELL)).then(() => self.skipWaiting())); });
self.addEventListener('activate', e => { e.waitUntil(caches.keys().then(ks => Promise.all(ks.filter(k => k !== CACHE).map(k => caches.delete(k)))).then(() => self.clients.claim())); });
self.addEventListener('fetch', e => {
  const u = new URL(e.request.url);
  if (e.request.method !== 'GET' || u.origin !== location.origin || /^\/(api|ws|dl|healthz)/.test(u.pathname)) return;
  // network first so a new server version shows up immediately; the cache is only the offline fallback
  e.respondWith(fetch(e.request).then(r => { if (r.ok) { const c = r.clone(); caches.open(CACHE).then(x => x.put(e.request, c)); } return r; })
    .catch(() => caches.match(e.request).then(r => r || caches.match('/'))));
});
