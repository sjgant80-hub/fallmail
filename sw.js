// FallMail service worker · offline-first cache
const VERSION = 'fallmail-v1';
const CORE = ['./', './index.html', './fallmail.js', './manifest.webmanifest'];

self.addEventListener('install', (e) => {
  e.waitUntil(caches.open(VERSION).then(c => c.addAll(CORE)).then(() => self.skipWaiting()));
});

self.addEventListener('activate', (e) => {
  e.waitUntil(caches.keys().then(keys => Promise.all(keys.filter(k => k !== VERSION).map(k => caches.delete(k)))).then(() => self.clients.claim()));
});

self.addEventListener('fetch', (e) => {
  const url = new URL(e.request.url);
  if (e.request.method !== 'GET') return;
  // Estate primitives: network-first with cache fallback (they get versioned upstream)
  if (url.origin === self.location.origin) {
    e.respondWith(caches.match(e.request).then(hit => hit || fetch(e.request).then(res => {
      if (res.ok) { const clone = res.clone(); caches.open(VERSION).then(c => c.put(e.request, clone)); }
      return res;
    }).catch(() => hit)));
  }
});
