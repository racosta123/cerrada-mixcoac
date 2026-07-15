const CACHE = 'mixcoac-v18';
const ASSETS = ['./','./index.html','./app.js','./config.js','./manifest.json'];
self.addEventListener('install', e => {
  e.waitUntil(caches.open(CACHE).then(c => c.addAll(ASSETS)).then(()=>self.skipWaiting()));
});
self.addEventListener('activate', e => {
  e.waitUntil(caches.keys().then(ks => Promise.all(ks.filter(k=>k!==CACHE).map(k=>caches.delete(k)))).then(()=>self.clients.claim()));
});
self.addEventListener('fetch', e => {
  const url = new URL(e.request.url);
  // Nunca cachear llamadas al Worker ni a Firebase
  if (url.pathname.startsWith('/abrir') || url.hostname.includes('workers.dev') || url.hostname.includes('googleapis')) return;
  e.respondWith(caches.match(e.request).then(r => r || fetch(e.request)));
});
