const FIVE_DAYS_MS = 5 * 24 * 60 * 60 * 1000;
const META_CACHE = 'poolstellar-meta';
const LAST_VISIT_URL = '/last-visit';

// Make the app's pages and workers cross-origin isolated, which the threaded
// prover needs. GitHub Pages cannot send these headers.
const ISOLATION_HEADERS = [
    ['Cross-Origin-Opener-Policy', 'same-origin'],
    ['Cross-Origin-Embedder-Policy', 'require-corp'],
];

self.addEventListener('install', () => self.skipWaiting());
self.addEventListener('activate', (e) => e.waitUntil(self.clients.claim()));

self.addEventListener('fetch', (e) => {
    const { request } = e;
    // Only documents and worker scripts carry the policy. Everything else,
    // cross-origin calls (RPC, bootnode, fonts) included, is not intercepted.
    if (request.mode !== 'navigate' && request.destination !== 'worker') return;
    const url = new URL(request.url);
    if (url.origin !== self.location.origin) return;
    // The docs published under docs/ need no isolation.
    if (url.href.startsWith(new URL('docs/', self.registration.scope).href)) return;
    e.respondWith(withIsolationHeaders(request));
});

async function withIsolationHeaders(request) {
    const res = await fetch(request);
    // Opaque (a navigation's redirect) cannot be rebuilt; pass it on as it is.
    if (res.status === 0) return res;
    const headers = new Headers(res.headers);
    for (const [name, value] of ISOLATION_HEADERS) headers.set(name, value);
    return new Response(res.body, { status: res.status, statusText: res.statusText, headers });
}

self.addEventListener('periodicsync', (e) => {
    if (e.tag === 'check-last-visit') {
        e.waitUntil(checkAndNotify());
    }
});

async function checkAndNotify() {
    const cache = await caches.open(META_CACHE);
    const res = await cache.match(LAST_VISIT_URL);
    if (!res) return;

    const lastVisit = parseInt(await res.text(), 10);
    if (!lastVisit || Date.now() - lastVisit < FIVE_DAYS_MS) return;

    // Skip if the user already has the tab open
    const openClients = await self.clients.matchAll({ type: 'window', includeUncontrolled: true });
    if (openClients.some((c) => c.visibilityState === 'visible')) return;

    await self.registration.showNotification('PoolStellar Reminder', {
        body: "It's been over 5 days since you last opened PoolStellar. Open the app to stay within the RPC retention window.",
        icon: '/assets/logo.svg',
        tag: 'reopen-reminder',
        renotify: false,
    });
}
