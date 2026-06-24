const FIVE_DAYS_MS = 5 * 24 * 60 * 60 * 1000;
const META_CACHE = 'poolstellar-meta';
const LAST_VISIT_URL = '/last-visit';

self.addEventListener('install', () => self.skipWaiting());
self.addEventListener('activate', (e) => e.waitUntil(self.clients.claim()));

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
