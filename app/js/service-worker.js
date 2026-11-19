// The threaded prover needs a cross-origin isolated page, i.e. COOP and COEP
// response headers. Hosts that cannot send them (GitHub Pages) get them from
// sw.js, which can only add them to pages it controls; a page loaded before it
// took over is reloaded once.

// sw.js sits next to the pages wherever the site is published (PUBLIC_URL), so
// its default scope covers all of them. Resolved from the bundle in js/.
const SERVICE_WORKER_URL = new URL('../sw.js', import.meta.url).href;
// Set before reloading, so a page that is still not isolated afterwards (the
// service worker was bypassed or cannot isolate) never reloads again.
const ISOLATION_RELOAD_KEY = 'spp.isolationReload';

let registration = null;

/**
 * Register sw.js once per page. Resolves to its registration, or null where
 * service workers are unavailable (insecure origin, some private windows).
 */
export function serviceWorkerRegistration() {
    registration ??= register();
    return registration;
}

async function register() {
    if (!('serviceWorker' in navigator)) return null;
    // Before registering: a first install or an update takes over this page
    // right away (skipWaiting + clients.claim in sw.js).
    if (!window.crossOriginIsolated) {
        navigator.serviceWorker.addEventListener('controllerchange', reloadOnce);
    }
    try {
        return await navigator.serviceWorker.register(SERVICE_WORKER_URL);
    } catch (e) {
        console.debug('[ServiceWorker] registration failed:', e);
        return null;
    }
}

function reloadOnce() {
    try {
        if (sessionStorage.getItem(ISOLATION_RELOAD_KEY) === 'true') return;
        sessionStorage.setItem(ISOLATION_RELOAD_KEY, 'true');
    } catch {
        // Without the flag nothing would stop a reload loop; prove serially instead.
        return;
    }
    window.location.reload();
}
