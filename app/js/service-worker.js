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
// How long a page that is not isolated waits for a newly installed sw.js to
// take it over, before it goes on without isolation.
const TAKEOVER_WAIT_MS = 5_000;

let registration = null;
let isolation = null;

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
    try {
        return await navigator.serviceWorker.register(SERVICE_WORKER_URL);
    } catch (e) {
        console.debug('[ServiceWorker] registration failed:', e);
        return null;
    }
}

/**
 * Resolves once the page will not reload for cross-origin isolation. A page
 * that is not isolated and not yet controlled by sw.js waits for sw.js to take
 * it over (skipWaiting + clients.claim), then reloads once and never resolves.
 * Call it before anything opens storage, so the reload cannot interrupt it.
 */
export function isolationReady() {
    isolation ??= waitForIsolation();
    return isolation;
}

async function waitForIsolation() {
    if (window.crossOriginIsolated || !('serviceWorker' in navigator)) return;
    // Already controlled but not isolated: sw.js cannot isolate this page, and
    // a reload would not change that.
    if (navigator.serviceWorker.controller || !canReload()) return;
    const takenOver = new Promise(resolve => {
        navigator.serviceWorker.addEventListener('controllerchange', () => resolve(true), { once: true });
        setTimeout(() => resolve(false), TAKEOVER_WAIT_MS);
    });
    if (!await serviceWorkerRegistration() || !await takenOver) return;
    try {
        sessionStorage.setItem(ISOLATION_RELOAD_KEY, 'true');
    } catch {
        return;
    }
    window.location.reload();
    await new Promise(() => {});
}

/** Whether this tab may still reload once for isolation. */
function canReload() {
    try {
        return sessionStorage.getItem(ISOLATION_RELOAD_KEY) !== 'true';
    } catch {
        // Without the flag nothing would stop a reload loop; prove serially instead.
        return false;
    }
}
