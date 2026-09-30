const AUTO_LOCK_KEY = 'spp.autoLockMinutes';
const DEFAULT_AUTO_LOCK_MINUTES = 5;
export const AUTO_LOCK_CHOICES = [5, 15, 30, 60, 0];

/** Minutes of inactivity before the app locks; 0 means never. */
export function autoLockMinutes() {
    try {
        const stored = window.localStorage.getItem(AUTO_LOCK_KEY);
        if (stored !== null && AUTO_LOCK_CHOICES.includes(Number(stored))) {
            return Number(stored);
        }
    } catch {
        // Storage can be unavailable; fall back to the default.
    }
    return DEFAULT_AUTO_LOCK_MINUTES;
}

export function setAutoLockMinutes(minutes) {
    if (!AUTO_LOCK_CHOICES.includes(minutes)) throw new Error('Invalid auto-lock timeout.');
    try {
        window.localStorage.setItem(AUTO_LOCK_KEY, String(minutes));
    } catch {
        // Keeps the default for this page when storage is unavailable.
    }
}

/**
 * Lock with `lock` after the configured minutes without user activity.
 * Browsers slow timers in background tabs, so the deadline is checked on a
 * short interval and whenever the tab becomes visible again. An operation in
 * progress gets a bounded grace period; a stuck operation cannot hold storage
 * open indefinitely.
 * @param {() => void} lock
 */
// Busy work can defer an expired idle lock for at most ten additional minutes.
export const MAX_BUSY_LOCK_DELAY_MS = 10 * 60_000;
export function startAutoLock(lock) {
    let lastActivity = Date.now();
    let busyDeadline = null;
    const touch = () => { lastActivity = Date.now(); busyDeadline = null; };
    const events = ['pointerdown', 'keydown', 'wheel', 'touchstart'];
    for (const type of events) window.addEventListener(type, touch, { capture: true, passive: true });
    let locking = false;
    const check = () => {
        if (locking) return;
        const minutes = autoLockMinutes();
        if (minutes === 0) { busyDeadline = null; return; }
        const now = Date.now();
        const busy = operationInProgress();
        if (!busy) busyDeadline = null;
        const idleAt = lastActivity + minutes * 60_000;
        if (now < idleAt) return;
        if (busy) {
            busyDeadline ??= idleAt + MAX_BUSY_LOCK_DELAY_MS;
            if (now < busyDeadline) return;
        }
        locking = true;
        lock();
    };
    const timer = window.setInterval(check, 15_000);
    document.addEventListener('visibilitychange', check);
    window.addEventListener('focus', check);
    return () => {
        window.clearInterval(timer);
        for (const type of events) window.removeEventListener(type, touch, true);
        document.removeEventListener('visibilitychange', check);
        window.removeEventListener('focus', check);
    };
}

function operationInProgress() {
    return document.querySelector('[data-status="submitting"], [data-state="generating"]') !== null;
}
