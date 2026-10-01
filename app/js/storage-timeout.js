const AUTO_LOCK_KEY = 'auto_lock_minutes';
const DEFAULT_AUTO_LOCK_MINUTES = 5;
export const AUTO_LOCK_CHOICES = [5, 15, 30, 60, 0];
let timeoutMinutes = DEFAULT_AUTO_LOCK_MINUTES;
let unlockedStorage = null;

export function autoLockMinutes() { return timeoutMinutes; }

/** Read only the encrypted setting; never migrate an untrusted plaintext timeout. */
export async function loadAutoLockSetting(storage) {
    clearAutoLockSetting();
    const saved = await storage.getSetting(AUTO_LOCK_KEY);
    const minutes = AUTO_LOCK_CHOICES.includes(saved) ? saved : DEFAULT_AUTO_LOCK_MINUTES;
    if (saved !== minutes) await storage.setSetting(AUTO_LOCK_KEY, minutes);
    timeoutMinutes = minutes;
    unlockedStorage = storage;
    try { globalThis.localStorage?.removeItem('spp.autoLockMinutes'); } catch { /* Obsolete value is never read. */ }
}

export function clearAutoLockSetting() {
    unlockedStorage = null;
    timeoutMinutes = DEFAULT_AUTO_LOCK_MINUTES;
}

export async function setAutoLockMinutes(minutes) {
    if (!unlockedStorage) throw new Error('Unlock local data to change the inactivity timeout.');
    if (!AUTO_LOCK_CHOICES.includes(minutes)) throw new Error('Invalid auto-lock timeout.');
    const storage = unlockedStorage;
    await storage.setSetting(AUTO_LOCK_KEY, minutes);
    if (storage === unlockedStorage) timeoutMinutes = minutes;
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
