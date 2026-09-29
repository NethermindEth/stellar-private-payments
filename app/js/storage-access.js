import { lastStorageActivity, storageActivityPending, withStorageActivity } from './storage-activity.js';
import { openStorage, settledStorageStatus } from './storage-open.js';
import { closeAndReload } from './storage-lock.js';
import { FreighterSigner } from 'stellar-private-payments/freighter';
import { createFreighter, unlockFreighter } from './storage-freighter.js';

const AUTO_LOCK_KEY = 'spp.autoLockMinutes';
const DEFAULT_AUTO_LOCK_MINUTES = 5;
export const AUTO_LOCK_CHOICES = [5, 15, 30, 60, 0];

/** Wallet approval opens the private vault; public indexing stays available. */
export async function unlockStorage(storage, { onOpened = () => {} } = {}) {
    if (await settledStorageStatus(storage) === 'unlocked') { onOpened(); return; }
    await new Promise((resolve, reject) => {
        const overlay = el('div', 'fixed inset-0 z-[70] flex items-center justify-center bg-ink-950/90 px-4 py-8 backdrop-blur-sm');
        overlay.setAttribute('role', 'dialog');
        overlay.setAttribute('aria-modal', 'true');
        overlay.setAttribute('aria-labelledby', 'storage-wallet-title');
        overlay.dataset.testid = 'storage-wallet-dialog';
        const card = el('div', 'w-full max-w-md rounded-[28px] border border-white/10 bg-ink-950 p-8 space-y-5 text-slate-200');
        overlay.append(card);
        document.body.append(overlay);
        let busy = false;
        const button = text => { const b = el('button', 'rounded-xl border border-white/10 px-4 py-3 text-sm hover:bg-white/10 disabled:opacity-50', text); b.type = 'button'; return b; };
        const cancel = button('Cancel');
        cancel.onclick = () => {
            if (busy) return;
            overlay.remove();
            reject(Object.assign(new Error('Private data remains locked.'), { code: 'unlock-cancelled' }));
        };
        const render = async (message = '') => {
            const status = await settledStorageStatus(storage);
            if (status === 'unlocked') {
                onOpened();
                overlay.remove();
                resolve();
                return;
            }
            overlay.dataset.mode = status;
            const creating = ['new', 'unencrypted'].includes(status);
            const blocked = status === 'recovery-required';
            const title = el('h2', 'text-xl font-semibold text-white', blocked ? 'Existing data needs recovery' : creating ? 'Protect your private data with Freighter' : 'Unlock your private data');
            title.id = 'storage-wallet-title';
            const text = el('p', 'text-sm leading-6', blocked
                ? 'This vault has no Freighter unlock record. Its data has been preserved. Open it with the previous app version and enable Freighter access, then return here. Reset permanently deletes local data.'
                : creating
                    ? 'Approve two matching messages in Freighter to protect your keys, notes and history. Future sessions need one approval from this same wallet account. There is no separate app password or passkey.'
                    : 'Approve the local-storage message in the enrolled Freighter account. This does not authorize a transaction.');
            const error = el('p', 'text-sm text-rose-300', message);
            error.dataset.testid = 'storage-wallet-error';
            error.setAttribute('role', 'alert');
            card.replaceChildren(title, text);
            if (status === 'unencrypted') card.append(el('p', 'text-sm text-amber-200', 'Existing plaintext data will be encrypted. Earlier copies and browser backups cannot be securely erased.'));
            if (!creating && !blocked) {
                const context = await storage.walletContext();
                card.append(el('p', 'break-all text-xs text-slate-400', context?.address || ''));
            }
            let timeout;
            if (creating) {
                const label = el('label', 'block text-sm', 'Automatically lock after');
                timeout = el('select', 'mt-2 w-full rounded-xl bg-ink-950 border border-white/10 p-3');
                timeout.dataset.testid = 'storage-auto-lock';
                for (const minutes of AUTO_LOCK_CHOICES) {
                    const option = el('option', '', minutes === 0 ? 'Never' : minutes === 60 ? '1 hour' : `${minutes} minutes`);
                    option.value = String(minutes);
                    timeout.append(option);
                }
                timeout.value = String(autoLockMinutes());
                label.append(timeout);
                card.append(label);
            }
            card.append(error);
            const actions = el('div', 'flex flex-wrap gap-3');
            if (!blocked) {
                const submit = button(creating ? 'Protect with Freighter' : 'Unlock with Freighter');
                submit.dataset.testid = 'storage-wallet-submit';
                submit.onclick = async () => {
                    if (busy) return;
                    busy = true;
                    for (const b of card.querySelectorAll('button, select')) b.disabled = true;
                    error.textContent = '';
                    try {
                        if (timeout) setAutoLockMinutes(Number(timeout.value));
                        await withStorageActivity(() => openStorage(storage, () => creating
                            ? createFreighter(storage, new FreighterSigner())
                            : unlockFreighter(storage, new FreighterSigner())));
                        await render();
                    } catch (failure) {
                        await render(failure?.message || 'Could not unlock local data.');
                    } finally { busy = false; cancel.disabled = false; }
                };
                actions.append(submit);
            }
            actions.append(cancel);
            card.append(actions);
            if (!creating) {
                const reset = button('Delete local data');
                reset.dataset.testid = 'storage-reset';
                reset.onclick = () => {
                    const warning = el('p', 'text-sm text-rose-300', 'Delete all local keys, notes, history and cached chain data? Unsynced local history may be lost. Deletion is not secure erasure. This cannot be undone.');
                    const confirm = button('Confirm deletion');
                    confirm.dataset.testid = 'storage-reset-confirm';
                    confirm.onclick = async () => {
                        if (busy) return;
                        busy = true;
                        confirm.disabled = true;
                        cancel.disabled = true;
                        try {
                            await storage.reset();
                            // The active indexer holds cursors in memory. Restart
                            // it against the empty public cache after deletion.
                            await closeAndReload(storage);
                        }
                        catch (failure) { await render(failure.message); }
                        finally { busy = false; cancel.disabled = false; }
                    };
                    card.replaceChildren(title, warning, confirm, cancel);
                };
                card.append(reset);
            }
        };
        render().catch(error => { overlay.remove(); reject(error); });
    });
}

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
    let lastActivity = performance.now();
    let busyDeadline = null;
    const touch = () => { lastActivity = performance.now(); busyDeadline = null; };
    const events = ['pointerdown', 'keydown', 'wheel', 'touchstart'];
    for (const type of events) window.addEventListener(type, touch, { capture: true, passive: true });
    let locking = false;
    const check = () => {
        if (locking) return;
        const minutes = autoLockMinutes();
        if (minutes === 0) { busyDeadline = null; return; }
        const now = performance.now();
        const busy = operationInProgress();
        if (!busy) busyDeadline = null;
        const idleAt = (busy ? lastActivity : Math.max(lastActivity, lastStorageActivity())) + minutes * 60_000;
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
    return () => {
        window.clearInterval(timer);
        for (const type of events) window.removeEventListener(type, touch, true);
        document.removeEventListener('visibilitychange', check);
    };
}

function operationInProgress() {
    return storageActivityPending() || document.querySelector('[data-status="submitting"], [data-state="generating"]') !== null;
}

function el(tag, className, text) {
    const node = document.createElement(tag);
    if (className) node.className = className;
    if (text !== undefined) node.textContent = text;
    return node;
}
