// The header's lock button and the Local Data settings: locking, the
// inactivity delay and wallet identity.

import {
    STORAGE_UNLOCKED_EVENT,
    ensurePrivateStorage,
    isStorageUnlocked,
    lockStorage,
    resetLocalData,
    unlockedStorage,
} from '../wasm-facade.js';
import {
    autoLockMinutes,
    setAutoLockMinutes,
} from '../storage-access.js';
import { isDbLockedError, showDbLockedModal } from '../db-locked.js';
import { Toast } from './core.js';
import { confirmAction } from './confirm.js';

function renderLockButton() {
    const button = document.getElementById('storage-lock-btn');
    if (!button) return;
    const unlocked = isStorageUnlocked();
    button.dataset.state = unlocked ? 'unlocked' : 'locked';
    button.title = unlocked ? 'Lock local data' : 'Unlock local data';
    const label = document.getElementById('storage-lock-label');
    if (label) label.textContent = unlocked ? 'Lock' : 'Unlock';
    // An open shackle while unlocked.
    document.getElementById('storage-lock-shackle')
        ?.setAttribute('d', unlocked ? 'M8 11V7a4 4 0 0 1 7.5-2' : 'M8 11V7a4 4 0 0 1 8 0');
}

function bindLockButton() {
    const button = document.getElementById('storage-lock-btn');
    button?.addEventListener('click', async () => {
        if (isStorageUnlocked()) {
            await lockStorage();
            return;
        }
        try {
            await ensurePrivateStorage();
        } catch (error) {
            if (error?.code === 'unlock-cancelled') return;
            const message = error?.message || 'Could not open local data';
            if (isDbLockedError(message)) showDbLockedModal(message);
            else Toast.show(message, 'error');
        }
    });
    window.addEventListener(STORAGE_UNLOCKED_EVENT, renderLockButton);
    renderLockButton();
}

function bindAutoLock() {
    const select = document.getElementById('settings-auto-lock');
    if (!select) return;
    const render = () => { select.value = String(autoLockMinutes()); };
    render();
    window.addEventListener(STORAGE_UNLOCKED_EVENT, render);
    select.addEventListener('change', () => setAutoLockMinutes(Number(select.value)));
}

function bindDeleteLocalData() {
    const button = document.getElementById('settings-delete-local-data');
    button?.addEventListener('click', async () => {
        button.disabled = true;
        try {
            const confirmed = await confirmAction({
                title: 'Delete local data?',
                confirmLabel: 'Delete local data',
                warning: 'This deletes local keys, notes, history, settings and cached chain data in this browser. Local-only history may be lost. This cannot be undone and does not securely erase older copies.',
            });
            if (confirmed) await resetLocalData();
        } catch (error) {
            Toast.show(error?.message || 'Could not delete local data. Reload and try again.', 'error');
        } finally { button.disabled = false; }
    });
}

export const LocalData = {
    init() {
        bindLockButton();
        bindAutoLock();
        bindDeleteLocalData();
        const methods = document.getElementById('settings-unlock-methods');
        const renderMethods = async () => {
            if (!methods) return;
            if (isStorageUnlocked()) {
                const context = await unlockedStorage().walletContext();
                const identity = document.createElement('p');
                identity.className = 'break-all text-sm text-slate-300';
                identity.textContent = `Freighter account: ${context?.address || 'Unavailable'}`;
                methods.replaceChildren(identity);
            }
            else {
                const button = document.createElement('button');
                button.type = 'button';
                button.className = 'text-sm text-cyan-200 underline';
                button.textContent = 'Unlock private data to manage access';
                button.addEventListener('click', () => ensurePrivateStorage().catch(() => {}));
                methods.replaceChildren(button);
            }
        };
        window.addEventListener(STORAGE_UNLOCKED_EVENT, renderMethods);
        renderMethods();
    },
};
