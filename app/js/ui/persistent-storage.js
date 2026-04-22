import { Toast } from './core.js';

// https://developer.mozilla.org/en-US/docs/Web/API/Storage_API/Storage_quotas_and_eviction_criteria

const STORAGE_PERSIST_FLAG = 'poolstellar_storage_persist_prompted';

function hasStorageManager() {
    return (
        typeof navigator !== 'undefined' &&
        navigator.storage &&
        typeof navigator.storage.persisted === 'function' &&
        typeof navigator.storage.persist === 'function'
    );
}

async function isPersisted() {
    if (!hasStorageManager()) return false;
    try {
        return await navigator.storage.persisted();
    } catch (e) {
        console.debug('[Storage] navigator.storage.persisted() failed:', e);
        return false;
    }
}

function showPersistModal() {
    const modal = document.getElementById('storage-persist-modal');
    const errorEl = document.getElementById('storage-persist-modal-error');
    const enableBtn = document.getElementById('storage-persist-enable-btn');
    const declineBtn = document.getElementById('storage-persist-decline-btn');

    if (!modal || !enableBtn || !declineBtn || !errorEl) {
        throw new Error('Storage persistence modal is missing from the page');
    }

    errorEl.classList.add('hidden');
    errorEl.textContent = '';
    enableBtn.disabled = false;
    declineBtn.disabled = false;

    modal.classList.remove('hidden');

    return new Promise((resolve) => {
        const cleanup = () => {
            enableBtn.removeEventListener('click', onEnableClick);
            declineBtn.removeEventListener('click', onDeclineClick);
            modal.classList.add('hidden');
        };

        const onEnableClick = async () => {
            try {
                enableBtn.disabled = true;
                declineBtn.disabled = true;

                let granted = false;
                try {
                    granted = await navigator.storage.persist();
                } catch (e) {
                    console.debug('[Storage] navigator.storage.persist() failed:', e);
                }

                cleanup();
                resolve({ action: 'enable', granted });
            } catch (e) {
                enableBtn.disabled = false;
                declineBtn.disabled = false;
                errorEl.textContent = e?.message || 'Failed to request durable storage';
                errorEl.classList.remove('hidden');
            }
        };

        const onDeclineClick = () => {
            cleanup();
            resolve({ action: 'decline', granted: false });
        };

        enableBtn.addEventListener('click', onEnableClick);
        declineBtn.addEventListener('click', onDeclineClick);
    });
}

/**
 * Best-effort request for durable/persistent storage to reduce risk of OPFS eviction.
 * For manual connect flows, shows a one-time modal that triggers persist() on a user click.
 *
 * @param {{ interactive?: boolean }} opts
 */
export async function ensurePersistentStorage({ interactive = false } = {}) {
    if (!hasStorageManager()) return;

    const already = await isPersisted();
    if (already) return;

    // Only prompt once (per browser profile).
    const prompted = (() => {
        try {
            return window.localStorage.getItem(STORAGE_PERSIST_FLAG) === '1';
        } catch {
            return false;
        }
    })();

    if (!interactive || prompted) {
        console.debug('[Storage] not persisted (no prompt)');
        return;
    }

    // Mark as prompted before showing UI to avoid repeated prompts if anything throws.
    try {
        window.localStorage.setItem(STORAGE_PERSIST_FLAG, '1');
    } catch {
        // ignore
    }

    const { action, granted } = await showPersistModal();

    if (action !== 'enable') {
        Toast.show(
            'Local database may be evicted by the browser under storage pressure.',
            'info',
            8000
        );
        return;
    }

    if (granted) {
        Toast.show('Durable storage enabled for this site.', 'success', 6000);
    } else {
        Toast.show(
            'Browser did not grant durable storage. Local database may still be evicted.',
            'info',
            10_000
        );
    }
}
