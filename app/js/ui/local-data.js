import { ensureStorage, isStorageUnlocked, lockStorage, STORAGE_STATE_EVENT } from '../wasm-facade.js';
import { autoLockMinutes, setAutoLockMinutes } from '../storage-timeout.js';
import { rememberedNoteOwner } from '../account-session.js';
import { getConnectedAddress } from '../wallet.js';
import { Wallet } from './navigation.js';
import { Toast } from './core.js';
import { isDbLockedError, showDbLockedModal } from '../db-locked.js';

export const LocalData = {
    init() {
        const button = document.getElementById('storage-lock-btn');
        const render = () => {
            const unlocked = isStorageUnlocked();
            // Verification is public; only database-backed views and receipt
            // generation require unlocked local data.
            document.querySelectorAll('[data-view-panel]').forEach(panel => {
                const blocked = !unlocked && panel.dataset.viewPanel !== 'disclosure';
                panel.inert = blocked;
                panel.style.display = blocked ? 'none' : '';
            });
            const generate = document.getElementById('disclosure-generate');
            if (generate) { generate.inert = !unlocked; generate.hidden = !unlocked; }

            const notice = document.getElementById('storage-locked-notice');
            if (notice) notice.hidden = unlocked;
            button.textContent = unlocked ? 'Lock' : 'Unlock';
            button.title = unlocked ? 'Lock local data' : 'Unlock local data';
            button.dataset.state = unlocked ? 'unlocked' : 'locked';
            button.disabled = ['unlocking', 'locking'].includes(document.body.dataset.storageState);
        };
        window.addEventListener(STORAGE_STATE_EVENT, render);
        render();
        button.addEventListener('click', async () => {
            if (isStorageUnlocked()) {
                await lockStorage();
                return;
            }
            try {
                await ensureStorage({ unlock: true });
                if (rememberedNoteOwner() && await getConnectedAddress()) await Wallet.connect({ auto: true });
            } catch (error) {
                if (error?.code === 'unlock-cancelled') return;
                if (isDbLockedError(String(error))) showDbLockedModal(String(error));
                else Toast.show(error?.message || 'Could not unlock local data.', 'error');
            }
        });
        const select = document.getElementById('settings-auto-lock');
        select.value = String(autoLockMinutes());
        select.addEventListener('change', () => setAutoLockMinutes(Number(select.value)));
    },
};
