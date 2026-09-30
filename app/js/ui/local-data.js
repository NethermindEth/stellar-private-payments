import { ensureStorage, isStorageUnlocked, lockStorage, manageStorageBackup, STORAGE_STATE_EVENT } from '../wasm-facade.js';
import { autoLockMinutes, setAutoLockMinutes } from '../storage-timeout.js';
import { rememberedNoteOwner } from '../account-session.js';
import { getConnectedAddress } from '../wallet.js';
import { Wallet } from './navigation.js';
import { Toast } from './core.js';
import { isDbLockedError, showDbLockedModal } from '../db-locked.js';

export const LocalData = {
    init() {
        const button = document.getElementById('storage-lock-btn');
        const select = document.getElementById('settings-auto-lock');
        let savingTimeout = false;
        const render = () => {
            const unlocked = isStorageUnlocked();
            const busy = ['unlocking', 'locking'].includes(document.body.dataset.storageState);
            document.getElementById('storage-export').disabled = busy || !unlocked;
            document.getElementById('storage-import').disabled = busy || unlocked;
            document.getElementById('storage-reset').disabled = busy || unlocked;
            if (document.body.dataset.storageRecovery === 'required') {
                document.getElementById('storage-recovery-message').textContent = 'Your encrypted data is still here, but its unlocking record is missing. Import a matching backup, or reset local storage to start again. The wallet signature alone cannot recover the missing key.';
            }
            select.disabled = !unlocked || savingTimeout;
            select.title = unlocked ? '' : 'Unlock to change';
            select.value = unlocked ? String(autoLockMinutes()) : '';
            document.getElementById('settings-auto-lock-hint').textContent = unlocked ? 'Saved in encrypted local storage.' : 'Unlock to change the inactivity timeout.';
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
        const fileInput = document.getElementById('storage-backup-file');
        document.getElementById('storage-import').addEventListener('click', () => fileInput.click());
        fileInput.addEventListener('change', async () => {
            const file = fileInput.files[0];
            fileInput.value = '';
            if (!file) return;
            if (file.size > 384 * 1024 * 1024) { Toast.show('Backup is too large.', 'error'); return; }
            if (!window.confirm('Restore this encrypted backup? It will become your active local storage after the original wallet account unlocks it and validation succeeds. Changes made since the backup will not appear in the restored data.')) return;
            try {
                await manageStorageBackup('import', await file.text());
                window.location.reload();
            } catch (error) { if (error?.code !== 'unlock-cancelled') Toast.show(error.message, 'error'); }
        });
        document.getElementById('storage-export').addEventListener('click', async () => {
            try {
                const text = await manageStorageBackup('export');
                const url = URL.createObjectURL(new Blob([text], { type: 'application/json' }));
                const link = document.createElement('a');
                link.href = url;
                link.download = `spp-encrypted-backup-${new Date().toISOString().slice(0, 10)}.json`;
                document.body.append(link);
                link.click();
                link.remove();
                setTimeout(() => { URL.revokeObjectURL(url); window.location.reload(); }, 1000);
            } catch (error) {
                Toast.show(error.message, 'error');
                // Clear decrypted application state even when exporting fails.
                setTimeout(() => window.location.reload(), 3000);
            }
        });
        document.getElementById('storage-reset').addEventListener('click', async () => {
            if (window.prompt('This permanently deletes encrypted local data, including private notes, history and settings, plus local encrypted backup copies. It does not move on-chain funds. Data without an external backup may be unrecoverable. Close other app tabs first. Type DELETE to reset.') !== 'DELETE') return;
            try { await manageStorageBackup('reset'); window.location.reload(); }
            catch (error) { Toast.show(`Could not reset local storage: ${error.message}. Close other app tabs and try again.`, 'error'); }
        });
        select.addEventListener('change', async () => {
            if (!isStorageUnlocked() || savingTimeout) { render(); return; }
            savingTimeout = true;
            const minutes = Number(select.value);
            render();
            try { await setAutoLockMinutes(minutes); }
            catch (error) { Toast.show(error.message, 'error'); }
            finally { savingTimeout = false; render(); }
        });
    },
};
