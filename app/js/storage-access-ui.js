import { Storage } from 'stellar-private-payments';
import { DatabaseKeyVault, IndexedDbKeyStore } from 'stellar-private-payments/key-vault';
import { FreighterSigner } from 'stellar-private-payments/freighter';
import { ensureWasmInit, configureStorageStartup, closeStorageForLock, exportEncryptedDatabase } from './wasm-facade.js';
import { createStorageAccess, DATABASE_ID } from './storage-access.js';

/** Gate all application initialization, including admin, on local storage access. */
export async function startStorageAccess() {
    const store = new IndexedDbKeyStore();
    const makeVault = store => new DatabaseKeyVault({ databaseId: DATABASE_ID, store });
    const vault = makeVault(store);
    const access = createStorageAccess({ vault, store, makeVault, selection: localStorage,
        open: async options => { await ensureWasmInit(); return Storage.openEncrypted(options); },
        configure: configureStorageStartup, close: closeStorageForLock, reload: () => location.reload(),
        exportDatabase: exportEncryptedDatabase,
        openMigration: async options => { await ensureWasmInit(); return Storage.openMigration(options); },
        recoverMigration: async options => { await ensureWasmInit(); return Storage.recoverMigrationSetup(options); },
        restoreDatabase: async (snapshot, keyProvider) => { await ensureWasmInit(); await Storage.restoreEncrypted(snapshot, { keyProvider }); } });
    const dialog = document.createElement('dialog');
    dialog.className = 'w-full max-w-lg rounded-2xl border border-slate-600 bg-slate-900 p-6 text-slate-100 shadow-xl backdrop:bg-black/80';
    dialog.setAttribute('aria-labelledby', 'storage-title');
    dialog.innerHTML = `
      <h2 id="storage-title" class="text-xl font-semibold">Local database</h2>
      <p id="storage-description" class="my-3 text-sm"></p>
      <p id="storage-feedback" role="alert" aria-live="assertive" tabindex="-1" class="my-3 text-sm"></p>
      <form id="storage-form" class="space-y-3">
        <label class="block">Database password
          <input id="storage-password" type="password" autocomplete="current-password" maxlength="1024" class="mt-1 block w-full rounded border border-slate-500 bg-slate-800 p-2">
        </label>
        <label id="storage-confirm-label" class="block">Confirm password
          <input id="storage-confirm" type="password" autocomplete="new-password" maxlength="1024" class="mt-1 block w-full rounded border border-slate-500 bg-slate-800 p-2">
        </label>
        <button id="storage-create" type="button">Create separate encrypted database</button>
        <button id="storage-migrate" type="button">Prepare encryption of existing local data</button>
        <p id="storage-migration-info" class="text-sm">To encrypt your current data, close other tabs using this app and choose “Prepare encryption of existing local data”. You will review and activate the copy separately.</p>
        <section id="storage-migration-section" hidden>
          <p>Close other tabs using this app. Preparation keeps your original plaintext database intact. Download a key backup before activation. Activation removes the original plaintext database and cannot be rolled back to it.</p>
          <button id="storage-migration-prepare" type="button">Prepare or resume encrypted copy</button>
          <button id="storage-migration-abort" type="button">Discard unactivated copy</button>
          <label class="block"><input id="storage-migration-confirm" type="checkbox"> I saved my key backup and want to activate encryption and remove the plaintext database.</label>
          <button id="storage-migration-activate" type="button">Activate encryption and remove plaintext</button>
        </section>
        <button id="storage-unlock" type="submit">Unlock with password</button>
        <button id="storage-migration-recover" type="button">Recover interrupted migration</button>
        <button id="storage-passkey" type="button">Unlock with passkey</button>
        <button id="storage-wallet" type="button">Unlock with Freighter</button>
        <p id="storage-wallet-account" class="text-sm break-all"></p>
        <button id="storage-resume" type="button">Retry interrupted database creation</button>
        <button id="storage-backup" type="button">Download encrypted key backup</button>
        <button id="storage-complete-backup" type="button">Download complete encrypted backup</button>
        <section id="storage-restore-section">
          <label class="block">Restore an encrypted key backup
            <input id="storage-file" type="file" accept=".json,application/json" class="my-2 block w-full">
          </label>
          <p class="text-sm">Enter the backup’s password above. The matching encrypted database must still be present in this browser.</p>
          <button id="storage-restore" type="button">Restore key and verify database</button>
        </section>
        <section id="storage-complete-restore-section">
          <p>Restore a complete database backup</p>
          <input id="storage-complete-file" type="file" accept=".sppbackup,application/octet-stream" aria-label="Complete database backup file" hidden>
          <button id="storage-complete-choose" type="button">Choose complete backup file…</button>
          <p id="storage-complete-filename" role="status" class="my-2 text-sm">No file selected. Choose a .sppbackup file.</p>
          <p class="text-sm">Use the password from when this backup was saved. Restore requires an empty encrypted database destination. If interrupted, select the same file and retry.</p>
          <button id="storage-complete-restore" type="button">Restore complete backup</button>
        </section>
        <section id="storage-manage" class="space-y-3">
          <button id="storage-enroll" type="button">Add passkey</button>
          <button id="storage-wallet-enroll" type="button">Add Freighter wallet unlock</button>
          <button id="storage-wallet-remove" type="button">Remove wallet unlock</button>
          <p>Wallet enrollment asks for two signatures of the same dedicated storage message to verify repeatable unlocking. Keep your password and backup for recovery. Never share the storage-unlock signature.</p>
          <label class="block">New password
            <input id="storage-new" type="password" autocomplete="new-password" maxlength="1024" class="mt-1 block w-full rounded border border-slate-500 bg-slate-800 p-2">
          </label>
          <label class="block">Confirm new password
            <input id="storage-new-confirm" type="password" autocomplete="new-password" maxlength="1024" class="mt-1 block w-full rounded border border-slate-500 bg-slate-800 p-2">
          </label>
          <button id="storage-change" type="button">Change password</button>
          <button id="storage-recover" type="button">Reset password with passkey</button>
        </section>
        <p class="text-sm text-slate-300">The key backup is password-encrypted and contains no database contents. Keep it with your database backup. Losing both local key storage and this file loses access. After changing your password, download a new backup; older backups still work with their old passwords.</p>
        <button id="storage-dismiss" type="button">Back</button>
      </form>`;
    for (const button of dialog.querySelectorAll('button')) {
        button.className = 'mr-2 mt-2 rounded-lg border border-slate-500 px-3 py-2 text-sm hover:bg-slate-700 disabled:opacity-40';
    }
    document.body.append(dialog);
    const el = id => dialog.querySelector(`#storage-${id}`);
    let unlocked = false;
    let required = true;
    let savedBackup = false;
    let resolveReady;
    const ready = new Promise(resolve => { resolveReady = resolve; });
    const channel = typeof BroadcastChannel === 'function' ? new BroadcastChannel('spp-storage-lock') : null;
    let locking = false;
    async function lock(broadcast = true) {
        if (locking) return;
        locking = true;
        if (broadcast) channel?.postMessage('lock');
        // Remove rendered balances, notes and key material immediately, before async teardown.
        document.body.replaceChildren(document.createTextNode('Locking local database…'));
        await access.lock();
    }
    channel?.addEventListener('message', event => { if (event.data === 'lock') void lock(false); });
    window.addEventListener('pagehide', () => channel?.close(), { once: true });
    const menu = document.createElement('div');
    menu.className = 'flex flex-wrap gap-2 px-5 py-2';
    const manage = document.createElement('button');
    manage.type = 'button'; manage.className = 'rounded border border-slate-500 px-3 py-2 text-sm';
    const lockButton = manage.cloneNode(); lockButton.textContent = 'Lock database'; lockButton.hidden = true;
    lockButton.addEventListener('click', () => void lock());
    menu.append(manage, lockButton);
    (document.querySelector('header') ?? document.body).append(menu);
    function feedback(message, failed = false) {
        el('feedback').textContent = message;
        el('feedback').className = `my-3 text-sm ${failed ? 'text-rose-300' : 'text-cyan-200'}`;
        el('feedback').focus();
    }
    async function refresh() {
        const state = await access.status();
        required = state.required;
        manage.textContent = state.required ? 'Database security' : 'Set up encrypted storage';
        lockButton.hidden = !unlocked;
        el('description').textContent = unlocked ? 'Encrypted database unlocked for this page.' : state.exists
            ? 'Unlock your local encrypted database to continue.'
            : state.required ? 'Restore your key backup, or complete the setup you started. No plaintext database will be opened.'
            : 'Create a separate encrypted database with a password of at least 15 characters. Existing plaintext data stays in place and is not copied into it.';
        if (state.restoring) el('description').textContent = 'Restore is unfinished. Select the same complete backup file and password to retry.';
        if (state.migrating) el('description').textContent = 'Migration is pending. Re-enter the same password to prepare or resume. If activation already started, use the activation action to finish cleanup.';
        el('migrate').hidden = state.exists || (state.required && !state.migrating);
        el('migration-info').hidden = el('migrate').hidden;
        el('migration-section').hidden = !state.migrating || !state.exists;
        el('create').hidden = state.exists || (state.required && !state.provisioning);
        el('confirm-label').hidden = el('create').hidden && el('migrate').hidden;
        el('password').autocomplete = state.exists ? 'current-password' : 'new-password';
        el('unlock').hidden = !state.exists || unlocked || state.restoring || state.migrating;
        el('migration-recover').hidden = !state.exists || unlocked || state.restoring || state.migrating || state.provisioning;
        el('passkey').hidden = !state.passkey || unlocked || state.restoring || state.migrating;
        el('wallet').hidden = !state.wallet || unlocked || state.restoring || state.migrating;
        el('wallet-account').hidden = !state.wallet;
        el('wallet-account').textContent = state.wallet ? `Storage wallet: ${state.walletAddress}` : '';
        el('wallet-enroll').hidden = !unlocked || state.wallet;
        el('wallet-remove').hidden = !unlocked || !state.wallet;
        el('resume').hidden = !state.needsCreation || !state.exists || unlocked;
        el('backup').hidden = !state.exists;
        el('complete-backup').hidden = !unlocked;
        el('complete-restore-section').hidden = unlocked || state.migrating || (state.exists && !state.restoring);
        el('restore-section').hidden = state.exists;
        el('manage').hidden = state.restoring || state.migrating || !state.exists || (!unlocked && !state.passkey);
        el('enroll').hidden = state.passkey || !unlocked;
        el('change').hidden = !unlocked;
        el('recover').hidden = !state.passkey;
        el('dismiss').hidden = required && !unlocked;
        return state;
    }
    let working = false;
    async function run(operation) {
        if (working || locking) return;
        working = true;
        for (const button of dialog.querySelectorAll('button')) button.disabled = true;
        feedback('Working…');
        try { await operation(); }
        catch (error) {
            feedback(error.name === 'NotAllowedError' ? 'Passkey request cancelled, timed out, or unavailable.'
                : error.code === 'unlock-failed' ? 'Incorrect password or damaged key backup. Nothing was unlocked.'
                : error.message, true);
        } finally {
            for (const input of dialog.querySelectorAll('input[type=password]')) input.value = '';
            working = false;
            for (const button of dialog.querySelectorAll('button')) button.disabled = false;
            try { await refresh(); } catch (error) { fatal(error); }
        }
    }
    const password = () => el('password').value;
    const newPassword = () => {
        if (el('new').value !== el('new-confirm').value) throw new Error('New passwords do not match.');
        return el('new').value;
    };
    async function finishUnlock(passkey) {
        const state = await access.status();
        if (state.provisioning && !savedBackup) throw new Error('Download your encrypted key backup before continuing.');
        await (passkey === 'wallet' ? access.unlockWallet(new FreighterSigner())
            : passkey ? access.unlockPasskey() : access.unlockPassword(password()));
        unlocked = true;
        dialog.close();
        resolveReady();
    }
    el('form').addEventListener('submit', event => {
        event.preventDefault();
        if (!unlocked) void run(() => finishUnlock(false));
    });
    el('create').onclick = () => run(async () => {
        if (!Storage.supportsEncryption()) throw new Error('Encrypted storage is not available in this application build.');
        if (password() !== el('confirm').value) throw new Error('Passwords do not match.');
        await access.setup(password());
        feedback('Database created. Re-enter your password and download the encrypted key backup, then unlock.');
    });
    el('resume').onclick = () => run(async () => {
        await access.resumeSetup(password());
        feedback('Database created. Download your key backup, then unlock. If it already existed, use unlock instead.');
    });
    const migrationFeedback = phase => feedback(phase === 'complete'
        ? 'Migration complete. Re-enter your password to unlock. The original plaintext database has been removed.'
        : phase === 'prepared' ? 'Encrypted copy verified. Download your key backup, then confirm activation below.'
        : phase === 'aborted' ? 'Unactivated copy discarded. Original plaintext data is intact. You can prepare it again with the same key.'
        : `Migration state: ${phase}. Resume activation to finish cleanup.`);
    el('migrate').onclick = () => run(async () => {
        if (!Storage.supportsEncryption()) throw new Error('Encrypted storage is not available in this application build.');
        if (password() !== el('confirm').value) throw new Error('Passwords do not match.');
        migrationFeedback(await access.startMigration(password()));
    });
    el('migration-prepare').onclick = () => run(async () => migrationFeedback(await access.prepareMigration(password())));
    el('migration-recover').onclick = () => run(async () => migrationFeedback(await access.recoverMigrationState(password())));
    el('migration-abort').onclick = () => run(async () => migrationFeedback(await access.abortMigration(password())));
    el('migration-activate').onclick = () => run(async () => {
        if (!savedBackup || !el('migration-confirm').checked) throw new Error('Download your key backup and confirm activation first.');
        migrationFeedback(await access.activateMigration(password()));
    });
    el('passkey').onclick = () => run(() => finishUnlock(true));
    el('wallet').onclick = () => run(() => finishUnlock('wallet'));
    el('wallet-enroll').onclick = () => run(async () => {
        await vault.addWallet(password(), new FreighterSigner());
        feedback('Wallet unlock added. Download an updated backup, then lock the database to test wallet unlock.');
    });
    el('wallet-remove').onclick = () => run(async () => {
        await vault.removeWallet(password());
        feedback('Wallet unlock removed from this browser. Saved older backups still contain their wallet wrapper.');
    });
    el('backup').onclick = () => run(async () => {
        const text = await access.backup(password());
        const url = URL.createObjectURL(new Blob([text], { type: 'application/json' }));
        const link = document.createElement('a'); link.href = url; link.download = 'spp-encrypted-key-backup.json'; link.click();
        setTimeout(() => URL.revokeObjectURL(url), 1000);
        savedBackup = true;
        feedback('Key backup download started. Keep the file safe. Re-enter your password to unlock.');
    });
    el('restore').onclick = () => run(async () => {
        const file = el('file').files[0];
        if (!file || file.size > 16384) throw new Error('Select a key backup file smaller than 16 KiB.');
        await access.restore(await file.text(), password());
        feedback('Key restored and database verified. Re-enter your password to unlock.');
    });
    el('complete-backup').onclick = () => run(async () => {
        const bytes = await access.completeBackup(password());
        const url = URL.createObjectURL(new Blob([bytes], { type: 'application/octet-stream' }));
        const link = document.createElement('a'); link.href = url; link.download = 'spp-complete-backup.sppbackup'; link.click();
        setTimeout(() => URL.revokeObjectURL(url), 1000);
        feedback('Complete encrypted backup download started. It includes this database snapshot and its wrapped key. Keep the file and its password safe.');
    });
    el('complete-choose').onclick = () => el('complete-file').click();
    el('complete-file').onchange = () => {
        el('complete-filename').textContent = el('complete-file').files[0]?.name ?? 'No file selected. Choose a .sppbackup file.';
    };
    el('complete-restore').onclick = () => {
        if (!el('complete-file').files[0]) {
            feedback('Click “Choose complete backup file…” and select your .sppbackup file first.', true);
            el('complete-choose').focus();
            return;
        }
        return run(async () => {
            const file = el('complete-file').files[0];
            await access.restoreComplete(new Uint8Array(await file.arrayBuffer()), password());
            feedback('Database and key restored. Re-enter your password to unlock.');
        });
    };
    el('enroll').onclick = () => run(async () => { await vault.addPasskey(password()); feedback('Passkey added. You can use it on your next unlock.'); });
    el('change').onclick = () => run(async () => { await vault.changePassword(password(), newPassword()); feedback('Password changed. Download a new encrypted key backup.'); });
    el('recover').onclick = () => run(async () => { await vault.resetPasswordWithPasskey(newPassword()); feedback('Password reset. Download a new encrypted key backup.'); });
    el('dismiss').onclick = () => {
        if (unlocked) dialog.close();
        else if (!required) { const url = new URL(location.href); url.searchParams.delete('storage'); location.replace(url); }
    };
    dialog.addEventListener('cancel', event => { if (!unlocked || working) event.preventDefault(); });
    manage.onclick = () => {
        if (unlocked) { feedback(''); dialog.showModal(); }
        else { const url = new URL(location.href); url.searchParams.set('storage', 'encrypted'); location.assign(url); }
    };
    function fatal(error) {
        required = true;
        if (!dialog.open) dialog.showModal();
        feedback(`Cannot access local key storage: ${error.message}`, true);
        for (const button of dialog.querySelectorAll('button')) button.disabled = true;
    }
    try {
        const state = await refresh();
        if (state.required || new URL(location.href).searchParams.get('storage') === 'encrypted') {
            dialog.showModal();
            if (!Storage.supportsEncryption()) {
                feedback('This build cannot open encrypted storage. Use an encryption-enabled build to continue.', true);
                for (const button of dialog.querySelectorAll('button')) button.disabled = button !== el('dismiss');
            }
        } else resolveReady();
    } catch (error) { fatal(error); }
    await ready;
}
