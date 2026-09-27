import { FreighterSigner } from 'stellar-private-payments/freighter';
import { enrollFreighter } from './storage-freighter.js';
import { enrollPasskey } from './storage-passkey.js';
import { passwordField } from './storage-access.js';
import { withStorageActivity } from './storage-activity.js';

/** Manage one optional envelope per method, always authenticating the password. */
export async function mountStorageMethods(container, storage) {
    container.replaceChildren();
    const password = passwordField({ label: 'Current password', autocomplete: 'current-password', testid: 'storage-method-password' });
    const message = document.createElement('p');
    message.className = 'text-sm text-slate-300';
    message.setAttribute('role', 'status');
    message.dataset.testid = 'storage-method-message';
    const methods = document.createElement('div');
    methods.className = 'space-y-4';
    container.append(password.field, methods, message);
    const render = async () => {
        const [wallet, passkey] = await Promise.all([storage.walletContext(), storage.passkeyContext()]);
        methods.replaceChildren();
        for (const [name, context, enroll, remove] of [
            ['Freighter', wallet, () => enrollFreighter(storage, password.input.value, new FreighterSigner()), () => storage.removeWallet(password.input.value)],
            ['Passkey', passkey, () => enrollPasskey(storage, password.input.value), () => storage.removePasskey(password.input.value)],
        ]) {
            const row = document.createElement('div');
            const status = document.createElement('p');
            status.className = 'break-all text-sm text-slate-300';
            status.dataset.testid = `storage-method-${name.toLowerCase()}-status`;
            status.textContent = context
                ? `${name}: enabled — ${name === 'Freighter' ? context.address : `${context.rpId} (${context.credentialId.slice(0, 12)}…)`}`
                : `${name}: not enabled`;
            row.appendChild(status);
            for (const [action, operation] of [[context ? 'Replace' : 'Enable', enroll], ...(context ? [['Remove', remove]] : [])]) {
                const button = document.createElement('button');
                button.type = 'button';
                button.className = 'mr-3 mt-2 rounded-2xl border border-white/10 px-4 py-2 text-sm text-slate-200 disabled:opacity-50';
                button.textContent = `${action} ${name}`;
                button.dataset.testid = `storage-method-${name.toLowerCase()}-${action.toLowerCase()}`;
                button.addEventListener('click', async () => {
                    if (button.disabled) return;
                    if (!password.input.value) {
                        message.textContent = 'Enter your current password to change an unlock method.';
                        password.input.focus();
                        return;
                    }
                    for (const control of container.querySelectorAll('input, button')) control.disabled = true;
                    message.textContent = 'Confirm the request to continue…';
                    try {
                        await withStorageActivity(async () => { await operation(); await render(); });
                        message.textContent = action === 'Remove'
                            ? `${name} access removed from this database. Your password still works.`
                            : `${name} access saved. Your password still works.`;
                    } catch (error) {
                        message.textContent = error?.message || 'Could not change the unlock method.';
                    } finally {
                        password.input.value = '';
                        for (const control of container.querySelectorAll('input, button')) control.disabled = false;
                    }
                });
                row.appendChild(button);
            }
            methods.appendChild(row);
        }
    };
    try { await render(); }
    catch (error) { message.textContent = error?.message || 'Could not read unlock methods.'; }
}
