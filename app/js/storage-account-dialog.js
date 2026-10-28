import { el } from './ui/dom.js';

/** Confirm the public account used to unlock local data before requesting signatures. */
export function confirmStorageAccount({ address, fresh, watchAccount }) {
    return new Promise((resolve, reject) => {
        let selectedAddress = address;
        let closed = false;
        let stopWatching;
        const dialog = el('dialog', 'modal-panel m-auto w-full max-w-lg p-8 text-white backdrop:bg-ink-950/90');
        const title = el('h2', 'text-xl font-semibold', fresh ? 'Choose your unlocking account' : 'Unlock local storage');
        title.id = 'storage-account-title';
        const description = el('p', 'mt-4 text-sm text-slate-300', fresh
            ? 'Select the account in Freighter that you want to use to unlock local storage. You’ll need this account whenever you unlock. The selected account updates automatically when you switch accounts.'
            : 'Unlock local storage using this account in Freighter. This is the account you chose when setting up local storage.');
        description.id = 'storage-account-description';
        const label = el('p', 'mt-5 text-sm text-slate-400', fresh ? 'Selected account' : 'Unlocking account');
        const account = el('p', 'mt-2 break-all font-mono text-sm', address);
        account.setAttribute('aria-live', 'polite');
        const actions = el('div', 'mt-6 flex justify-end gap-3');
        const cancel = el('button', 'btn-secondary', 'Cancel');
        cancel.type = 'button';
        const proceed = el('button', 'btn-primary', fresh ? 'Continue' : 'Unlock with Freighter');
        proceed.type = 'button';
        proceed.dataset.testid = 'storage-account-continue';
        const finish = accepted => {
            if (closed) return;
            closed = true;
            stopWatching?.();
            dialog.close();
            dialog.remove();
            if (accepted) resolve(selectedAddress);
            else reject(Object.assign(new Error('Storage unlock cancelled.'), { code: 'unlock-cancelled' }));
        };
        cancel.addEventListener('click', () => finish(false));
        proceed.addEventListener('click', () => finish(true));
        dialog.addEventListener('cancel', event => { event.preventDefault(); finish(false); });
        dialog.setAttribute('aria-labelledby', title.id);
        dialog.setAttribute('aria-describedby', description.id);
        actions.append(cancel, proceed);
        dialog.append(title, description, label, account, actions);
        document.body.append(dialog);
        dialog.showModal();
        if (fresh && watchAccount) {
            try {
                stopWatching = watchAccount({ intervalMs: 500, onChange: ({ address: next }) => {
                    if (closed) return;
                    selectedAddress = typeof next === 'string' ? next : '';
                    account.textContent = selectedAddress || 'Select an account in Freighter and allow this app to access it.';
                    proceed.disabled = !selectedAddress;
                } });
            } catch (error) {
                closed = true;
                dialog.close();
                dialog.remove();
                reject(error);
            }
        }
    });
}
