/** Confirm the public account used to unlock local data before requesting signatures. */
export function confirmStorageAccount({ address, fresh, watchAccount }) {
    return new Promise((resolve, reject) => {
        let selectedAddress = address;
        let closed = false;
        let stopWatching;
        const dialog = document.createElement('dialog');
        dialog.className = 'm-auto w-full max-w-lg rounded-[28px] border border-white/10 bg-ink-950 p-8 text-white backdrop:bg-ink-950/90';
        const title = document.createElement('h2');
        title.id = 'storage-account-title';
        title.className = 'text-xl font-semibold';
        title.textContent = fresh ? 'Choose your unlocking account' : 'Unlock local storage';
        const description = document.createElement('p');
        description.id = 'storage-account-description';
        description.className = 'mt-4 text-sm text-slate-300';
        description.textContent = fresh
            ? 'Select the account in Freighter that you want to use to unlock local storage. You’ll need this account whenever you unlock. The selected account updates automatically when you switch accounts.'
            : 'Unlock local storage using this account in Freighter. This is the account you chose when setting up local storage.';
        const label = document.createElement('p');
        label.className = 'mt-5 text-sm text-slate-400';
        label.textContent = fresh ? 'Selected account' : 'Unlocking account';
        const account = document.createElement('p');
        account.className = 'mt-2 break-all font-mono text-sm';
        account.textContent = address;
        account.setAttribute('aria-live', 'polite');
        const actions = document.createElement('div');
        actions.className = 'mt-6 flex justify-end gap-3';
        const cancel = document.createElement('button');
        cancel.type = 'button';
        cancel.className = 'rounded-xl border border-white/10 px-5 py-3';
        cancel.textContent = 'Cancel';
        const proceed = document.createElement('button');
        proceed.type = 'button';
        proceed.dataset.testid = 'storage-account-continue';
        proceed.className = 'rounded-xl bg-cyan-900 px-5 py-3 text-white';
        proceed.textContent = fresh ? 'Continue' : 'Unlock with Freighter';
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
