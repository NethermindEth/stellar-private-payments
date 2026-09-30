/** Password dialog for local encrypted storage. Never persists the password. */
export function requestStoragePassword({ creating, error = '' } = {}) {
    return new Promise((resolve, reject) => {
        const previousFocus = document.activeElement;
        const dialog = document.createElement('dialog');
        dialog.dataset.testid = 'storage-password-dialog';
        dialog.className = 'm-auto w-full max-w-md rounded-[28px] border border-white/10 bg-ink-950 p-6 text-white shadow-2xl backdrop:bg-ink-950/80';
        dialog.setAttribute('aria-labelledby', 'storage-password-title');
        const form = document.createElement('form');
        const title = document.createElement('h2');
        title.id = 'storage-password-title';
        title.className = 'text-xl font-semibold';
        title.textContent = creating ? 'Create storage password' : 'Unlock local storage';
        const description = document.createElement('p');
        description.className = 'mt-3 text-sm text-slate-300';
        description.textContent = creating
            ? 'Choose a password for your encrypted local data. You will need it when reopening this app. This password cannot be recovered.'
            : 'Enter your storage password to unlock your encrypted local data.';
        const field = (labelText, testid, autocomplete) => {
            const label = document.createElement('label');
            label.className = 'mt-4 block text-sm text-slate-200';
            label.textContent = labelText;
            const input = document.createElement('input');
            input.type = 'password';
            input.required = true;
            input.autocomplete = autocomplete;
            input.dataset.testid = testid;
            input.className = 'mt-2 block w-full rounded-xl border border-white/15 bg-ink-900 p-3 text-white';
            label.appendChild(input);
            return { label, input };
        };
        const password = field('Storage password', 'storage-password', creating ? 'new-password' : 'current-password');
        const confirmation = creating ? field('Confirm storage password', 'storage-password-confirm', 'new-password') : null;
        const alert = document.createElement('p');
        alert.setAttribute('role', 'alert');
        alert.className = 'mt-3 text-sm text-red-300';
        alert.textContent = error;
        const actions = document.createElement('div');
        actions.className = 'mt-6 flex justify-end gap-3';
        const cancel = document.createElement('button');
        cancel.type = 'button';
        cancel.textContent = 'Cancel';
        cancel.className = 'rounded-xl border border-white/15 px-4 py-2';
        const submit = document.createElement('button');
        submit.type = 'submit';
        submit.dataset.testid = 'storage-password-submit';
        submit.textContent = creating ? 'Create encrypted storage' : 'Unlock';
        submit.className = 'rounded-xl bg-cyan-300 px-4 py-2 font-semibold text-ink-950';
        actions.append(cancel, submit);
        form.append(title, description, password.label);
        if (confirmation) form.appendChild(confirmation.label);
        form.append(alert, actions);
        dialog.appendChild(form);
        let settled = false;
        const finish = (value, failure) => {
            if (settled) return;
            settled = true;
            password.input.value = '';
            if (confirmation) confirmation.input.value = '';
            dialog.close();
            dialog.remove();
            previousFocus?.focus?.();
            if (failure) reject(failure); else resolve(value);
        };
        const cancelled = () => finish(undefined, Object.assign(new Error('Storage unlocking cancelled.'), { code: 'unlock-cancelled' }));
        cancel.addEventListener('click', cancelled);
        dialog.addEventListener('cancel', event => { event.preventDefault(); cancelled(); });
        form.addEventListener('submit', event => {
            event.preventDefault();
            if (!password.input.value) return;
            if (confirmation && confirmation.input.value !== password.input.value) {
                alert.textContent = 'Storage passwords do not match.';
                confirmation.input.focus();
                return;
            }
            finish(password.input.value);
        });
        document.body.appendChild(dialog);
        dialog.showModal();
        password.input.focus();
    });
}
