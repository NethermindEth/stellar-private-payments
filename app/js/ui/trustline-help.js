// How to add a classic asset's trustline in the wallet, shown when a deposit
// is refused because the paying account has none.

import { Utils } from './core.js';
import { el, elc } from './dom.js';
import { openModal } from './toast.js';

/**
 * Tells the user how to add the trustline for `label` in their wallet, with
 * the token's address to paste there. Resolves when the dialog closes.
 */
export function showTrustlineHelp({ label, tokenContractId }) {
    return new Promise((resolve) => {
        const title = `Add ${label} to your wallet first`;
        const dialog = el('dialog', 'modal open:grid place-items-center px-4 backdrop:bg-ink-950/75');
        dialog.ariaLabel = title;

        const panel = el('div', 'modal-panel w-full max-w-md');
        panel.setAttribute('data-testid', 'trustline-help');

        const address = el('code', 'min-w-0 break-all font-mono text-sm text-slate-100', tokenContractId);
        address.setAttribute('data-testid', 'trustline-help-address');

        const copy = Object.assign(el('button', 'btn-secondary shrink-0 px-3 py-1.5 text-xs', 'Copy'), { type: 'button' });
        copy.setAttribute('data-testid', 'trustline-help-copy');
        copy.addEventListener('click', () => Utils.copyToClipboard(tokenContractId));

        const done = Object.assign(el('button', 'btn-primary', 'Done'), { type: 'button' });
        done.setAttribute('data-testid', 'trustline-help-done');

        panel.append(
            el('h2', 'text-xl font-semibold tracking-tight text-white', title),
            el('p', 'mt-3 text-sm leading-relaxed text-slate-200',
                `The account you deposit from has no trustline for ${label}, so it can't hold or send it yet. Add one in your wallet:`),
            elc('ol', 'mt-4 list-decimal space-y-2 pl-5 text-sm leading-relaxed text-slate-200', [
                el('li', '', 'Open your wallet and choose Add token.'),
                el('li', '', 'Paste the token address below into the search field.'),
                el('li', '', `Choose Add next to ${label}, then confirm the transaction that adds the trustline.`),
            ]),
            elc('div', 'panel mt-5 bg-ink-900/80', [
                el('p', 'text-sm text-slate-400', `${label} token address`),
                elc('div', 'mt-2 flex items-center justify-between gap-4', [address, copy]),
            ]),
            el('p', 'mt-4 text-sm leading-relaxed text-slate-400',
                `Once ${label} shows in your wallet and the account holds enough of it, deposit again.`),
            elc('div', 'mt-6 flex justify-end', [done]),
        );
        dialog.appendChild(panel);

        const close = () => {
            if (dialog.open) dialog.close();
        };
        done.addEventListener('click', close);
        dialog.addEventListener('click', (event) => {
            if (event.target === dialog) close();
        });
        // Escape closes the dialog without a `click`, so settle on `close`.
        dialog.addEventListener('close', () => {
            dialog.remove();
            resolve();
        });

        openModal(dialog);
        done.focus();
    });
}
