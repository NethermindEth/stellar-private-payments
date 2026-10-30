// Shared confirmation dialog for both pages.

import { el, elc } from './dom.js';
import { openModal } from './toast.js';

/**
 * Show a confirmation dialog and wait for the user's choice.
 *
 * Dismiss paths: Confirm button resolves true; Cancel button, outside click,
 * and Escape all resolve false. The promise settles exactly once. On open, focus
 * lands on the Cancel button (safe default for financial confirmations: a
 * follow-up Enter cancels rather than confirms). Confirm is reachable via Tab
 * or click.
 */
export function confirmAction({ title = '', message = '', rows = [], confirmLabel = 'Confirm', warning = '', danger = false } = {}) {
    return new Promise((resolve) => {
        const dialog = el('dialog', 'modal open:grid place-items-center px-4 backdrop:bg-ink-950/75');
        dialog.ariaLabel = title || message;

        const panel = el('div', 'modal-panel w-full max-w-md');
        panel.setAttribute('data-testid', 'confirm-dialog');

        if (title) {
            const heading = el('h2', 'text-xl font-semibold tracking-tight text-white', title);
            heading.setAttribute('data-testid', 'confirm-dialog-title');
            panel.appendChild(heading);
        }
        if (message) panel.appendChild(el('p', 'text-sm leading-relaxed text-slate-200 [overflow-wrap:anywhere]', message));

        if (rows.length) {
            panel.appendChild(elc('dl', 'panel mt-5 space-y-3 bg-ink-900/80', rows.map(({ label, value }) => elc('div', 'flex items-center justify-between gap-4 text-sm', [
                el('dt', 'shrink-0 text-slate-400', label),
                el('dd', 'break-all text-right font-mono text-slate-100', value),
            ]))));
        }

        if (warning) {
            const note = el('p', 'mt-4 rounded-2xl border border-amber-300/20 bg-amber-300/5 p-4 text-sm text-amber-200', warning);
            note.setAttribute('role', 'alert');
            note.setAttribute('data-testid', 'confirm-dialog-warning');
            panel.appendChild(note);
        }

        const cancelBtn = el('button', 'btn-secondary', 'Cancel');
        cancelBtn.type = 'button';
        cancelBtn.setAttribute('data-testid', 'confirm-dialog-cancel');

        const confirmBtn = el('button', danger ? 'btn-danger' : 'btn-primary', confirmLabel);
        confirmBtn.type = 'button';
        confirmBtn.setAttribute('data-testid', 'confirm-dialog-confirm');

        panel.appendChild(elc('div', 'mt-6 flex flex-col gap-3 sm:flex-row sm:justify-end', [cancelBtn, confirmBtn]));
        dialog.appendChild(panel);

        let settled = false;
        const settle = (result) => {
            if (settled) return;
            settled = true;
            dialog.close();
            dialog.remove();
            resolve(result);
        };

        confirmBtn.addEventListener('click', () => settle(true));
        cancelBtn.addEventListener('click', () => settle(false));
        dialog.addEventListener('cancel', () => settle(false));
        dialog.addEventListener('click', (event) => {
            if (event.target === dialog) settle(false);
        });

        openModal(dialog);
        cancelBtn.focus();
    });
}
