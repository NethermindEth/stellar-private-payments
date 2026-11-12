/**
 * Shared confirmation modal.
 *
 * Builds its DOM at runtime and appends it to document.body, so it works
 * identically from both esbuild bundles (ui.js and disclosure.js have
 * separate module graphs — no shared singleton state is assumed).
 *
 * @module ui/confirm
 */

import { el, elc } from './dom.js';

/**
 * Show a confirmation dialog and wait for the user's choice.
 *
 * Dismiss paths: Confirm button resolves true; Cancel button, overlay click,
 * and Escape all resolve false. The promise settles exactly once. On open, focus
 * lands on the Cancel button (safe default for financial confirmations: a
 * follow-up Enter cancels rather than confirms). Confirm is reachable via Tab
 * or click.
 *
 * @param {object} opts
 * @param {string} opts.title - Dialog heading.
 * @param {Array<{label: string, value: string}>} [opts.rows] - Summary lines shown above the actions.
 * @param {string} [opts.confirmLabel] - Primary button label (default 'Confirm').
 * @param {string} [opts.warning] - Caution shown below the summary; the user can still confirm.
 * @returns {Promise<boolean>} true on Confirm, false on every cancel path.
 */
export function confirmAction({ title, rows = [], confirmLabel = 'Confirm', warning = '' } = {}) {
    return new Promise((resolve) => {
        const previouslyFocused = document.activeElement;

        const overlay = el('div', 'fixed inset-0 z-[60] flex items-center justify-center bg-ink-950/75 px-4 backdrop-blur-sm');

        const panel = el('div', 'modal-panel w-full max-w-md');
        panel.setAttribute('role', 'dialog');
        panel.setAttribute('aria-modal', 'true');
        panel.setAttribute('data-testid', 'confirm-dialog');

        const heading = el('h2', 'text-xl font-semibold tracking-tight text-white', title);
        heading.setAttribute('data-testid', 'confirm-dialog-title');
        panel.appendChild(heading);

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

        const confirmBtn = el('button', 'btn-primary', confirmLabel);
        confirmBtn.type = 'button';
        confirmBtn.setAttribute('data-testid', 'confirm-dialog-confirm');

        panel.appendChild(elc('div', 'mt-6 flex flex-col gap-3 sm:flex-row sm:justify-end', [cancelBtn, confirmBtn]));
        overlay.appendChild(panel);
        document.body.appendChild(overlay);

        let settled = false;
        const settle = (result) => {
            if (settled) return;
            settled = true;
            document.removeEventListener('keydown', onKeydown, true);
            overlay.remove();
            if (previouslyFocused && typeof previouslyFocused.focus === 'function') {
                previouslyFocused.focus();
            }
            resolve(result);
        };

        // Capture phase + stopPropagation so Escape dismisses only this dialog
        // and does not fall through to page-level key handlers underneath.
        const onKeydown = (event) => {
            if (event.key !== 'Escape') return;
            event.preventDefault();
            event.stopPropagation();
            settle(false);
        };

        confirmBtn.addEventListener('click', () => settle(true));
        cancelBtn.addEventListener('click', () => settle(false));
        overlay.addEventListener('click', (event) => {
            if (event.target === overlay) settle(false);
        });
        document.addEventListener('keydown', onKeydown, true);

        cancelBtn.focus();
    });
}
