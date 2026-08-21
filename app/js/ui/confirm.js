/**
 * Shared confirmation modal.
 *
 * Builds its DOM at runtime and appends it to document.body, so it works
 * identically from both esbuild bundles (ui.js and disclosure.js have
 * separate module graphs — no shared singleton state is assumed).
 *
 * @module ui/confirm
 */

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
 * @returns {Promise<boolean>} true on Confirm, false on every cancel path.
 */
export function confirmAction({ title, rows = [], confirmLabel = 'Confirm' } = {}) {
    return new Promise((resolve) => {
        const previouslyFocused = document.activeElement;

        const overlay = document.createElement('div');
        overlay.className = 'fixed inset-0 z-[60] flex items-center justify-center bg-ink-950/75 px-4 backdrop-blur-sm';

        const panel = document.createElement('div');
        panel.setAttribute('role', 'dialog');
        panel.setAttribute('aria-modal', 'true');
        panel.setAttribute('data-testid', 'confirm-dialog');
        panel.className = 'w-full max-w-md rounded-[28px] border border-white/8 bg-[linear-gradient(180deg,rgba(11,18,35,0.98),rgba(6,11,24,1))] p-6 shadow-[0_24px_100px_rgba(0,0,0,0.6)]';

        const heading = document.createElement('h2');
        heading.className = 'text-xl font-semibold tracking-tight text-white';
        heading.setAttribute('data-testid', 'confirm-dialog-title');
        heading.textContent = title;
        panel.appendChild(heading);

        if (rows.length) {
            const list = document.createElement('dl');
            list.className = 'mt-5 space-y-3 rounded-[24px] border border-white/8 bg-ink-900/80 p-5';
            rows.forEach(({ label, value }) => {
                const row = document.createElement('div');
                row.className = 'flex items-center justify-between gap-4 text-sm';
                const dt = document.createElement('dt');
                dt.className = 'shrink-0 text-slate-500';
                dt.textContent = label;
                const dd = document.createElement('dd');
                dd.className = 'break-all text-right font-mono text-slate-100';
                dd.textContent = value;
                row.append(dt, dd);
                list.appendChild(row);
            });
            panel.appendChild(list);
        }

        const actions = document.createElement('div');
        actions.className = 'mt-6 flex flex-col gap-3 sm:flex-row sm:justify-end';

        const cancelBtn = document.createElement('button');
        cancelBtn.type = 'button';
        cancelBtn.className = 'rounded-2xl border border-white/10 px-5 py-3 text-sm font-medium text-slate-300 transition hover:border-cyan-300/30 hover:text-cyan-100';
        cancelBtn.setAttribute('data-testid', 'confirm-dialog-cancel');
        cancelBtn.textContent = 'Cancel';

        const confirmBtn = document.createElement('button');
        confirmBtn.type = 'button';
        confirmBtn.className = 'rounded-2xl bg-[linear-gradient(135deg,#74c5ff,#2f6dff)] px-5 py-3 text-sm font-semibold text-ink-950 shadow-[0_12px_30px_rgba(63,138,255,0.45)] transition hover:brightness-110';
        confirmBtn.setAttribute('data-testid', 'confirm-dialog-confirm');
        confirmBtn.textContent = confirmLabel;

        actions.append(cancelBtn, confirmBtn);
        panel.appendChild(actions);
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
