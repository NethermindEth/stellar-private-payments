// Handling for the "local database holds two different sets of privacy keys
// for one account" condition -- migration 2's ambiguous-keypairs refusal.
// Distinct from db-migration-failed.js: reloading does not resolve this (the
// ambiguity is still there afterwards), so this modal offers an exportable,
// non-destructive diagnostic instead of a reload button.

export const AMBIGUOUS_KEYPAIRS_CODE = 'ambiguous-keypairs';

export function isAmbiguousKeypairsError(message) {
    return typeof message === 'string' && message.includes(AMBIGUOUS_KEYPAIRS_CODE);
}

let shown = false;

/**
 * Show a blocking, top-most modal carrying the backend-provided message and
 * an "Export diagnostic" action.
 *
 * `diagnose` is injected (rather than importing wasm-facade.js directly) so
 * this module stays loadable, and its wiring testable, under plain
 * `node --test` -- wasm-facade.js imports the wasm package and cannot be.
 *
 * @param {string} message
 * @param {{ accountAddress: string, diagnose: (accountAddress: string) => Promise<unknown> }} options
 */
export function showAmbiguousKeypairsModal(message, { accountAddress, diagnose }) {
    if (shown || typeof document === 'undefined') return;
    shown = true;

    const overlay = document.createElement('div');
    overlay.className = 'fixed inset-0 z-[80] flex items-center justify-center bg-ink-950/90 px-4 backdrop-blur-sm';

    const card = document.createElement('div');
    card.className = 'mx-auto max-w-lg rounded-[28px] border border-white/8 bg-[linear-gradient(180deg,rgba(11,18,35,0.98),rgba(6,11,24,1))] p-8 text-center shadow-[0_24px_100px_rgba(0,0,0,0.6)]';

    const eyebrow = document.createElement('p');
    eyebrow.className = 'text-[11px] font-semibold uppercase tracking-[0.34em] text-amber-200/80';
    eyebrow.textContent = 'Local database';

    const title = document.createElement('h2');
    title.className = 'mt-3 text-xl font-semibold tracking-tight text-white';
    title.textContent = 'Two key sets found for this account';

    const msg = document.createElement('p');
    msg.className = 'mt-4 text-sm leading-6 text-slate-300 text-left';
    msg.textContent = String(message ?? '');

    const exportBtn = document.createElement('button');
    exportBtn.type = 'button';
    exportBtn.className = 'mt-6 inline-flex w-full items-center justify-center rounded-2xl bg-[linear-gradient(135deg,#74c5ff,#2f6dff)] px-5 py-3 text-sm font-semibold text-ink-950 shadow-[0_12px_30px_rgba(63,138,255,0.45)] transition hover:brightness-110';
    exportBtn.textContent = 'Export diagnostic for support';

    const status = document.createElement('p');
    status.className = 'mt-3 text-xs text-slate-400';

    const output = document.createElement('textarea');
    output.readOnly = true;
    output.className = 'mt-3 hidden h-40 w-full rounded-xl border border-white/10 bg-black/30 p-3 text-left font-mono text-xs text-slate-200';

    const copyBtn = document.createElement('button');
    copyBtn.type = 'button';
    copyBtn.className = 'mt-3 hidden inline-flex w-full items-center justify-center rounded-2xl border border-white/15 px-5 py-2.5 text-sm font-medium text-slate-200 transition hover:bg-white/5';
    copyBtn.textContent = 'Copy to clipboard';

    exportBtn.addEventListener('click', async () => {
        exportBtn.disabled = true;
        status.textContent = 'Building diagnostic…';
        try {
            const diagnostic = await diagnose(accountAddress);
            output.value = JSON.stringify(diagnostic, null, 2);
            output.classList.remove('hidden');
            copyBtn.classList.remove('hidden');
            status.textContent = 'Contains no private keys -- safe to share with support.';
        } catch (e) {
            status.textContent = `Could not build the diagnostic: ${e?.message || e}`;
            exportBtn.disabled = false;
        }
    });

    copyBtn.addEventListener('click', () => {
        navigator.clipboard?.writeText(output.value).then(
            () => { status.textContent = 'Copied.'; },
            () => { status.textContent = 'Could not copy -- select the text above manually.'; },
        );
    });

    card.append(eyebrow, title, msg, exportBtn, status, output, copyBtn);
    overlay.appendChild(card);
    document.body.appendChild(overlay);
}
