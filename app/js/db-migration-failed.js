// Shared handling for the "local database could not be opened" condition
// (a failed schema migration or corrupt/locked-out database file). Distinct
// from db-locked.js's "another tab has it open" case.
//
// The Rust storage worker keeps its user-facing message short and free of the
// SQL it may have failed on (see MigrationFailedError/AmbiguousKeypairsError
// in sdk/native/src/state/storage.rs) and stamps it with a stable code
// instead, so this module can recognise the condition without matching
// against text that varies with the underlying SQLite failure.

export const DB_MIGRATION_FAILED_CODE = 'db-migration-failed';

export function isDbMigrationFailedError(message) {
    return typeof message === 'string' && message.includes(DB_MIGRATION_FAILED_CODE);
}

let shown = false;

// Show a blocking, top-most modal carrying the backend-provided message and a
// reload button. Injected into the DOM so every page behaves identically without
// per-page markup. Idempotent: only the first call renders.
export function showDbMigrationFailedModal(message) {
    if (shown || typeof document === 'undefined') return;
    shown = true;

    const overlay = document.createElement('div');
    overlay.className = 'fixed inset-0 z-[80] flex items-center justify-center bg-ink-950/90 px-4 backdrop-blur-sm';

    const card = document.createElement('div');
    card.className = 'mx-auto max-w-md rounded-[28px] border border-white/8 bg-[linear-gradient(180deg,rgba(11,18,35,0.98),rgba(6,11,24,1))] p-8 text-center shadow-[0_24px_100px_rgba(0,0,0,0.6)]';

    const eyebrow = document.createElement('p');
    eyebrow.className = 'text-[11px] font-semibold uppercase tracking-[0.34em] text-amber-200/80';
    eyebrow.textContent = 'Local database';

    const title = document.createElement('h2');
    title.className = 'mt-3 text-xl font-semibold tracking-tight text-white';
    title.textContent = "Couldn't open your wallet database";

    const msg = document.createElement('p');
    msg.className = 'mt-4 text-sm leading-6 text-slate-300';
    msg.textContent = String(message ?? '');

    const btn = document.createElement('button');
    btn.type = 'button';
    btn.className = 'mt-6 inline-flex w-full items-center justify-center rounded-2xl bg-[linear-gradient(135deg,#74c5ff,#2f6dff)] px-5 py-3 text-sm font-semibold text-ink-950 shadow-[0_12px_30px_rgba(63,138,255,0.45)] transition hover:brightness-110';
    btn.textContent = 'Reload this page';
    btn.addEventListener('click', () => window.location.reload());

    card.append(eyebrow, title, msg, btn);
    overlay.appendChild(card);
    document.body.appendChild(overlay);
}
