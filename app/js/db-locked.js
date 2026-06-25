// Shared handling for the "local database is locked by another tab/window"
// condition. The message text is produced by the Rust storage worker and
// surfaced verbatim — this module only detects it and renders a blocking modal.

export function isDbLockedError(message) {
    return typeof message === 'string'
        && message.includes("Another tab or window is using this app's local database");
}

let shown = false;

// Show a blocking, top-most modal carrying the backend-provided message and a
// reload button. Injected into the DOM so every page behaves identically without
// per-page markup. Idempotent: only the first call renders.
export function showDbLockedModal(message) {
    if (shown || typeof document === 'undefined') return;
    shown = true;

    const overlay = document.createElement('div');
    overlay.className = 'fixed inset-0 z-[80] flex items-center justify-center bg-ink-950/90 px-4 backdrop-blur-sm';

    const card = document.createElement('div');
    card.className = 'mx-auto max-w-md rounded-[28px] border border-white/8 bg-[linear-gradient(180deg,rgba(11,18,35,0.98),rgba(6,11,24,1))] p-8 text-center shadow-[0_24px_100px_rgba(0,0,0,0.6)]';

    const eyebrow = document.createElement('p');
    eyebrow.className = 'text-[11px] font-semibold uppercase tracking-[0.34em] text-amber-200/80';
    eyebrow.textContent = 'App already open';

    const title = document.createElement('h2');
    title.className = 'mt-3 text-xl font-semibold tracking-tight text-white';
    title.textContent = 'Another tab is using this app';

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
