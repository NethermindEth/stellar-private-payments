// Shared handling for the "local database is locked by another tab/window"
// condition. The message text is produced by the Rust storage worker and
// surfaced verbatim — this module only detects it and renders a blocking modal.

import { el, elc } from './ui/dom.js';

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

    const btn = el('button', 'btn-primary mt-6 w-full', 'Reload this page');
    btn.type = 'button';
    btn.addEventListener('click', () => window.location.reload());

    document.body.appendChild(elc('div', 'fixed inset-0 z-[80] flex items-center justify-center bg-ink-950/90 px-4 backdrop-blur-sm', [
        elc('div', 'mx-auto max-w-md rounded-[28px] border border-white/8 bg-[linear-gradient(180deg,rgba(11,18,35,0.98),rgba(6,11,24,1))] p-8 text-center shadow-[0_24px_100px_rgba(0,0,0,0.6)]', [
            el('p', 'eyebrow text-amber-200/80', 'App already open'),
            el('h2', 'mt-3 text-xl font-semibold tracking-tight text-white', 'Another tab is using this app'),
            el('p', 'mt-4 text-sm leading-6 text-slate-300', message),
            btn,
        ]),
    ]));
}
