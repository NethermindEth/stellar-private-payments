// One toast implementation for both pages.
import { friendlyErrorMessage } from '../facade-errors.js';
import { el, elc } from './dom.js';

// Older toasts give way so the stack covers less of the page.
const MAX_TOASTS = 3;

let container;

// Everything outside the topmost modal dialog is inert, so toasts follow it.
function place() {
    const dialog = [...document.querySelectorAll('dialog:modal')].at(-1);
    const parent = dialog ?? document.body;
    // A move blurs a focused toast button.
    if (container.parentElement !== parent) parent.append(container);
    dialog?.addEventListener('close', place, { once: true });
}

// Last in <body> is then last opened, the order the browser stacks modal dialogs in.
export function openModal(dialog) {
    document.body.append(dialog);
    dialog.showModal();
    if (container) place();
}

// A countdown that holds while the pointer or focus is on the toast.
function timer(toast, duration, onExpire) {
    let remaining = duration;
    let startedAt = 0;
    let handle = null;
    const held = new Set();
    const run = () => {
        if (handle || held.size) return;
        startedAt = Date.now();
        handle = setTimeout(onExpire, remaining);
    };
    const hold = (reason) => {
        held.add(reason);
        if (!handle) return;
        clearTimeout(handle);
        handle = null;
        remaining = Math.max(0, remaining - (Date.now() - startedAt));
    };
    const release = (reason) => {
        held.delete(reason);
        run();
    };
    toast.addEventListener('mouseenter', () => hold('pointer'));
    toast.addEventListener('mouseleave', () => release('pointer'));
    toast.addEventListener('focusin', () => hold('focus'));
    toast.addEventListener('focusout', (event) => {
        if (!toast.contains(event.relatedTarget)) release('focus');
    });
    return {
        restart() {
            clearTimeout(handle);
            handle = null;
            remaining = duration;
            run();
        },
        stop() {
            clearTimeout(handle);
            handle = null;
        },
    };
}

function copyButton(details) {
    const button = Object.assign(el('button', 'text-slate-400 underline underline-offset-4 transition hover:text-slate-200', 'Copy details'), { type: 'button' });
    button.addEventListener('click', async () => {
        try {
            await navigator.clipboard.writeText(details);
            button.textContent = 'Copied';
        } catch {
            button.textContent = 'Copy failed';
        }
    });
    return button;
}

function dismiss(toast) {
    if (toast.dataset.state !== 'visible') return;
    toast.dataset.state = 'dismissing';
    toast.toastTimer?.stop();
    setTimeout(() => toast.remove(), 200);
}

// Options: `details` adds a Copy details button for the raw error text;
// `linkUrl` adds a link, labelled `linkText` (an explorer link by default).
export function showToast(message, type = 'success', duration = 4000, { origin, transactionHash, linkUrl, linkText, details } = {}) {
    const text = String(friendlyErrorMessage(message) ?? '');
    // Cached: a dialog removed right after close() holds it until its close event.
    container ??= document.getElementById('toast-container');
    place();

    // The same message again restarts the visible toast instead of stacking a copy.
    const visible = [...container.children].filter((toast) => toast.dataset.state === 'visible');
    const repeat = !transactionHash && visible.find((toast) =>
        toast.dataset.status === type &&
        (toast.dataset.toastOrigin ?? '') === (origin ?? '') &&
        !toast.dataset.transactionHash &&
        toast.querySelector('[data-testid="toast-message"]')?.textContent === text);
    if (repeat) {
        container.append(repeat);
        repeat.toastTimer.restart();
        return;
    }

    const body = Object.assign(el('p', 'break-words', text), { title: text });
    body.dataset.testid = 'toast-message';
    const link = linkUrl && Object.assign(el('a', 'text-cyan-100 underline underline-offset-4', linkText || 'Open explorer'), {
        href: linkUrl,
        target: '_blank',
        rel: 'noreferrer',
        ariaLabel: linkText || 'Open transaction in explorer',
    });
    const close = Object.assign(el('button', 'text-slate-400 underline underline-offset-4 transition hover:text-slate-200', 'Dismiss'), { type: 'button' });
    const actions = [link, details && copyButton(details), close];
    const toast = elc('div', 'toast', [elc('div', 'min-w-0 flex-1', [body, elc('div', 'mt-2 flex gap-4 text-xs font-medium', actions)])]);
    Object.assign(toast.dataset, { testid: 'toast', status: type, state: 'visible' });
    // Errors interrupt; the rest wait their turn in the container's polite live region.
    if (type === 'error') toast.setAttribute('role', 'alert');
    if (origin) toast.dataset.toastOrigin = origin;
    if (transactionHash) toast.dataset.transactionHash = transactionHash;
    if (transactionHash && link) toast.dataset.keep = 'true';
    close.addEventListener('click', () => dismiss(toast));
    toast.toastTimer = timer(toast, duration, () => dismiss(toast));
    container.append(toast);
    toast.toastTimer.restart();
    // A submitted transaction's toast holds its only explorer link, so it stays.
    const evictable = visible.filter((old) => !old.dataset.keep);
    evictable.slice(0, Math.max(0, visible.length + 1 - MAX_TOASTS)).forEach(dismiss);
}
