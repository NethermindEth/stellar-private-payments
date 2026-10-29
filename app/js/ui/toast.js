// One toast implementation for both pages.
import { friendlyErrorMessage } from '../facade-errors.js';
import { el, elc } from './dom.js';

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

export function showToast(message, type = 'success', duration = 4000, { origin, transactionHash, linkUrl } = {}) {
    const text = String(friendlyErrorMessage(message) ?? '');
    const body = Object.assign(el('p', 'break-words', text), { title: text });
    body.dataset.testid = 'toast-message';
    const link = linkUrl && Object.assign(el('a', 'text-cyan-100 underline underline-offset-4', 'Open explorer'), {
        href: linkUrl,
        target: '_blank',
        rel: 'noreferrer',
        ariaLabel: 'Open transaction in explorer',
    });
    const close = Object.assign(el('button', 'text-slate-400 underline underline-offset-4 transition hover:text-slate-200', 'Dismiss'), { type: 'button' });
    const toast = elc('div', 'toast', [elc('div', 'min-w-0 flex-1', [body, elc('div', 'mt-2 flex gap-4 text-xs font-medium', [link, close])])]);
    Object.assign(toast.dataset, { testid: 'toast', status: type, state: 'visible' });
    if (origin) toast.dataset.toastOrigin = origin;
    if (transactionHash) toast.dataset.transactionHash = transactionHash;
    const dismiss = () => {
        toast.dataset.state = 'dismissing';
        setTimeout(() => toast.remove(), 200);
    };
    close.addEventListener('click', dismiss);
    // Cached: a dialog removed right after close() holds it until its close event.
    container ??= document.getElementById('toast-container');
    place();
    container.append(toast);
    setTimeout(dismiss, duration);
}
