import { lastStorageActivity, storageActivityPending } from './storage-activity.js';
import { openStorage, settledStorageStatus } from './storage-open.js';
import { FreighterSigner } from 'stellar-private-payments/freighter';
import { enrollFreighter, unlockFreighter } from './storage-freighter.js';
import { enrollPasskey, unlockPasskey } from './storage-passkey.js';

// Password, optional Freighter and passkey access to the encrypted local database.
//
// The SDK keeps the database encrypted and unlocks it inside its storage
// worker; this module asks for a password or an enrolled wallet signature.
// One dialog covers the states the storage reports before use: "new" (choose a password),
// "unencrypted" (choose one to encrypt what an earlier version stored) and
// "locked" (enter it), plus resetting after a forgotten password.
//
// Locking, by hand or after inactivity, closes the storage and reloads the
// page, which then starts locked.

/** Minimum length of a new password, in characters (matches the SDK). */
export const MIN_PASSWORD_LENGTH = 15;

const AUTO_LOCK_KEY = 'spp.autoLockMinutes';
const DEFAULT_AUTO_LOCK_MINUTES = 5;
export const AUTO_LOCK_CHOICES = [5, 15, 30, 60, 0];

const COPY = {
    new: {
        title: 'Protect your private data',
        text: 'This app keeps your notes, keys and history encrypted in this browser. Choose a password to access them when needed. Public chain data and ordinary settings stay available while locked.',
        submit: 'Set password',
        busy: 'Setting up…',
    },
    unencrypted: {
        title: 'Encrypt your local data',
        text: 'An earlier version of this app stored your notes, keys and history in this browser unencrypted. Choose a password to encrypt them; you enter it once per session. Encryption cannot securely erase earlier plaintext copies or browser backups.',
        submit: 'Encrypt and continue',
        busy: 'Encrypting…',
    },
    'password-recovery-required': {
        title: 'Restore password access',
        text: 'Your enrolled method unlocked the database. Choose a new password to restore password access. Your data and enrolled methods will be preserved.',
        submit: 'Save password and continue',
        busy: 'Saving password…',
    },
    locked: {
        title: 'Unlock your private data',
        text: 'Enter your password to open your notes, keys and history in this browser.',
        submit: 'Unlock',
        busy: 'Unlocking…',
    },
};

/**
 * Ask for the password until `storage` is unlocked. Resolves once it is.
 * @param {import('stellar-private-payments').Storage} storage
 */
export async function unlockStorage(storage, { onOpened = () => {} } = {}) {
    let status = await settledStorageStatus(storage);
    while (status !== 'unlocked') {
        if (status === 'password-recovery-required') onOpened();
        const [walletContext, passkeyContext] = ['locked', 'recovery-required'].includes(status)
            ? await Promise.all([
                storage.walletContext().catch(() => null),
                storage.passkeyContext().catch(() => null),
            ]) : [null, null];
        status = await showPasswordDialog(storage, status, walletContext, passkeyContext, onOpened);
    }
    onOpened();
}

/**
 * The dialog for one storage status. Resolves with the status after the
 * user's action: "unlocked", or "new" after a reset.
 */
function showPasswordDialog(storage, status, walletContext, passkeyContext, onOpened) {
    return new Promise((resolve, reject) => {
        const overlay = el('div', 'fixed inset-0 z-[70] flex items-center justify-center overflow-y-auto bg-ink-950/90 px-4 py-8 backdrop-blur-sm');
        overlay.setAttribute('role', 'dialog');
        overlay.setAttribute('aria-modal', 'true');
        overlay.setAttribute('aria-labelledby', 'storage-password-title');
        overlay.dataset.testid = 'storage-password-dialog';
        overlay.dataset.mode = status;
        const card = el('div', 'w-full max-w-md rounded-[28px] border border-white/8 bg-[linear-gradient(180deg,rgba(11,18,35,0.98),rgba(6,11,24,1))] p-8 shadow-[0_24px_100px_rgba(0,0,0,0.6)]');
        overlay.appendChild(card);
        document.body.appendChild(overlay);

        const cancel = el('button', 'absolute right-5 top-5 rounded-xl px-4 py-2 text-sm text-slate-300 hover:text-white', 'Continue with public data');
        cancel.type = 'button';
        cancel.dataset.testid = 'storage-password-cancel';
        overlay.appendChild(cancel);
        cancel.addEventListener('click', () => {
            // Never abandon an in-flight create/unlock or wallet prompt.
            if (card.querySelector('button:disabled')) return;
            overlay.remove();
            // An enrollment offer means the vault has already opened.
            if (card.querySelector('[data-testid="storage-freighter-skip"], [data-testid="storage-passkey-skip"]')) {
                resolve('unlocked');
            } else {
                reject(Object.assign(new Error('Private data remains locked.'), { code: 'unlock-cancelled' }));
            }
        });
        const finish = (next) => {
            overlay.remove();
            resolve(next);
        };
        if (status === 'recovery-required') renderRecovery(card, storage, finish, walletContext, passkeyContext, onOpened);
        else renderPasswordForm(card, storage, status, finish, walletContext, passkeyContext, null, onOpened);
    });
}

function renderPasswordForm(card, storage, status, finish, walletContext, passkeyContext, initialError = null, onOpened = () => {}) {
    const copy = COPY[status];
    if (!copy) throw new Error(`unexpected storage status: ${status}`);
    const recovering = status === 'password-recovery-required';
    const creating = status !== 'locked';
    card.replaceChildren();

    const title = heading(copy.title);
    const text = el('p', 'mt-3 text-sm leading-6 text-slate-300', copy.text);
    const form = el('form', 'mt-6 space-y-4');
    form.noValidate = true;

    // Lets password managers file the password under a recognisable name.
    const username = document.createElement('input');
    username.type = 'text';
    username.autocomplete = 'username';
    username.value = 'Stellar Private Payments local data';
    username.hidden = true;
    username.tabIndex = -1;
    form.appendChild(username);

    const password = passwordField({
        label: 'Password',
        autocomplete: creating ? 'new-password' : 'current-password',
        testid: 'storage-password-input',
    });
    form.appendChild(password.field);
    let confirm = null;
    let autoLock = null;
    if (creating) {
        confirm = passwordField({
            label: 'Confirm password',
            autocomplete: 'new-password',
            testid: 'storage-password-confirm',
        });
        form.appendChild(confirm.field);
        form.appendChild(el('p', 'text-xs leading-5 text-slate-400',
            `At least ${MIN_PASSWORD_LENGTH} characters. A passphrase of four or more random words works well.`));

    }
    if (creating && !recovering) {
        const field = el('div');
        const label = el('label', 'text-xs font-medium uppercase tracking-[0.22em] text-slate-500', 'Lock after inactivity');
        label.htmlFor = 'storage-auto-lock';
        autoLock = el('select', 'mt-2 w-full rounded-2xl border border-white/10 bg-ink-950 px-4 py-3 text-sm text-slate-100 outline-none transition focus:border-cyan-300/40');
        autoLock.id = 'storage-auto-lock';
        autoLock.dataset.testid = 'storage-auto-lock';
        for (const minutes of AUTO_LOCK_CHOICES) {
            const option = el('option', null, minutes === 0 ? 'Never' : `${minutes} minutes`);
            option.value = String(minutes);
            autoLock.appendChild(option);
        }
        autoLock.value = String(DEFAULT_AUTO_LOCK_MINUTES);
        field.append(label, autoLock, el('p', 'mt-2 text-xs leading-5 text-slate-400',
            'Automatically lock your local data when you stop using the app. You can change this later in Settings.'));
        form.appendChild(field);
    }

    const error = el('p', 'hidden rounded-2xl border border-rose-400/25 bg-rose-400/10 px-4 py-3 text-sm text-rose-100');
    error.setAttribute('role', 'alert');
    error.dataset.testid = 'storage-password-error';
    form.appendChild(error);

    const submit = el('button', 'inline-flex w-full items-center justify-center rounded-2xl bg-[linear-gradient(135deg,#74c5ff,#2f6dff)] px-5 py-3 text-sm font-semibold text-ink-950 shadow-[0_12px_30px_rgba(63,138,255,0.45)] transition hover:brightness-110 disabled:cursor-wait disabled:opacity-70', copy.submit);
    submit.type = 'submit';
    submit.dataset.testid = 'storage-password-submit';
    form.appendChild(submit);

    const showError = (message) => {
        error.textContent = message;
        error.classList.remove('hidden');
    };

    form.addEventListener('submit', async (event) => {
        event.preventDefault();
        if (submit.disabled) return;
        error.classList.add('hidden');
        let value = password.input.value;
        if (creating) {
            if ([...value].length < MIN_PASSWORD_LENGTH) {
                showError(`Use a password of at least ${MIN_PASSWORD_LENGTH} characters.`);
                password.input.focus();
                return;
            }
            if (confirm.input.value !== value) {
                showError("Passwords don't match.");
                confirm.input.focus();
                return;
            }
        } else if (!value) {
            showError('Enter your password.');
            password.input.focus();
            return;
        }
        setBusy(true);
        submit.textContent = copy.busy;
        try {
            if (recovering) {
                try { await storage.recoverPassword(value); }
                catch (error) {
                    if (await settledStorageStatus(storage) !== 'unlocked') throw error;
                }
            } else if (creating) {
                await openStorage(storage, () => storage.create(value));
                setAutoLockMinutes(Number(autoLock.value));
            } else {
                await openStorage(storage, () => storage.unlock(value));
            }
            onOpened();
            password.input.value = '';
            if (confirm) confirm.input.value = '';
            if (creating && !recovering) {
                renderFreighterOffer(card, storage, value, finish);
            } else {
                finish('unlocked');
            }
        } catch (e) {
            setBusy(false);
            submit.textContent = copy.submit;
            if (e?.code === 'wrong-password') {
                showError('Wrong password. Try again.');
                password.input.value = '';
                password.input.focus();
            } else {
                const next = await settledStorageStatus(storage).catch(() => status);
                if (next === 'unlocked') { finish(next); return; }
                if (next !== status) {
                    password.input.value = '';
                    if (confirm) confirm.input.value = '';
                    if (next === 'recovery-required') renderRecovery(card, storage, finish, walletContext, passkeyContext, onOpened);
                    else renderPasswordForm(card, storage, next, finish, walletContext, passkeyContext, e?.message || String(e), onOpened);
                    return;
                }
                showError(e?.message || String(e));
            }
        } finally { value = undefined; }
    });

    const setBusy = (busy) => {
        for (const control of card.querySelectorAll('button, input, select')) control.disabled = busy;
    };
    card.append(eyebrow(), title, text, form);
    if (!creating && walletContext) {
        const wallet = actionButton('Unlock with Freighter', 'storage-freighter-unlock');
        wallet.addEventListener('click', async () => {
            if (wallet.disabled) return;
            setBusy(true);
            error.classList.add('hidden');
            wallet.textContent = 'Approve in Freighter…';
            try {
                await openStorage(storage, () => unlockFreighter(storage, new FreighterSigner()));
                finish('unlocked');
            } catch (e) {
                showError(e?.message || 'Freighter could not unlock your data. Use your password.');
                setBusy(false);
                wallet.textContent = 'Unlock with Freighter';
            }
        });
        card.appendChild(wallet);
    }
    if (!creating && passkeyContext) {
        const passkey = actionButton('Unlock with passkey', 'storage-passkey-unlock');
        passkey.addEventListener('click', async () => {
            if (passkey.disabled) return;
            setBusy(true);
            error.classList.add('hidden');
            passkey.textContent = 'Confirm your passkey…';
            try {
                await openStorage(storage, () => unlockPasskey(storage));
                finish('unlocked');
            } catch (e) {
                showError(e?.message || 'Passkey could not unlock your data. Use your password.');
                setBusy(false);
                passkey.textContent = 'Unlock with passkey';
            }
        });
        card.appendChild(passkey);
    }
    if (!creating) {
        const forgot = el('button', 'mt-4 w-full text-center text-sm text-slate-400 underline-offset-4 transition hover:text-cyan-100 hover:underline', 'Forgot password?');
        forgot.type = 'button';
        forgot.dataset.testid = 'storage-password-forgot';
        forgot.addEventListener('click', () => renderResetConfirmation(card, storage, status, finish, walletContext, passkeyContext, onOpened));
        card.appendChild(forgot);
    }
    if (initialError) showError(initialError);
    password.input.focus();
}

function actionButton(text, testid) {
    const button = el('button', 'mt-4 w-full rounded-2xl border border-white/10 px-5 py-3 text-sm font-medium text-slate-200 transition hover:border-cyan-300/30 hover:text-cyan-100 disabled:cursor-wait disabled:opacity-70', text);
    button.type = 'button';
    button.dataset.testid = testid;
    return button;
}

function renderFreighterOffer(card, storage, password, finish) {
    card.replaceChildren();
    card.parentElement.dataset.mode = 'freighter';
    const enable = actionButton('Enable Freighter unlocking', 'storage-freighter-enable');
    const skip = actionButton('Skip Freighter', 'storage-freighter-skip');
    const error = el('p', 'mt-4 hidden text-sm text-rose-100');
    error.setAttribute('role', 'alert');
    error.dataset.testid = 'storage-freighter-error';
    const done = () => {
        renderPasskeyOffer(card, storage, password, finish);
        password = undefined;
    };
    enable.addEventListener('click', async () => {
        if (enable.disabled) return;
        enable.disabled = skip.disabled = true;
        enable.textContent = 'Approve in Freighter…';
        error.classList.add('hidden');
        try {
            await enrollFreighter(storage, password, new FreighterSigner());
            done();
        } catch (e) {
            error.textContent = e?.message || 'Could not enable Freighter. Your password is already set.';
            error.classList.remove('hidden');
            enable.disabled = skip.disabled = false;
            enable.textContent = 'Try Freighter again';
        }
    });
    skip.addEventListener('click', done);
    card.append(eyebrow(), heading('Unlock with Freighter too?'),
        el('p', 'mt-3 text-sm leading-6 text-slate-300', 'Your password is set. You can also use your Freighter account to unlock this browser’s local data. Your password will still work.'),
        el('p', 'mt-3 text-sm leading-6 text-slate-400', 'Setup asks you to approve the same message twice to check that unlocking works. No transaction or fee is involved. Keep your password in case you lose access to Freighter.'),
        error, enable, skip);
    enable.focus();
}

function renderPasskeyOffer(card, storage, password, finish) {
    card.replaceChildren();
    card.parentElement.dataset.mode = 'passkey';
    const enable = actionButton('Enable passkey unlocking', 'storage-passkey-enable');
    const skip = actionButton('Continue without a passkey', 'storage-passkey-skip');
    const error = el('p', 'mt-4 hidden text-sm text-rose-100');
    error.setAttribute('role', 'alert');
    error.dataset.testid = 'storage-passkey-error';
    const done = () => { password = undefined; finish('unlocked'); };
    enable.addEventListener('click', async () => {
        if (enable.disabled) return;
        enable.disabled = skip.disabled = true;
        enable.textContent = 'Confirm your passkey…';
        error.classList.add('hidden');
        try {
            await enrollPasskey(storage, password);
            done();
        } catch (e) {
            error.textContent = e?.message || 'Could not enable a passkey. Your password still works.';
            error.classList.remove('hidden');
            enable.disabled = skip.disabled = false;
            enable.textContent = 'Try passkey again';
        }
    });
    skip.addEventListener('click', done);
    card.append(eyebrow(), heading('Unlock with a passkey too?'),
        el('p', 'mt-3 text-sm leading-6 text-slate-300', 'Use your device’s screen lock, fingerprint, or security key to unlock your local data. Your password and any enrolled Freighter account will still work.'),
        el('p', 'mt-3 text-sm leading-6 text-slate-400', 'Create a passkey, then confirm it twice to check that it can unlock encrypted storage. Some passkey providers do not support this. Keep your password as a backup.'),
        error, enable, skip);
    enable.focus();
}

function renderRecovery(card, storage, finish, walletContext, passkeyContext, onOpened) {
    card.replaceChildren();
    const error = el('p', 'mt-4 text-sm text-rose-100');
    error.setAttribute('role', 'alert');
    card.append(eyebrow(), heading('Local data needs recovery'),
        el('p', 'mt-3 text-sm leading-6 text-slate-300', 'Encrypted data exists, but its password record is missing or unavailable. Nothing has been deleted. Restore a complete backup, try an enrolled unlock method, or explicitly reset local data.'), error);
    for (const [available, label, testid, unlock] of [
        [walletContext, 'Unlock with Freighter', 'storage-freighter-unlock', () => unlockFreighter(storage, new FreighterSigner())],
        [passkeyContext, 'Unlock with passkey', 'storage-passkey-unlock', () => unlockPasskey(storage)],
    ]) {
        if (!available) continue;
        const button = actionButton(label, testid);
        button.addEventListener('click', async () => {
            for (const control of card.querySelectorAll('button')) control.disabled = true;
            try { await openStorage(storage, unlock); finish(await settledStorageStatus(storage)); }
            catch (e) {
                error.textContent = e?.message || String(e);
                for (const control of card.querySelectorAll('button')) control.disabled = false;
            }
        });
        card.appendChild(button);
    }
    const reset = actionButton('Reset local data…', 'storage-recovery-reset');
    reset.addEventListener('click', () => renderResetConfirmation(card, storage, 'recovery-required', finish, walletContext, passkeyContext, onOpened));
    card.appendChild(reset);
}

function renderResetConfirmation(card, storage, status, finish, walletContext, passkeyContext, onOpened) {
    card.replaceChildren();
    const title = heading('Reset local data?');
    const text = el('div', 'mt-3 space-y-3 text-sm leading-6 text-slate-300');
    text.append(
        el('p', null, 'Without the password, an enrolled Freighter account, or a working passkey, the encrypted data in this browser cannot be opened. Resetting deletes it: your operation history and settings here are lost.'),
        el('p', null, 'Your funds stay on-chain. After you choose a new password, connect your wallet again: your keys are derived again and your notes sync from the chain.'),
    );
    const error = el('p', 'mt-4 hidden rounded-2xl border border-rose-400/25 bg-rose-400/10 px-4 py-3 text-sm text-rose-100');
    error.setAttribute('role', 'alert');

    const reset = el('button', 'inline-flex flex-1 items-center justify-center rounded-2xl border border-rose-400/25 px-5 py-3 text-sm font-medium text-rose-100 transition hover:border-rose-400/40 hover:bg-rose-400/10 disabled:cursor-wait disabled:opacity-70', 'Delete local data');
    reset.type = 'button';
    reset.dataset.testid = 'storage-reset-confirm';
    const cancel = el('button', 'inline-flex flex-1 items-center justify-center rounded-2xl border border-white/10 px-5 py-3 text-sm font-medium text-slate-200 transition hover:border-cyan-300/30 hover:text-cyan-100', 'Cancel');
    cancel.type = 'button';
    cancel.addEventListener('click', () => {
        if (status === 'recovery-required') renderRecovery(card, storage, finish, walletContext, passkeyContext, onOpened);
        else renderPasswordForm(card, storage, status, finish, walletContext, passkeyContext, null, onOpened);
    });
    reset.addEventListener('click', async () => {
        if (reset.disabled) return;
        reset.disabled = cancel.disabled = true;
        reset.textContent = 'Deleting…';
        try {
            await storage.reset();
            finish('new');
        } catch (e) {
            reset.disabled = cancel.disabled = false;
            reset.textContent = 'Delete local data';
            error.textContent = e?.message || String(e);
            error.classList.remove('hidden');
        }
    });

    const buttons = el('div', 'mt-6 flex flex-col gap-3 sm:flex-row');
    buttons.append(cancel, reset);
    card.append(eyebrow(), title, text, error, buttons);
    cancel.focus();
}

/**
 * A labelled password input with a button that shows or hides the password.
 * @returns {{ field: HTMLElement, input: HTMLInputElement }}
 */
export function passwordField({ label, autocomplete, testid, id }) {
    const inputId = id || `password-${Math.random().toString(36).slice(2)}`;
    const field = el('div');
    const labelEl = el('label', 'text-xs font-medium uppercase tracking-[0.22em] text-slate-500', label);
    labelEl.htmlFor = inputId;
    const wrap = el('div', 'relative mt-2');
    const input = document.createElement('input');
    input.id = inputId;
    input.type = 'password';
    input.autocomplete = autocomplete;
    input.spellcheck = false;
    input.className = 'w-full rounded-2xl border border-white/10 bg-ink-950 py-3 pl-4 pr-12 text-sm text-slate-100 outline-none transition focus:border-cyan-300/40';
    if (testid) input.dataset.testid = testid;

    const toggle = el('button', 'absolute inset-y-0 right-0 inline-flex w-12 items-center justify-center rounded-r-2xl text-slate-400 transition hover:text-cyan-100');
    toggle.type = 'button';
    toggle.dataset.testid = testid ? `${testid}-reveal` : 'password-reveal';
    const eye = icon('M1 12s4-7 11-7 11 7 11 7-4 7-11 7-11-7-11-7z', true);
    const eyeOff = icon('M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24M1 1l22 22', false);
    eyeOff.classList.add('hidden');
    toggle.append(eye, eyeOff);
    const update = () => {
        const shown = input.type === 'text';
        toggle.setAttribute('aria-label', shown ? 'Hide password' : 'Show password');
        toggle.setAttribute('aria-pressed', String(shown));
        eye.classList.toggle('hidden', shown);
        eyeOff.classList.toggle('hidden', !shown);
    };
    toggle.addEventListener('click', () => {
        input.type = input.type === 'password' ? 'text' : 'password';
        update();
        input.focus();
    });
    update();

    wrap.append(input, toggle);
    field.append(labelEl, wrap);
    return { field, input };
}

/** Minutes of inactivity before the app locks; 0 means never. */
export function autoLockMinutes() {
    try {
        const stored = window.localStorage.getItem(AUTO_LOCK_KEY);
        if (stored !== null && AUTO_LOCK_CHOICES.includes(Number(stored))) {
            return Number(stored);
        }
    } catch {
        // Storage can be unavailable; fall back to the default.
    }
    return DEFAULT_AUTO_LOCK_MINUTES;
}

export function setAutoLockMinutes(minutes) {
    try {
        window.localStorage.setItem(AUTO_LOCK_KEY, String(minutes));
    } catch {
        // Keeps the default for this page when storage is unavailable.
    }
}

/**
 * Lock with `lock` after the configured minutes without user activity.
 * Browsers slow timers in background tabs, so the deadline is checked on a
 * short interval and whenever the tab becomes visible again. An operation in
 * progress gets a bounded grace period; a stuck operation cannot hold storage
 * open indefinitely.
 * @param {() => void} lock
 */
// Busy work can defer an expired idle lock for at most ten additional minutes.
export const MAX_BUSY_LOCK_DELAY_MS = 10 * 60_000;
export function startAutoLock(lock) {
    let lastActivity = performance.now();
    let busyDeadline = null;
    const touch = () => { lastActivity = performance.now(); busyDeadline = null; };
    const events = ['pointerdown', 'keydown', 'wheel', 'touchstart'];
    for (const type of events) window.addEventListener(type, touch, { capture: true, passive: true });
    let locking = false;
    const check = () => {
        if (locking) return;
        const minutes = autoLockMinutes();
        if (minutes === 0) { busyDeadline = null; return; }
        const now = performance.now();
        const busy = operationInProgress();
        if (!busy) busyDeadline = null;
        const idleAt = (busy ? lastActivity : Math.max(lastActivity, lastStorageActivity())) + minutes * 60_000;
        if (now < idleAt) return;
        if (busy) {
            busyDeadline ??= idleAt + MAX_BUSY_LOCK_DELAY_MS;
            if (now < busyDeadline) return;
        }
        locking = true;
        lock();
    };
    const timer = window.setInterval(check, 15_000);
    document.addEventListener('visibilitychange', check);
    return () => {
        window.clearInterval(timer);
        for (const type of events) window.removeEventListener(type, touch, true);
        document.removeEventListener('visibilitychange', check);
    };
}

function operationInProgress() {
    return storageActivityPending() || document.querySelector('[data-status="submitting"], [data-state="generating"]') !== null;
}

function el(tag, className, text) {
    const node = document.createElement(tag);
    if (className) node.className = className;
    if (text !== undefined) node.textContent = text;
    return node;
}

function eyebrow() {
    return el('p', 'text-[11px] font-semibold uppercase tracking-[0.34em] text-cyan-200/70', 'Local data');
}

function heading(text) {
    const title = el('h2', 'mt-3 text-xl font-semibold tracking-tight text-white', text);
    title.id = 'storage-password-title';
    return title;
}

function icon(path, withPupil) {
    const ns = 'http://www.w3.org/2000/svg';
    const svg = document.createElementNS(ns, 'svg');
    svg.setAttribute('class', 'h-4 w-4');
    svg.setAttribute('viewBox', '0 0 24 24');
    svg.setAttribute('fill', 'none');
    svg.setAttribute('stroke', 'currentColor');
    svg.setAttribute('stroke-width', '1.8');
    svg.setAttribute('aria-hidden', 'true');
    const p = document.createElementNS(ns, 'path');
    p.setAttribute('d', path);
    svg.appendChild(p);
    if (withPupil) {
        const circle = document.createElementNS(ns, 'circle');
        circle.setAttribute('cx', '12');
        circle.setAttribute('cy', '12');
        circle.setAttribute('r', '3');
        svg.appendChild(circle);
    }
    return svg;
}
