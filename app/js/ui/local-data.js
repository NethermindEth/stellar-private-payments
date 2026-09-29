import { mountStorageMethods } from '../storage-methods.js';
// The header's lock button and the Local Data settings: locking, the
// inactivity delay and changing the password.

import {
    STORAGE_UNLOCKED_EVENT,
    changeStoragePassword,
    ensurePrivateStorage,
    isStorageUnlocked,
    lockStorage,
    unlockedStorage,
} from '../wasm-facade.js';
import {
    MIN_PASSWORD_LENGTH,
    autoLockMinutes,
    passwordField,
    setAutoLockMinutes,
} from '../storage-access.js';
import { isDbLockedError, showDbLockedModal } from '../db-locked.js';
import { Toast } from './core.js';

function renderLockButton() {
    const button = document.getElementById('storage-lock-btn');
    if (!button) return;
    const unlocked = isStorageUnlocked();
    button.dataset.state = unlocked ? 'unlocked' : 'locked';
    button.title = unlocked ? 'Lock local data' : 'Unlock local data';
    const label = document.getElementById('storage-lock-label');
    if (label) label.textContent = unlocked ? 'Lock' : 'Unlock';
    // An open shackle while unlocked.
    document.getElementById('storage-lock-shackle')
        ?.setAttribute('d', unlocked ? 'M8 11V7a4 4 0 0 1 7.5-2' : 'M8 11V7a4 4 0 0 1 8 0');
}

function bindLockButton() {
    const button = document.getElementById('storage-lock-btn');
    button?.addEventListener('click', async () => {
        if (isStorageUnlocked()) {
            await lockStorage();
            return;
        }
        try {
            await ensurePrivateStorage();
        } catch (error) {
            if (error?.code === 'unlock-cancelled') return;
            const message = error?.message || 'Could not open local data';
            if (isDbLockedError(message)) showDbLockedModal(message);
            else Toast.show(message, 'error');
        }
    });
    window.addEventListener(STORAGE_UNLOCKED_EVENT, renderLockButton);
    renderLockButton();
}

function bindAutoLock() {
    const select = document.getElementById('settings-auto-lock');
    if (!select) return;
    const render = () => { select.value = String(autoLockMinutes()); };
    render();
    window.addEventListener(STORAGE_UNLOCKED_EVENT, render);
    select.addEventListener('change', () => setAutoLockMinutes(Number(select.value)));
}

function bindChangePassword() {
    const form = document.getElementById('settings-change-password');
    const fields = document.getElementById('settings-password-fields');
    const message = document.getElementById('settings-password-message');
    const button = document.getElementById('settings-change-password-btn');
    if (!form || !fields || !message || !button) return;

    const current = passwordField({
        label: 'Current password',
        autocomplete: 'current-password',
        testid: 'settings-current-password',
        id: 'settings-current-password',
    });
    const next = passwordField({
        label: 'New password',
        autocomplete: 'new-password',
        testid: 'settings-new-password',
        id: 'settings-new-password',
    });
    const confirm = passwordField({
        label: 'Confirm new password',
        autocomplete: 'new-password',
        testid: 'settings-confirm-password',
        id: 'settings-confirm-password',
    });
    fields.append(current.field, next.field, confirm.field);

    const show = (text, ok) => {
        message.textContent = text;
        message.className = ok
            ? 'rounded-2xl border border-emerald-400/25 bg-emerald-400/10 px-4 py-3 text-sm text-emerald-100'
            : 'rounded-2xl border border-rose-400/25 bg-rose-400/10 px-4 py-3 text-sm text-rose-100';
    };

    form.addEventListener('submit', async (event) => {
        event.preventDefault();
        message.classList.add('hidden');
        if (!current.input.value) {
            show('Enter your current password.', false);
            current.input.focus();
            return;
        }
        if ([...next.input.value].length < MIN_PASSWORD_LENGTH) {
            show(`Use a new password of at least ${MIN_PASSWORD_LENGTH} characters.`, false);
            next.input.focus();
            return;
        }
        if (confirm.input.value !== next.input.value) {
            show("New passwords don't match.", false);
            confirm.input.focus();
            return;
        }
        button.disabled = true;
        button.textContent = 'Changing…';
        try {
            await changeStoragePassword(current.input.value, next.input.value);
            for (const field of [current, next, confirm]) field.input.value = '';
            show('Password changed.', true);
        } catch (error) {
            if (error?.code === 'wrong-password') {
                show('The current password is wrong.', false);
                current.input.value = '';
                current.input.focus();
            } else {
                show(error?.message || 'Could not change the password.', false);
            }
        } finally {
            button.disabled = false;
            button.textContent = 'Change password';
        }
    });
}

export const LocalData = {
    init() {
        bindLockButton();
        bindAutoLock();
        bindChangePassword();
        const methods = document.getElementById('settings-unlock-methods');
        const renderMethods = () => {
            if (!methods) return;
            if (isStorageUnlocked()) mountStorageMethods(methods, unlockedStorage());
            else {
                const button = document.createElement('button');
                button.type = 'button';
                button.className = 'text-sm text-cyan-200 underline';
                button.textContent = 'Unlock private data to manage access';
                button.addEventListener('click', () => ensurePrivateStorage().catch(() => {}));
                methods.replaceChildren(button);
            }
        };
        window.addEventListener(STORAGE_UNLOCKED_EVENT, renderMethods);
        renderMethods();
    },
};
