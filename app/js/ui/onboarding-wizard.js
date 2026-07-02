import { getHandle } from '../wasm-facade.js';
import { deriveKeysFromWallet } from '../wallet.js';
import { Utils, Toast } from './core.js';
import {
    hasNotificationSupport,
    getNotificationsPrompted,
    setNotificationsPrompted,
    requestNotificationPermission,
} from './push-notifications.js';

const STORAGE_PERSIST_FLAG = 'poolstellar_storage_persist_prompted';
const DEFAULT_EXPLORER_BASE_URL = 'https://stellar.expert/explorer/testnet';
const STEP_ORDER = ['disclaimer', 'storage', 'keys', 'retention', 'explorer', 'registration'];

function hasStorageManager() {
    return (
        typeof navigator !== 'undefined' &&
        navigator.storage &&
        typeof navigator.storage.persisted === 'function' &&
        typeof navigator.storage.persist === 'function'
    );
}

async function isPersisted() {
    if (!hasStorageManager()) return false;
    try {
        return await navigator.storage.persisted();
    } catch {
        return false;
    }
}

function getPersistPromptedFlag() {
    try {
        return window.localStorage.getItem(STORAGE_PERSIST_FLAG) === '1';
    } catch {
        return false;
    }
}

function setPersistPromptedFlag() {
    try {
        window.localStorage.setItem(STORAGE_PERSIST_FLAG, '1');
    } catch {
        // ignore
    }
}

function setError(message) {
    const el = document.getElementById('onboarding-error');
    if (!el) return;
    if (!message) {
        el.textContent = '';
        el.classList.add('hidden');
        return;
    }
    el.textContent = message;
    el.classList.remove('hidden');
}

function showModal() {
    const el = document.getElementById('onboarding-modal');
    if (!el) throw new Error('Onboarding modal is missing');
    setError('');
    el.classList.remove('hidden');
}

function hideModal() {
    document.getElementById('onboarding-modal')?.classList.add('hidden');
}

function renderContent(node) {
    const el = document.getElementById('onboarding-content');
    if (!el) return;
    el.replaceChildren();
    if (node) el.appendChild(node);
}

function renderWhy(stepId) {
    document.querySelectorAll('#onboarding-why [data-why]').forEach(el => {
        el.classList.toggle('hidden', el.dataset.why !== stepId);
    });
}

function renderActions(buttons) {
    const el = document.getElementById('onboarding-actions');
    if (!el) return;
    el.replaceChildren(...buttons);
}

function makeButton({ text, variant = 'secondary', onClick }) {
    const btn = document.createElement('button');
    btn.type = 'button';
    btn.textContent = text;
    btn.className = variant === 'primary'
        ? 'rounded-2xl bg-[linear-gradient(135deg,#74c5ff,#2f6dff)] px-5 py-3 text-sm font-semibold text-ink-950 shadow-[0_12px_30px_rgba(63,138,255,0.45)] transition hover:brightness-110 disabled:opacity-60'
        : variant === 'ghost'
            ? 'rounded-2xl border border-white/10 px-5 py-3 text-sm font-medium text-slate-300 transition hover:border-cyan-300/30 hover:text-cyan-100 disabled:opacity-60'
            : 'rounded-2xl border border-white/10 bg-white/[0.03] px-5 py-3 text-sm font-medium text-slate-200 transition hover:border-cyan-300/30 hover:text-cyan-100 disabled:opacity-60';
    if (onClick) btn.addEventListener('click', onClick);
    return btn;
}

function makePanel({ eyebrow, title, body, aside }) {
    const wrap = document.createElement('div');
    wrap.className = 'space-y-5';

    const intro = document.createElement('div');
    const eyebrowEl = document.createElement('p');
    eyebrowEl.className = 'text-[11px] font-semibold uppercase tracking-[0.28em] text-cyan-200/70';
    eyebrowEl.textContent = eyebrow;
    const titleEl = document.createElement('h3');
    titleEl.className = 'mt-2 text-2xl font-semibold tracking-tight text-white';
    titleEl.textContent = title;
    intro.append(eyebrowEl, titleEl);
    if (body) {
        const bodyEl = document.createElement('p');
        bodyEl.className = 'mt-3 text-sm leading-6 text-slate-300';
        bodyEl.textContent = body;
        intro.appendChild(bodyEl);
    }
    wrap.appendChild(intro);

    if (aside) {
        const info = document.createElement('div');
        info.className = 'rounded-[24px] border border-white/8 bg-ink-950/70 p-5 text-sm leading-6 text-slate-300';
        if (typeof aside === 'string') {
            info.textContent = aside;
        } else {
            info.appendChild(aside);
        }
        wrap.appendChild(info);
    }

    return wrap;
}

function setStepState(stepId, state) {
    const el = document.querySelector(`#onboarding-steps [data-step="${stepId}"]`);
    if (!el) return;
    el.dataset.state = state;
    el.classList.remove(
        'border-white/8',
        'bg-white/[0.03]',
        'text-slate-400',
        'border-cyan-300/30',
        'bg-cyan-300/10',
        'text-cyan-100',
        'border-emerald-300/30',
        'bg-emerald-300/10',
        'text-emerald-100'
    );
    if (state === 'current') {
        el.classList.add('border-cyan-300/30', 'bg-cyan-300/10', 'text-cyan-100');
    } else if (state === 'done') {
        el.classList.add('border-emerald-300/30', 'bg-emerald-300/10', 'text-emerald-100');
    } else {
        el.classList.add('border-white/8', 'bg-white/[0.03]', 'text-slate-400');
    }
}

function maskSecret(secret) {
    if (!secret) return 'Not available';
    return `${'*'.repeat(12)}${secret.slice(-6)}`;
}

function renderDisclaimerMarkdown(md, container) {
    container.textContent = '';
    const lines = String(md || '').replace(/\r\n/g, '\n').split('\n');
    let currentList = null;
    let inCode = false;
    let codeLines = [];

    const flushList = () => {
        currentList = null;
    };

    const flushCode = () => {
        if (!codeLines.length) return;
        const pre = document.createElement('pre');
        pre.className = 'overflow-auto rounded-2xl border border-white/8 bg-ink-950 px-4 py-3 text-xs text-slate-200';
        pre.textContent = codeLines.join('\n');
        container.appendChild(pre);
        codeLines = [];
    };

    for (const rawLine of lines) {
        const line = rawLine.replace(/\s+$/g, '');
        if (line.startsWith('```')) {
            if (inCode) {
                inCode = false;
                flushCode();
            } else {
                flushList();
                inCode = true;
                codeLines = [];
            }
            continue;
        }
        if (inCode) {
            codeLines.push(rawLine);
            continue;
        }
        if (!line.trim()) {
            flushList();
            continue;
        }

        const headingMatch = line.match(/^(#{1,6})\s+(.*)$/);
        if (headingMatch) {
            flushList();
            const level = headingMatch[1].length;
            const text = headingMatch[2].trim();
            const heading = document.createElement(level === 1 ? 'h4' : 'h5');
            heading.className = level === 1 ? 'text-lg font-semibold text-white' : 'text-sm font-semibold text-white';
            heading.textContent = text;
            container.appendChild(heading);
            continue;
        }

        const listMatch = line.match(/^[-*]\s+(.*)$/);
        if (listMatch) {
            if (!currentList) {
                currentList = document.createElement('ul');
                currentList.className = 'list-disc space-y-2 pl-5';
                container.appendChild(currentList);
            }
            const li = document.createElement('li');
            li.textContent = listMatch[1].trim();
            currentList.appendChild(li);
            continue;
        }

        flushList();
        const p = document.createElement('p');
        p.className = 'leading-6';
        p.textContent = line.trim();
        container.appendChild(p);
    }

    if (inCode) flushCode();
}

function notificationStepNeeded() {
    if (!hasNotificationSupport()) return false;
    if (Notification.permission !== 'default') return false;
    return !getNotificationsPrompted();
}

async function persistStorageIfWanted() {
    if (!hasStorageManager()) return false;
    try {
        return await navigator.storage.persist();
    } catch {
        return false;
    }
}

async function registerNow({ client, address, notePublicKey, encryptionPublicKey, networkPassphrase }) {
    if (!networkPassphrase) throw new Error('Missing Stellar network passphrase');
    return client.registerPublicKeys(
        address,
        notePublicKey,
        encryptionPublicKey,
        networkPassphrase,
        null,
    );
}

export async function runOnboardingWizard({ address, networkPassphrase, bootnodeRequired = false } = {}) {
    const client = getHandle().webClient;
    if (!address) throw new Error('Wallet address required for onboarding');

    const disclaimerState = await client.getDisclaimerState(address);
    const existingKeys = await client.getUserKeys(address);
    const existingAspSecret = await client.getASPSecret(address);
    const explorerSetting = await client.getExplorerSetting();
    const bootnodeSetting = await client.getBootnodeConfig();
    const registryLookup = await client.lookupRegisteredPublicKey(address).catch(() => null);

    const storageAvailable = hasStorageManager();
    const persisted = storageAvailable ? await isPersisted() : false;
    const storagePrompted = storageAvailable ? getPersistPromptedFlag() : true;
    const needsStorageStep = storageAvailable && (!persisted || !storagePrompted);
    const needsNotificationStep = notificationStepNeeded();

    const steps = [
        ...(!disclaimerState?.accepted ? ['disclaimer'] : []),
        ...(needsStorageStep ? ['storage'] : []),
        ...((!existingKeys || !existingAspSecret?.membershipBlinding) ? ['keys'] : []),
        ...(needsNotificationStep || !bootnodeSetting || bootnodeRequired ? ['retention'] : []),
        [explorerSetting?.baseUrl ? null : 'explorer'].filter(Boolean),
        // Only offer registration when the registry is fully synced AND there's no
        // entry. If the local registry hasn't synced yet, the lookup can't prove the
        // user is unregistered — skip it rather than falsely suggesting registration.
        ...((!registryLookup?.entry && registryLookup?.registryFullySynced) ? ['registration'] : []),
    ].flat();

    // Registration is optional (also available later from Settings), so it must
    // not, on its own, reopen onboarding on reload. Only required steps
    // (disclaimer, durable storage, keys, retention) should trigger the modal —
    // e.g. it keeps reappearing while permanent storage hasn't been granted.
    const hasRequiredStep = steps.some(step => step !== 'registration');
    if (!hasRequiredStep) {
        return {
            pubKey: existingKeys.noteKeypair.public,
            encryptionKeypair: { publicKey: existingKeys.encryptionKeypair.public },
            aspSecret: existingAspSecret.membershipBlinding,
        };
    }

    showModal();

    let cancelled = false;
    let closeHandler = null;
    const cancelOnboarding = () => {
        cancelled = true;
        closeHandler?.();
        hideModal();
    };
    const closeBtn = document.getElementById('onboarding-close-btn');
    closeBtn.onclick = cancelOnboarding;

    const state = {
        keys: existingKeys ? {
            pubKey: existingKeys.noteKeypair.public,
            encryptionKeypair: { publicKey: existingKeys.encryptionKeypair.public },
            aspSecret: existingAspSecret?.membershipBlinding || '',
        } : null,
        explorerBaseUrl: explorerSetting?.baseUrl || DEFAULT_EXPLORER_BASE_URL,
        bootnode: bootnodeSetting || { enabled: false, url: '' },
        registered: !!registryLookup?.entry,
    };

    STEP_ORDER.forEach(stepId => {
        setStepState(stepId, steps.includes(stepId) ? 'pending' : 'done');
    });

    const ensureNotCancelled = () => {
        if (cancelled) throw new Error('Onboarding cancelled');
    };

    const waitForStep = (setup) => new Promise((resolve, reject) => {
        closeHandler = () => reject(new Error('Onboarding cancelled'));
        setup(
            (value) => {
                closeHandler = null;
                resolve(value);
            },
            (error) => {
                closeHandler = null;
                reject(error);
            },
        );
    });

    for (let i = 0; i < steps.length; i += 1) {
        const stepId = steps[i];
        setError('');
        steps.forEach((candidate, index) => {
            setStepState(candidate, index < i ? 'done' : index === i ? 'current' : 'pending');
        });
        renderWhy(stepId);

        if (stepId === 'disclaimer') {
            const markdown = document.createElement('div');
            markdown.className = 'space-y-3 text-sm text-slate-300';
            renderDisclaimerMarkdown(disclaimerState?.disclaimerTextMd || '', markdown);
            const panel = makePanel({
                eyebrow: `Step ${STEP_ORDER.indexOf(stepId) + 1} of ${STEP_ORDER.length}`,
                title: 'Review the operating disclaimer',
                aside: markdown,
            });
            renderContent(panel);

            await waitForStep((resolve, reject) => {
                const cancel = makeButton({ text: 'Cancel', variant: 'ghost', onClick: cancelOnboarding });
                const accept = makeButton({
                    text: 'Accept disclaimer',
                    variant: 'primary',
                    onClick: async () => {
                        try {
                            accept.disabled = true;
                            await client.acceptDisclaimer(address, disclaimerState?.disclaimerHashHex || '');
                            resolve();
                        } catch (error) {
                            accept.disabled = false;
                            setError(error?.message || 'Failed to accept disclaimer');
                        }
                    },
                });
                renderActions([cancel, accept]);
            });
            ensureNotCancelled();
            continue;
        }

        if (stepId === 'storage') {
            const statusWrap = document.createElement('p');
            statusWrap.append('Current status: ');
            const statusValue = document.createElement('span');
            statusValue.className = 'font-semibold text-white';
            statusValue.textContent = persisted ? 'already persisted' : 'not persisted yet';
            statusWrap.appendChild(statusValue);
            const panel = makePanel({
                eyebrow: `Step ${STEP_ORDER.indexOf(stepId) + 1} of ${STEP_ORDER.length}`,
                title: 'Request durable browser storage',
                body: 'The app keeps your privacy keys, ASP secret, local notes, and settings in browser storage. Persistent storage reduces the chance of silent eviction.',
                aside: statusWrap,
            });
            renderContent(panel);

            await waitForStep((resolve, reject) => {
                const later = makeButton({
                    text: 'Continue without it',
                    variant: 'ghost',
                    onClick: () => {
                        setPersistPromptedFlag();
                        resolve();
                    },
                });
                const request = makeButton({
                    text: 'Request persistent storage',
                    variant: 'primary',
                    onClick: async () => {
                        try {
                            request.disabled = true;
                            later.disabled = true;
                            const granted = await persistStorageIfWanted();
                            setPersistPromptedFlag();
                            statusValue.textContent = granted ? 'granted — storage is now persistent' : 'denied by the browser';
                            statusValue.className = granted ? 'font-semibold text-emerald-200' : 'font-semibold text-amber-200';
                            renderActions([makeButton({ text: 'Continue', variant: 'primary', onClick: () => resolve() })]);
                        } catch (error) {
                            request.disabled = false;
                            later.disabled = false;
                            setError(error?.message || 'Failed to request storage persistence');
                        }
                    },
                });
                renderActions([later, request]);
            });
            ensureNotCancelled();
            continue;
        }

        if (stepId === 'keys') {
            const secretWrap = document.getElementById('tpl-onboarding-keys').content.firstElementChild.cloneNode(true);
            const noteField = secretWrap.querySelector('[data-field="note"]');
            const aspField = secretWrap.querySelector('[data-field="asp"]');
            noteField.textContent = state.keys?.pubKey || 'Not available';
            aspField.textContent = maskSecret(state.keys?.aspSecret || '');
            secretWrap.querySelector('[data-copy="note"]').addEventListener('click', () => {
                if (state.keys?.pubKey) Utils.copyToClipboard(state.keys.pubKey);
            });
            secretWrap.querySelector('[data-copy="asp"]').addEventListener('click', () => {
                if (state.keys?.aspSecret) Utils.copyToClipboard(state.keys.aspSecret);
            });
            const panel = makePanel({
                eyebrow: `Step ${STEP_ORDER.indexOf(stepId) + 1} of ${STEP_ORDER.length}`,
                title: 'Derive note keys and ASP secret',
                body: 'Your wallet is requested to sign one message. That signature derives your privacy keys locally plus your ASP secret. This does not move funds.',
                aside: secretWrap,
            });
            renderContent(panel);

            await waitForStep((resolve, reject) => {
                const cancel = makeButton({ text: 'Cancel', variant: 'ghost', onClick: cancelOnboarding });
                const derive = makeButton({
                    text: 'Derive and store keys',
                    variant: 'primary',
                    onClick: async () => {
                        try {
                            derive.disabled = true;
                            const result = await deriveKeysFromWallet(address, {
                                onStatus: () => {},
                                skipCacheCheck: false,
                            });
                            state.keys = result;
                            noteField.textContent = result.pubKey;
                            aspField.textContent = maskSecret(result.aspSecret);
                            renderActions([makeButton({ text: 'Continue', variant: 'primary', onClick: () => resolve() })]);
                        } catch (error) {
                            derive.disabled = false;
                            setError(error?.message || 'Failed to derive privacy keys');
                        }
                    },
                });
                renderActions([cancel, derive]);
            });
            ensureNotCancelled();
            continue;
        }

        if (stepId === 'retention') {
            const enableNotifications = hasNotificationSupport();
            const bootnodeEnabled = bootnodeRequired || !!state.bootnode?.enabled;
            const inputWrap = document.createElement('div');
            inputWrap.className = 'space-y-4';
            const bootnodeBox = document.getElementById('tpl-wizard-bootnode').content.firstElementChild.cloneNode(true);
            const bootnodeEnabledInput = bootnodeBox.querySelector('#wizard-bootnode-enabled');
            bootnodeEnabledInput.checked = bootnodeEnabled;
            bootnodeEnabledInput.disabled = bootnodeRequired;
            bootnodeBox.querySelector('#wizard-bootnode-url').value = state.bootnode?.url || '';
            inputWrap.appendChild(bootnodeBox);

            if (bootnodeRequired) {
                const requiredNote = document.createElement('p');
                requiredNote.className = 'mt-4 text-sm text-amber-200';
                requiredNote.textContent = 'The public RPC is missing event history (sync gap), so a bootnode archive URL is required to join the app.';
                bootnodeBox.appendChild(requiredNote);
            }

            let permStatus = null;
            if (enableNotifications) {
                const notif = document.createElement('div');
                notif.className = 'rounded-[24px] border border-white/8 bg-white/[0.03] p-5 text-sm text-slate-300 space-y-2';
                const notifTitle = document.createElement('p');
                notifTitle.className = 'font-medium text-white';
                notifTitle.textContent = 'Browser reminder';
                const notifBody = document.createElement('p');
                notifBody.textContent = 'If you choose to rely on RPC only, you can allow notifications so the app can remind you to reopen the tab before retention becomes a problem.';
                permStatus = document.createElement('p');
                permStatus.className = 'text-xs text-slate-500';
                permStatus.textContent = `Current permission: ${Notification.permission}`;
                notif.append(notifTitle, notifBody, permStatus);
                inputWrap.appendChild(notif);
            }

            const panel = makePanel({
                eyebrow: `Step ${STEP_ORDER.indexOf(stepId) + 1} of ${STEP_ORDER.length}`,
                title: 'Set your retention fallback',
                body: 'Choose whether this operator station keeps a bootnode archive URL, relies on browser reminders, or both. You can change bootnode settings later.',
                aside: inputWrap,
            });
            renderContent(panel);

            await waitForStep((resolve, reject) => {
                const later = makeButton({ text: 'Continue', variant: 'ghost', onClick: () => resolve() });
                const requestNotif = enableNotifications && Notification.permission !== 'granted'
                    ? makeButton({
                        text: 'Allow reminders',
                        onClick: async () => {
                            try {
                                requestNotif.disabled = true;
                                const permission = await requestNotificationPermission();
                                setNotificationsPrompted();
                                if (permStatus) permStatus.textContent = `Current permission: ${Notification.permission}`;
                                Toast.show(
                                    permission === 'granted' ? 'Reminders enabled' : `Notifications ${permission}`,
                                    permission === 'granted' ? 'success' : 'info',
                                );
                                requestNotif.disabled = false;
                            } catch (error) {
                                requestNotif.disabled = false;
                                setError(error?.message || 'Failed to request notifications');
                            }
                        },
                    })
                    : null;
                const save = makeButton({
                    text: 'Save retention setup',
                    variant: 'primary',
                    onClick: async () => {
                        try {
                            const enabled = bootnodeRequired || !!document.getElementById('wizard-bootnode-enabled')?.checked;
                            const url = document.getElementById('wizard-bootnode-url')?.value?.trim() || '';
                            if (bootnodeRequired && !url) {
                                throw new Error('A bootnode URL is required because the public RPC is missing event history.');
                            }
                            if (enabled && url && !url.startsWith('https://')) {
                                throw new Error('Bootnode URL must start with https://');
                            }
                            await client.setSetting('bootnode_config', { enabled, url });
                            state.bootnode = { enabled, url };
                            if (enableNotifications) {
                                setNotificationsPrompted();
                            }
                            resolve();
                        } catch (error) {
                            setError(error?.message || 'Failed to save retention configuration');
                        }
                    },
                });
                renderActions([...(bootnodeRequired ? [] : [later]), ...(requestNotif ? [requestNotif] : []), save]);
            });
            ensureNotCancelled();
            continue;
        }

        if (stepId === 'explorer') {
            const wrap = document.getElementById('tpl-wizard-explorer').content.firstElementChild.cloneNode(true);
            wrap.querySelector('#wizard-explorer-url').value = state.explorerBaseUrl;
            const panel = makePanel({
                eyebrow: `Step ${STEP_ORDER.indexOf(stepId) + 1} of ${STEP_ORDER.length}`,
                title: 'Choose the explorer base link',
                aside: wrap,
            });
            renderContent(panel);

            const persistExplorer = async (button, baseUrl) => {
                try {
                    button.disabled = true;
                    await client.setSetting('explorer', { baseUrl });
                    state.explorerBaseUrl = baseUrl;
                    resolveStep();
                } catch (error) {
                    button.disabled = false;
                    setError(error?.message || 'Failed to save explorer setting');
                }
            };
            let resolveStep = null;
            await waitForStep((resolve, reject) => {
                resolveStep = resolve;
                const later = makeButton({
                    text: 'Use default',
                    variant: 'ghost',
                    onClick: () => persistExplorer(later, DEFAULT_EXPLORER_BASE_URL),
                });
                const save = makeButton({
                    text: 'Save explorer',
                    variant: 'primary',
                    onClick: () => persistExplorer(
                        save,
                        document.getElementById('wizard-explorer-url')?.value?.trim() || DEFAULT_EXPLORER_BASE_URL,
                    ),
                });
                renderActions([later, save]);
            });
            ensureNotCancelled();
            continue;
        }

        if (stepId === 'registration') {
            const panel = makePanel({
                eyebrow: `Step ${STEP_ORDER.indexOf(stepId) + 1} of ${STEP_ORDER.length}`,
                title: 'Register your public keys in the address book',
                body: 'If you register now, other users can transfer to your Stellar address without asking for note and encryption public keys out of band.',
                aside: 'If you skip this step, transfers to you require sharing your note and encryption public keys manually. Registration remains available later from settings.',
            });
            renderContent(panel);

            await waitForStep((resolve, reject) => {
                const later = makeButton({ text: 'Register later', variant: 'ghost', onClick: () => resolve() });
                const register = makeButton({
                    text: 'Register now',
                    variant: 'primary',
                    onClick: async () => {
                        try {
                            if (!state.keys?.pubKey || !state.keys?.encryptionKeypair?.publicKey) {
                                throw new Error('Derive keys before registration');
                            }
                            register.disabled = true;
                            await registerNow({
                                client,
                                address,
                                notePublicKey: state.keys.pubKey,
                                encryptionPublicKey: state.keys.encryptionKeypair.publicKey,
                                networkPassphrase,
                            });
                            state.registered = true;
                            resolve();
                        } catch (error) {
                            register.disabled = false;
                            setError(error?.message || 'Failed to register public keys');
                        }
                    },
                });
                renderActions([later, register]);
            });
            ensureNotCancelled();
        }
    }

    hideModal();

    const finalKeys = state.keys || await deriveKeysFromWallet(address, { onStatus: () => {}, skipCacheCheck: false });
    return finalKeys;
}
