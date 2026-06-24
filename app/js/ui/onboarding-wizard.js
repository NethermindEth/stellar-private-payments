import { getHandle } from '../wasm-facade.js';
import { deriveKeysFromWallet } from '../wallet.js';
import {
    hasNotificationSupport,
    getNotificationsPrompted,
    setNotificationsPrompted,
    requestNotificationPermission,
} from './push-notifications.js';

const STORAGE_PERSIST_FLAG = 'poolstellar_storage_persist_prompted';
const DEFAULT_EXPLORER_BASE_URL = 'https://stellar.expert/explorer/testnet';

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

function setHidden(el, hidden) {
    el?.classList.toggle('hidden', !!hidden);
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
    intro.innerHTML = `
        <p class="text-[11px] font-semibold uppercase tracking-[0.28em] text-cyan-200/70">${eyebrow}</p>
        <h3 class="mt-2 text-2xl font-semibold tracking-tight text-white">${title}</h3>
        <p class="mt-3 text-sm leading-6 text-slate-300">${body}</p>
    `;
    wrap.appendChild(intro);

    if (aside) {
        const info = document.createElement('div');
        info.className = 'rounded-[24px] border border-white/8 bg-ink-950/70 p-5 text-sm leading-6 text-slate-300';
        if (typeof aside === 'string') {
            info.innerHTML = aside;
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

export async function runOnboardingWizard({ address, networkPassphrase } = {}) {
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
        ...(needsNotificationStep || !bootnodeSetting ? ['retention'] : []),
        [explorerSetting?.baseUrl ? null : 'explorer'].filter(Boolean),
        [registryLookup?.entry ? null : 'registration'].filter(Boolean),
    ].flat();

    if (!steps.length) {
        return {
            pubKey: existingKeys.noteKeypair.public,
            encryptionKeypair: { publicKey: existingKeys.encryptionKeypair.public },
            aspSecret: existingAspSecret.membershipBlinding,
        };
    }

    showModal();

    let cancelled = false;
    let closeHandler = null;
    const closeBtn = document.getElementById('onboarding-close-btn');
    closeBtn.onclick = () => {
        cancelled = true;
        closeHandler?.();
        hideModal();
    };

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

    ['disclaimer', 'storage', 'keys', 'retention', 'explorer', 'registration'].forEach(stepId => {
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

        if (stepId === 'disclaimer') {
            const markdown = document.createElement('div');
            markdown.className = 'space-y-3 text-sm text-slate-300';
            renderDisclaimerMarkdown(disclaimerState?.disclaimerTextMd || '', markdown);
            const panel = makePanel({
                eyebrow: `Step ${i + 1} of ${steps.length}`,
                title: 'Review the operating disclaimer',
                body: 'This setup stores private payment material locally and assumes the operator understands the wallet, retention, and registration model.',
                aside: markdown,
            });
            renderContent(panel);

            await waitForStep((resolve, reject) => {
                const cancel = makeButton({ text: 'Cancel', variant: 'ghost', onClick: () => reject(new Error('Onboarding cancelled')) });
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
            const panel = makePanel({
                eyebrow: `Step ${i + 1} of ${steps.length}`,
                title: 'Request durable browser storage',
                body: 'The app keeps your privacy keys, ASP secret, local notes, and settings in browser storage. Persistent storage reduces the chance of silent eviction.',
                aside: `<p>Current status: <span class="font-semibold text-white">${persisted ? 'already persisted' : 'not persisted yet'}</span></p>`,
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
                            await persistStorageIfWanted();
                            setPersistPromptedFlag();
                            resolve();
                        } catch (error) {
                            request.disabled = false;
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
            const secretWrap = document.createElement('div');
            secretWrap.className = 'rounded-[24px] border border-white/8 bg-ink-950/75 p-5';
            secretWrap.innerHTML = `
                <p class="text-[11px] font-semibold uppercase tracking-[0.22em] text-slate-500">Derived Material</p>
                <p class="mt-3 text-sm text-slate-300">Your ASP secret is derived deterministically from wallet signatures and stored locally. It stays masked unless explicitly revealed.</p>
                <div class="mt-4 rounded-2xl border border-white/8 bg-white/[0.03] p-4">
                    <p class="text-xs text-slate-500">ASP secret preview</p>
                    <p id="wizard-asp-secret" class="mt-2 break-all font-mono text-xs text-slate-100">${maskSecret(state.keys?.aspSecret || '')}</p>
                </div>
            `;
            const panel = makePanel({
                eyebrow: `Step ${i + 1} of ${steps.length}`,
                title: 'Derive note keys and ASP secret',
                body: 'This requires a wallet signature but does not move funds. The derived note key, encryption key, and ASP secret are then cached locally.',
                aside: secretWrap,
            });
            renderContent(panel);

            await waitForStep((resolve, reject) => {
                const cancel = makeButton({ text: 'Cancel', variant: 'ghost', onClick: () => reject(new Error('Onboarding cancelled')) });
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
                            document.getElementById('wizard-asp-secret').textContent = maskSecret(result.aspSecret);
                            resolve();
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
            const bootnodeEnabled = !!state.bootnode?.enabled;
            const inputWrap = document.createElement('div');
            inputWrap.className = 'space-y-4';
            inputWrap.innerHTML = `
                <div class="rounded-[24px] border border-white/8 bg-ink-950/75 p-5 text-sm text-slate-300">
                    <p class="font-semibold text-white">When do you need this?</p>
                    <p class="mt-3">If you rely only on a public RPC and miss the event retention window, the app may need either a browser reminder to reopen the tab in time or a bootnode archive URL to rebuild history later.</p>
                    <ul class="mt-4 list-disc space-y-2 pl-5">
                        <li>Integrity risk: a bootnode can omit or forge event history.</li>
                        <li>Availability risk: a bootnode can be unavailable or rate limit you.</li>
                        <li>Privacy risk: the operator can observe IP address and timing.</li>
                        <li>Handoff risk: it can provide an incorrect ledger handoff point.</li>
                    </ul>
                </div>
                <div class="rounded-[24px] border border-white/8 bg-white/[0.03] p-5">
                    <label class="flex items-start gap-3">
                        <input id="wizard-bootnode-enabled" type="checkbox" class="mt-1 h-4 w-4 rounded border-white/10 bg-ink-950 text-cyan-300 focus:ring-cyan-300" ${bootnodeEnabled ? 'checked' : ''}>
                        <span>
                            <span class="block text-sm font-medium text-white">Store a bootnode URL now</span>
                            <span class="mt-1 block text-sm text-slate-400">Use this if you want an explicit retention bypass path instead of relying only on reminders.</span>
                        </span>
                    </label>
                    <div class="mt-4">
                        <label for="wizard-bootnode-url" class="text-xs font-medium uppercase tracking-[0.22em] text-slate-500">Bootnode RPC URL</label>
                        <input id="wizard-bootnode-url" type="text" value="${state.bootnode?.url || ''}" placeholder="https://..." class="mt-3 w-full rounded-2xl border border-white/10 bg-ink-950 px-4 py-3 text-sm text-slate-100 outline-none transition focus:border-cyan-300/40">
                    </div>
                </div>
            `;

            if (enableNotifications) {
                const notif = document.createElement('div');
                notif.className = 'rounded-[24px] border border-white/8 bg-white/[0.03] p-5 text-sm text-slate-300';
                notif.innerHTML = `
                    <p class="font-medium text-white">Browser reminder</p>
                    <p class="mt-2">If you choose to rely on RPC only, you can allow notifications so the app can remind you to reopen the tab before retention becomes a problem.</p>
                    <p class="mt-2 text-xs text-slate-500">Current permission: ${Notification.permission}</p>
                `;
                inputWrap.appendChild(notif);
            }

            const panel = makePanel({
                eyebrow: `Step ${i + 1} of ${steps.length}`,
                title: 'Set your retention fallback',
                body: 'Choose whether this operator station keeps a bootnode archive URL, relies on browser reminders, or both. You can change bootnode settings later.',
                aside: inputWrap,
            });
            renderContent(panel);

            await waitForStep((resolve, reject) => {
                const later = makeButton({ text: 'Continue', variant: 'ghost', onClick: () => resolve() });
                const requestNotif = enableNotifications
                    ? makeButton({
                        text: 'Allow reminders',
                        onClick: async () => {
                            try {
                                requestNotif.disabled = true;
                                await requestNotificationPermission();
                                setNotificationsPrompted();
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
                            const enabled = !!document.getElementById('wizard-bootnode-enabled')?.checked;
                            const url = document.getElementById('wizard-bootnode-url')?.value?.trim() || '';
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
                renderActions([later, ...(requestNotif ? [requestNotif] : []), save]);
            });
            ensureNotCancelled();
            continue;
        }

        if (stepId === 'explorer') {
            const wrap = document.createElement('div');
            wrap.className = 'rounded-[24px] border border-white/8 bg-white/[0.03] p-5';
            wrap.innerHTML = `
                <label for="wizard-explorer-url" class="text-xs font-medium uppercase tracking-[0.22em] text-slate-500">Explorer Base URL</label>
                <input id="wizard-explorer-url" type="text" value="${state.explorerBaseUrl}" class="mt-3 w-full rounded-2xl border border-white/10 bg-ink-950 px-4 py-3 text-sm text-slate-100 outline-none transition focus:border-cyan-300/40">
                <p class="mt-3 text-sm text-slate-400">This controls explorer links shown after transactions and in the shell. You can update it later in settings.</p>
            `;
            const panel = makePanel({
                eyebrow: `Step ${i + 1} of ${steps.length}`,
                title: 'Choose the explorer base link',
                body: 'The UI uses a single explorer base URL across transaction feedback and address shortcuts.',
                aside: wrap,
            });
            renderContent(panel);

            await waitForStep((resolve, reject) => {
                const later = makeButton({ text: 'Use default', variant: 'ghost', onClick: () => resolve() });
                const save = makeButton({
                    text: 'Save explorer',
                    variant: 'primary',
                    onClick: async () => {
                        try {
                            const baseUrl = document.getElementById('wizard-explorer-url')?.value?.trim() || DEFAULT_EXPLORER_BASE_URL;
                            await client.setSetting('explorer', { baseUrl });
                            state.explorerBaseUrl = baseUrl;
                            resolve();
                        } catch (error) {
                            setError(error?.message || 'Failed to save explorer setting');
                        }
                    },
                });
                renderActions([later, save]);
            });
            ensureNotCancelled();
            continue;
        }

        if (stepId === 'registration') {
            const panel = makePanel({
                eyebrow: `Step ${i + 1} of ${steps.length}`,
                title: 'Register your public keys in the address book',
                body: 'If you register now, other users can transfer to your Stellar address without asking for note and encryption public keys out of band.',
                aside: `<p>If you skip this step, transfers to you require sharing your note and encryption public keys manually. Registration remains available later from settings.</p>`,
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
