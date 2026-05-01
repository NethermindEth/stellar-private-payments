import { getHandle } from '../wasm-facade.js';
import { deriveKeysFromWallet } from '../wallet.js';

const STORAGE_PERSIST_FLAG = 'poolstellar_storage_persist_prompted';

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
    } catch (e) {
        console.debug('[Storage] navigator.storage.persisted() failed:', e);
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
        pre.className = 'p-3 bg-dark-950 border border-dark-800 rounded-lg overflow-auto text-xs font-mono text-dark-200';
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
            const el = document.createElement(`h${level}`);
            el.textContent = text;
            el.className =
                level === 1
                    ? 'text-base sm:text-lg font-semibold text-dark-100 mt-2'
                    : level === 2
                        ? 'text-sm sm:text-base font-semibold text-dark-100 mt-4'
                        : 'text-sm font-semibold text-dark-100 mt-3';
            container.appendChild(el);
            continue;
        }

        const listMatch = line.match(/^[-*]\s+(.*)$/);
        if (listMatch) {
            if (!currentList) {
                currentList = document.createElement('ul');
                currentList.className = 'list-disc pl-5 space-y-1';
                container.appendChild(currentList);
            }
            const li = document.createElement('li');
            li.textContent = listMatch[1].trim();
            currentList.appendChild(li);
            continue;
        }

        flushList();

        const p = document.createElement('p');
        p.className = 'leading-relaxed';

        const trimmed = line.trim();
        if (/^https?:\/\/\S+$/i.test(trimmed)) {
            const a = document.createElement('a');
            a.href = trimmed;
            a.target = '_blank';
            a.rel = 'noreferrer';
            a.className = 'text-brand-400 hover:text-brand-300 underline';
            a.textContent = trimmed;
            p.appendChild(a);
        } else {
            p.textContent = trimmed;
        }

        container.appendChild(p);
    }

    if (inCode) {
        flushCode();
    }
}

function setHidden(el, hidden) {
    el?.classList.toggle('hidden', !!hidden);
}

function setError(msg) {
    const errorEl = document.getElementById('onboarding-error');
    if (!errorEl) return;
    if (!msg) {
        errorEl.textContent = '';
        errorEl.classList.add('hidden');
        return;
    }
    errorEl.textContent = msg;
    errorEl.classList.remove('hidden');
}

function setStepState(stepId, state) {
    const el = document.querySelector(`#onboarding-steps [data-step="${stepId}"]`);
    if (!el) return;
    el.dataset.state = state;

    el.classList.remove(
        'border-dark-700',
        'text-dark-400',
        'bg-dark-900/40',
        'border-brand-500/40',
        'text-brand-300',
        'bg-brand-500/10',
        'border-emerald-500/40',
        'text-emerald-300',
        'bg-emerald-500/10'
    );

    if (state === 'current') {
        el.classList.add('border-brand-500/40', 'text-brand-300', 'bg-brand-500/10');
    } else if (state === 'done') {
        el.classList.add('border-emerald-500/40', 'text-emerald-300', 'bg-emerald-500/10');
    } else {
        el.classList.add('border-dark-700', 'text-dark-400', 'bg-dark-900/40');
    }
}

function showModal() {
    const modal = document.getElementById('onboarding-modal');
    if (!modal) throw new Error('Onboarding modal is missing from the page');
    setError('');
    modal.classList.remove('hidden');
}

function hideModal() {
    const modal = document.getElementById('onboarding-modal');
    modal?.classList.add('hidden');
}

function renderActions(buttons) {
    const actions = document.getElementById('onboarding-actions');
    if (!actions) return;
    actions.textContent = '';
    for (const btn of buttons) actions.appendChild(btn);
}

function makeButton({ id, text, variant = 'secondary', onClick }) {
    const btn = document.createElement('button');
    btn.type = 'button';
    if (id) btn.id = id;
    btn.textContent = text;

    if (variant === 'primary') {
        btn.className =
            'px-4 py-2 rounded-lg bg-brand-500 text-dark-950 font-semibold hover:bg-brand-400 transition-colors disabled:opacity-60 disabled:cursor-not-allowed';
    } else if (variant === 'danger') {
        btn.className =
            'px-4 py-2 rounded-lg border border-dark-600 bg-dark-800 text-dark-200 hover:bg-dark-700 hover:text-red-300 transition-colors disabled:opacity-60 disabled:cursor-not-allowed';
    } else {
        btn.className =
            'px-4 py-2 rounded-lg border border-dark-600 bg-dark-800 text-dark-200 hover:bg-dark-700 transition-colors disabled:opacity-60 disabled:cursor-not-allowed';
    }

    if (onClick) btn.addEventListener('click', onClick);
    return btn;
}

function renderStepContent(htmlOrNode) {
    const content = document.getElementById('onboarding-content');
    if (!content) return;
    content.textContent = '';
    if (typeof htmlOrNode === 'string') {
        content.innerHTML = htmlOrNode;
        return;
    }
    if (htmlOrNode) content.appendChild(htmlOrNode);
}

export async function runOnboardingWizard({ address, setButtonLoading } = {}) {
    const client = getHandle().webClient;
    if (!address) throw new Error('Wallet address required for onboarding');

    const disclaimerState = await client.getDisclaimerState(address);
    const existingKeys = await client.getUserKeys(address);

    const needsDisclaimer = !disclaimerState?.accepted;
    const needsKeys = !existingKeys;

    const storageAvailable = hasStorageManager();
    const persisted = storageAvailable ? await isPersisted() : false;
    const prompted = storageAvailable ? getPersistPromptedFlag() : true;
    const needsStorageStep = storageAvailable && !persisted && !prompted;

    if (!needsDisclaimer && !needsStorageStep && !needsKeys) {
        return {
            privKey: existingKeys.noteKeypair.private,
            pubKey: existingKeys.noteKeypair.public,
            encryptionKeypair: {
                publicKey: existingKeys.encryptionKeypair.public,
                privateKey: existingKeys.encryptionKeypair.private,
            },
        };
    }

    showModal();

    const abort = new AbortController();
    let cancelled = false;
    const closeBtn = document.getElementById('onboarding-close-btn');
    const onClose = () => {
        cancelled = true;
        abort.abort();
        hideModal();
    };
    if (closeBtn) closeBtn.onclick = onClose;

    setStepState('disclaimer', needsDisclaimer ? 'current' : 'done');
    setStepState('storage', needsStorageStep ? 'pending' : 'done');
    setStepState('keys', needsKeys ? 'pending' : 'done');

    if (needsDisclaimer) {
        setStepState('disclaimer', 'current');
        const wrap = document.createElement('div');
        wrap.className = 'space-y-3 text-sm text-dark-300';

        const intro = document.createElement('p');
        intro.className = 'text-xs text-dark-500';
        intro.textContent = 'Step 1/3 · Please review and accept the Terms & Conditions to continue.';
        wrap.appendChild(intro);

        const md = document.createElement('div');
        md.className = 'space-y-3';
        renderDisclaimerMarkdown(disclaimerState?.disclaimerTextMd || '', md);
        wrap.appendChild(md);

        renderStepContent(wrap);

        await new Promise((resolve, reject) => {
            const onAbort = () => reject(new Error('Onboarding cancelled'));
            abort.signal.addEventListener('abort', onAbort, { once: true });

            const decline = makeButton({
                text: 'Decline',
                variant: 'danger',
                onClick: () => {
                    onClose();
                    reject(new Error('Terms & Conditions must be accepted to use this service.'));
                },
            });
            const accept = makeButton({
                text: 'Accept',
                variant: 'primary',
                onClick: async () => {
                    try {
                        setError('');
                        accept.disabled = true;
                        decline.disabled = true;
                        setButtonLoading?.('Accepting Terms & Conditions…');
                        await client.acceptDisclaimer(address, disclaimerState?.disclaimerHashHex || '');
                        abort.signal.removeEventListener('abort', onAbort);
                        resolve();
                    } catch (e) {
                        accept.disabled = false;
                        decline.disabled = false;
                        setError(e?.message || 'Failed to accept Terms & Conditions');
                    }
                },
            });

            renderActions([decline, accept]);
        });

        if (cancelled) throw new Error('Onboarding cancelled');
        setStepState('disclaimer', 'done');
    }

    if (needsStorageStep) {
        setStepState('storage', 'current');
        // Mark as prompted before showing UI to avoid repeated prompts if anything throws.
        setPersistPromptedFlag();
        renderStepContent(`
            <div class="space-y-3 text-sm text-dark-300">
                <p class="text-xs text-dark-500">Step 2/3 · Optional, but recommended.</p>
                <h3 class="text-base font-semibold text-dark-100">Enable durable storage?</h3>
                <p>
                    This app stores your local database in the browser (SQLite via OPFS).
                    Without durable storage, the browser may delete it under storage pressure.
                </p>
                <p class="text-xs text-dark-500">
                    Durable storage helps prevent eviction, but clearing site data will still remove it.
                </p>
            </div>
        `);

        await new Promise((resolve) => {
            const onAbort = () => resolve();
            abort.signal.addEventListener('abort', onAbort, { once: true });

            const notNow = makeButton({
                text: 'Not now',
                variant: 'secondary',
                onClick: () => {
                    abort.signal.removeEventListener('abort', onAbort);
                    resolve();
                },
            });

            const enable = makeButton({
                text: 'Enable durable storage',
                variant: 'primary',
                onClick: async () => {
                    try {
                        setError('');
                        notNow.disabled = true;
                        enable.disabled = true;
                        setButtonLoading?.('Requesting durable storage…');
                        let granted = false;
                        try {
                            granted = await navigator.storage.persist();
                        } catch (e) {
                            console.debug('[Storage] navigator.storage.persist() failed:', e);
                        }
                        if (!granted) {
                            setError('Browser did not grant durable storage. You can continue, but data may be evicted under storage pressure.');
                        }
                        abort.signal.removeEventListener('abort', onAbort);
                        resolve();
                    } catch (e) {
                        notNow.disabled = false;
                        enable.disabled = false;
                        setError(e?.message || 'Failed to request durable storage');
                    }
                },
            });

            renderActions([notNow, enable]);
        });

        if (cancelled) throw new Error('Onboarding cancelled');
        setStepState('storage', 'done');
    }

    let keys = existingKeys;
    if (needsKeys) {
        setStepState('keys', 'current');

        const wrap = document.createElement('div');
        wrap.className = 'space-y-3 text-sm text-dark-300';

        const intro = document.createElement('p');
        intro.className = 'text-xs text-dark-500';
        intro.textContent = 'Step 3/3 · Create your privacy keys.';
        wrap.appendChild(intro);

        const title = document.createElement('h3');
        title.className = 'text-base font-semibold text-dark-100';
        title.textContent = 'Derive privacy keys (2 signatures)';
        wrap.appendChild(title);

        const p1 = document.createElement('p');
        p1.textContent =
            'We ask Freighter to sign two messages. These signatures derive your privacy keys locally (spending key + encryption key). This does not move funds.';
        wrap.appendChild(p1);

        const p2 = document.createElement('p');
        p2.className = 'text-xs text-dark-500';
        p2.textContent =
            'Tip: starting this from a button click helps some browsers keep Freighter in its normal overlay window.';
        wrap.appendChild(p2);

        const progress = document.createElement('p');
        progress.id = 'onboarding-progress';
        progress.className = 'text-xs text-dark-400';
        progress.textContent = 'Ready.';
        wrap.appendChild(progress);

        renderStepContent(wrap);

        await new Promise((resolve, reject) => {
            const onAbort = () => reject(new Error('Onboarding cancelled'));
            abort.signal.addEventListener('abort', onAbort, { once: true });

            const deriveBtn = makeButton({
                text: 'Derive privacy keys',
                variant: 'primary',
                onClick: async () => {
                    try {
                        setError('');
                        deriveBtn.disabled = true;
                        progress.textContent = 'Starting…';
                        const derived = await deriveKeysFromWallet(address, {
                            onStatus: (msg) => {
                                if (msg) progress.textContent = msg;
                                setButtonLoading?.(msg);
                            },
                            signOptions: { address },
                            signDelay: 300,
                            skipCacheCheck: true,
                        });
                        keys = {
                            noteKeypair: { private: derived.privKey, public: derived.pubKey },
                            encryptionKeypair: derived.encryptionKeypair,
                        };
                        abort.signal.removeEventListener('abort', onAbort);
                        resolve();
                    } catch (e) {
                        deriveBtn.disabled = false;
                        setError(e?.message || 'Failed to derive privacy keys');
                    }
                },
            });

            renderActions([deriveBtn]);
        });

        if (cancelled) throw new Error('Onboarding cancelled');
        if (!keys) throw new Error('Privacy keys not ready yet. Please try again.');
        setStepState('keys', 'done');
    }

    hideModal();

    const final = keys || (await client.getUserKeys(address));
    if (!final) throw new Error('Privacy keys not available');

    return {
        privKey: final.noteKeypair.private,
        pubKey: final.noteKeypair.public,
        encryptionKeypair: {
            publicKey: final.encryptionKeypair.public,
            privateKey: final.encryptionKeypair.private,
        },
    };
}
