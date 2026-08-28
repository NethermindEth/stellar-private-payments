import { FreighterSigner } from 'stellar-private-payments/freighter';
import { DEFAULT_BOOTNODE_URL } from '../app-storage.js';
import { client } from '../wasm-facade.js';
import { friendlyErrorForCode } from '../facade-errors.js';
import { App, Utils, Toast } from './core.js';
import { createRebindTracker } from '../onboarding-rebind.js';
import { createStepLifecycle } from '../onboarding-step-lifecycle.js';
import { beginPoolOp, endPoolOp } from './pool.js';
import {
    hasNotificationSupport,
    getNotificationsPrompted,
    setNotificationsPrompted,
    requestNotificationPermission,
} from './push-notifications.js';

const STORAGE_PERSIST_FLAG = 'poolstellar_storage_persist_prompted';
const DEFAULT_EXPLORER_BASE_URL = 'https://stellar.expert/explorer/testnet';
const STEP_ORDER = ['disclaimer', 'retention', 'storage', 'keys', 'explorer', 'registration'];

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

// Accepts either a plain message string (most call sites) or the caught
// error itself, when a call site needs friendlyErrorForCode to see `.code`.
function setError(errorOrMessage) {
    const el = document.getElementById('onboarding-error');
    if (!el) return;
    if (!errorOrMessage) {
        el.textContent = '';
        el.classList.add('hidden');
        return;
    }
    el.textContent = friendlyErrorForCode(errorOrMessage);
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

const HIDDEN_SECRET_PLACEHOLDER = '••••••••••••';

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

// notePublicKey/encryptionPublicKey were deliberately dropped from this
// signature: the bound account now reads its own keys, so accepting them here would
// only re-open the door to registering a value the caller happened to hold.
async function registerNow({ address, networkPassphrase, signer }) {
    if (!networkPassphrase) throw new Error('Missing Stellar network passphrase');
    await client().openAccount({ networkPassphrase, userAddress: address }, signer);
    // Matches the beginPoolOp/endPoolOp wrapping on the Settings registration
    // action (navigation.js), so both sites that sign and submit
    // registerPublicKeys are visible to hasInFlightPoolOps(). This call runs
    // while walletState is 'connecting' or 'binding', where the watcher's
    // disconnect branch is not reachable for an account change -- but a
    // NETWORK change during onboarding calls disconnect() unconditionally with
    // no drain at all.
    beginPoolOp();
    try {
        // See navigation.js. The bound account reads its own keys from
        // storage rather than being handed values from the wizard's closure,
        // which during a mid-wizard re-bind may belong to the account the user
        // switched AWAY from.
        return await client().account().registerPublicKeys();
    } finally {
        endPoolOp();
    }
}

// Thrown (via waitForStep's reject) when the live wallet account changes
// while a step is in flight, so the outer loop in runOnboardingWizard can
// replan against the account the user actually switched to instead of
// finishing a step's write under the account that was active when it
// started.
class AccountRebindSignal extends Error {
    constructor(address) {
        super('Onboarding account changed mid-step');
        this.name = 'AccountRebindSignal';
        this.address = address;
    }
}

async function computeStepPlan(address, { bootnodeRequired }) {
    const storage = client().storage();
    const disclaimerState = await storage.getDisclaimerState(address);
    const storedPublicKeys = await storage.getUserPublicKeys(address).catch(() => null);
    const keysExist = !!storedPublicKeys?.noteKeypair?.public;
    const explorerSetting = await storage.getExplorerSetting();
    // Scoped to the address this plan is being computed for. On a
    // mid-wizard re-bind the plan is recomputed with the new address, so the
    // bootnode shown is the one belonging to the account the user switched to.
    const bootnodeSetting = await storage.getBootnodeConfig(address);
    const registryLookup = await client().recipientLookup(address).catch(() => null);

    const storageAvailable = hasStorageManager();
    const persisted = storageAvailable ? await isPersisted() : false;
    const storagePrompted = storageAvailable ? getPersistPromptedFlag() : true;
    const needsStorageStep = storageAvailable && (!persisted || !storagePrompted);
    const needsNotificationStep = notificationStepNeeded();

    // A missing bootnode record does not mean the user was never asked: the
    // record is per-account, so an already-onboarded account simply has none.
    // Gate on completed onboarding instead. A new account still gets the step,
    // and a real sync gap still forces it via bootnodeRequired.
    const hasCompletedOnboarding = !!disclaimerState?.accepted && keysExist;
    const retentionNeverAsked = !bootnodeSetting && !hasCompletedOnboarding;

    const steps = [
        ...(!disclaimerState?.accepted ? ['disclaimer'] : []),
        ...(needsNotificationStep || retentionNeverAsked || bootnodeRequired ? ['retention'] : []),
        ...(needsStorageStep ? ['storage'] : []),
        ...(!keysExist ? ['keys'] : []),
        [explorerSetting?.baseUrl ? null : 'explorer'].filter(Boolean),
        // Only offer registration when the registry is fully synced AND there's no
        // entry. If the local registry hasn't synced yet, the lookup can't prove the
        // user is unregistered — skip it rather than falsely suggesting registration.
        ...((!registryLookup?.entry && registryLookup?.registryFullySynced) ? ['registration'] : []),
    ].flat();

    const state = {
        keys: keysExist
            ? {
                pubKey: storedPublicKeys.noteKeypair.public,
                encryptionKeypair: { publicKey: storedPublicKeys.encryptionKeypair.public },
            }
            : null,
        explorerBaseUrl: explorerSetting?.baseUrl || DEFAULT_EXPLORER_BASE_URL,
        bootnode: bootnodeSetting || { enabled: false, url: '' },
        registered: !!registryLookup?.entry,
    };

    return { steps, state, disclaimerState, persisted };
}

// Registration is optional (also available later from Settings), so it must
// not, on its own, reopen onboarding on reload. Only required steps
// (disclaimer, durable storage, keys, retention) should trigger the modal —
// e.g. it keeps reappearing while permanent storage hasn't been granted.
const hasRequiredStep = (steps) => steps.some(step => step !== 'registration');

export async function runOnboardingWizard({
    address: initialAddress,
    networkPassphrase,
    bootnodeRequired = false,
    signer = new FreighterSigner(),
} = {}) {
    if (!initialAddress) throw new Error('Wallet address required for onboarding');

    const storage = client().storage();
    let address = initialAddress;
    // Computed inside the replan loop, after subscribing to
    // wallet:account-rebind — computeStepPlan awaits a network lookup, so a
    // switch during it would otherwise go unseen.
    let plan = null;

    let cancelled = false;
    // Owns which step may touch the wizard's shared surface.
    const lifecycle = createStepLifecycle();
    let closeHandler = null;
    let rebindHandler = null;
    // Owns which account onboarding is for and which switch is still
    // outstanding. See app/js/onboarding-rebind.js for why the rules live
    // there rather than as loose variables mutated inline.
    const rebind = createRebindTracker(address);
    let modalShown = false;
    const showModalOnce = () => {
        // Keyed on visibility, not a one-shot flag: cancelOnboarding() hides it.
        const el = document.getElementById('onboarding-modal');
        if (modalShown && el && !el.classList.contains('hidden')) return;
        modalShown = true;
        showModal();
    };
    const cancelOnboarding = () => {
        cancelled = true;
        lifecycle.cancel();
        clearRebindDebounce();
        closeHandler?.();
        hideModal();
    };
    // Static DOM, so this binds fine before the modal is revealed.
    const closeBtn = document.getElementById('onboarding-close-btn');
    closeBtn.onclick = cancelOnboarding;

    // The watcher in navigation.js starts before this wizard opens, per
    // design, specifically so a mid-onboarding account switch is observed
    // here. A switch means the user wants the wallet-bound work (disclaimer,
    // keys, registration) done for the account they switched to, so it
    // aborts whatever step is in flight; the replan loop below recomputes
    // the gate plan for the account actually active now.
    let rebindDebounce = null;
    const clearRebindDebounce = () => {
        if (rebindDebounce) clearTimeout(rebindDebounce);
        rebindDebounce = null;
    };
    const onAccountRebind = (event) => {
        // The tracker decides; this only carries out the timer action. A
        // switch back to the account we are already on returns 'cancel',
        // which is what stops an obsolete switch from firing later.
        const action = rebind.observe(event.detail?.address);
        if (action === 'ignore') return;
        clearRebindDebounce();
        if (action === 'cancel') return;
        // Give a moment for a click already in flight against the current
        // step's UI to land before aborting it out from under that
        // interaction -- the switch is already recorded in the tracker
        // (picked up at the next safe checkpoint even without this timer
        // firing), so this only softens how abruptly an active step's DOM
        // can change mid-click, not how promptly the account switch itself
        // is noticed.
        rebindDebounce = setTimeout(() => {
            rebindDebounce = null;
            const due = rebind.dueAddress();
            if (due) rebindHandler?.(due);
        }, 400);
    };
    App.events.addEventListener('wallet:account-rebind', onAccountRebind);

    // Also cancel on a mid-wizard disconnect (network change, unreadable wallet).
    const onWalletDisconnected = () => cancelOnboarding();
    App.events.addEventListener('wallet:disconnected', onWalletDisconnected);

    const ensureNotCancelled = () => {
        if (cancelled) throw new Error('Onboarding cancelled');
    };

    // setup() gets isLive() as a third argument; a handler must check it
    // before touching shared state, since rejecting the promise doesn't stop it.
    const waitForStep = (setup) => new Promise((resolve, reject) => {
        const token = lifecycle.begin();
        const isLive = () => lifecycle.isLive(token);
        const settle = (finish) => (arg) => {
            if (!isLive()) return;
            lifecycle.retire(token);
            closeHandler = null;
            rebindHandler = null;
            finish(arg);
        };
        closeHandler = () => {
            lifecycle.retire(token);
            closeHandler = null;
            rebindHandler = null;
            reject(new Error('Onboarding cancelled'));
        };
        rebindHandler = (nextAddress) => {
            lifecycle.retire(token);
            closeHandler = null;
            rebindHandler = null;
            reject(new AccountRebindSignal(nextAddress));
        };
        setup(settle(resolve), settle(reject), isLive);
    });

    try {
    // The listener is now live, but the watcher in navigation.js started
    // before this function was called, so a switch may already have landed
    // and been dispatched into the void. Reconcile against live state once,
    // here, rather than trusting the address the caller passed in.
    rebind.observe(App.state.wallet.address);

    replanLoop:
    while (true) {
        ensureNotCancelled();
        // `plan === null` is the first pass; the rest is a replan after a
        // switch. Both compute under the listener, so a switch arriving
        // during the computation is caught by the re-check below instead of
        // being overwritten by a plan built for the previous account.
        const adopted = rebind.adopt();
        if (plan === null || adopted !== null) {
            if (adopted !== null) address = adopted;
            plan = await computeStepPlan(address, { bootnodeRequired });
            ensureNotCancelled();
            if (rebind.dueAddress() !== null) {
                // Switched again while we were computing. Discard this plan
                // rather than acting on one built for a stale account.
                continue replanLoop;
            }
            if (!hasRequiredStep(plan.steps)) {
                break;
            }
            if (adopted !== null) {
                Toast.show('Freighter account changed — continuing onboarding for it.', 'info', 5000);
            }
        }
        // Only a pending value that is no longer a change. Clearing
        // unconditionally here discarded a switch that landed during the
        // replan above.
        rebind.discardStale();
        // Deferred until here so the "nothing to do" break above can return
        // without ever flashing an empty modal.
        showModalOnce();

        const { steps, state, disclaimerState, persisted } = plan;
        STEP_ORDER.forEach(stepId => {
            setStepState(stepId, steps.includes(stepId) ? 'pending' : 'done');
        });

        for (let i = 0; i < steps.length; i += 1) {
        // Per-step checkpoint: a switch recorded since the last step began is
        // acted on here without waiting for the debounce, so the next step
        // never starts under an account the user has left.
        if (rebind.dueAddress() !== null) {
            continue replanLoop;
        }
        const stepId = steps[i];
        setError('');
        steps.forEach((candidate, index) => {
            setStepState(candidate, index < i ? 'done' : index === i ? 'current' : 'pending');
        });
        renderWhy(stepId);

        try {
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

            await waitForStep((resolve, reject, isLive) => {
                const cancel = makeButton({ text: 'Cancel', variant: 'ghost', onClick: cancelOnboarding });
                const accept = makeButton({
                    text: 'Accept disclaimer',
                    variant: 'primary',
                    onClick: async () => {
                        try {
                            accept.disabled = true;
                            await client().openAccount({ networkPassphrase, userAddress: address }, signer);
                            if (!isLive()) return;
                            await storage.acceptDisclaimer(address, disclaimerState?.disclaimerHashHex || '');
                            resolve();
                        } catch (error) {
                            if (!isLive()) return;
                            accept.disabled = false;
                            setError(error || 'Failed to accept disclaimer');
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
            aspField.textContent = state.keys?.pubKey ? HIDDEN_SECRET_PLACEHOLDER : 'Not available';
            secretWrap.querySelector('[data-copy="note"]').addEventListener('click', () => {
                if (state.keys?.pubKey) Utils.copyToClipboard(state.keys.pubKey);
            });
            secretWrap.querySelector('[data-copy="asp"]').addEventListener('click', async () => {
                try {
                    const secret = await client().account().aspSecret();
                    if (secret != null) Utils.copyToClipboard(String(secret));
                } catch (error) {
                    setError(error?.message || 'Failed to load ASP secret');
                }
            });
            const panel = makePanel({
                eyebrow: `Step ${STEP_ORDER.indexOf(stepId) + 1} of ${STEP_ORDER.length}`,
                title: 'Derive note keys and ASP secret',
                body: 'Your wallet is requested to sign one message. That signature derives your privacy keys locally plus your ASP secret. This does not move funds.',
                aside: secretWrap,
            });
            renderContent(panel);

            await waitForStep((resolve, reject, isLive) => {
                const cancel = makeButton({ text: 'Cancel', variant: 'ghost', onClick: cancelOnboarding });
                const derive = makeButton({
                    text: 'Derive and store keys',
                    variant: 'primary',
                    onClick: async () => {
                        try {
                            derive.disabled = true;
                            await client().openAccount(
                                { networkPassphrase, userAddress: address },
                                signer,
                            );
                            const result = await client().account().userPublicKeys();
                            if (!isLive()) return;
                            state.keys = {
                                pubKey: result.notePublicKey,
                                encryptionKeypair: { publicKey: result.encryptionPublicKey },
                            };
                            noteField.textContent = result.notePublicKey;
                            aspField.textContent = HIDDEN_SECRET_PLACEHOLDER;
                            renderActions([makeButton({ text: 'Continue', variant: 'primary', onClick: () => resolve() })]);
                        } catch (error) {
                            if (!isLive()) return;
                            derive.disabled = false;
                            setError(error || 'Failed to derive privacy keys');
                        }
                    },
                });
                renderActions([cancel, derive]);
            });
            ensureNotCancelled();
            continue;
        }

        if (stepId === 'retention') {
            // Snapshotted so a mid-step rebind can't retarget this write.
            const stepAddress = address;
            const enableNotifications = hasNotificationSupport();
            const bootnodeEnabled = bootnodeRequired || !!state.bootnode?.enabled;
            const inputWrap = document.createElement('div');
            inputWrap.className = 'space-y-4';
            const bootnodeBox = document.getElementById('tpl-wizard-bootnode').content.firstElementChild.cloneNode(true);
            const bootnodeEnabledInput = bootnodeBox.querySelector('#wizard-bootnode-enabled');
            bootnodeEnabledInput.checked = bootnodeEnabled;
            bootnodeEnabledInput.disabled = bootnodeRequired;
            bootnodeBox.querySelector('#wizard-bootnode-url').value =
                state.bootnode?.url || DEFAULT_BOOTNODE_URL;
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

            await waitForStep((resolve, reject, isLive) => {
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
                            if (enableNotifications && Notification.permission === 'default') {
                                await requestNotificationPermission();
                            }
                            if (!isLive()) return;
                            await storage.setSetting('bootnode_config', { enabled, url }, stepAddress);
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
                    await storage.setSetting('explorer', { baseUrl });
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
                aside: 'If you skip this step, transfers to you require sharing your note and encryption public keys manually. Registration remains available later from settings. Note: registering publishes your public address to key binding on-chain as an opt-in public event.',

            });
            renderContent(panel);

            await waitForStep((resolve, reject, isLive) => {
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
                            await registerNow({ address, networkPassphrase, signer });
                            if (!isLive()) return;
                            state.registered = true;
                            resolve();
                        } catch (error) {
                            if (!isLive()) return;
                            register.disabled = false;
                            setError(error?.message || 'Failed to register public keys');
                        }
                    },
                });
                renderActions([later, register]);
            });
            ensureNotCancelled();
        }
        } catch (error) {
            if (error instanceof AccountRebindSignal) {
                continue replanLoop;
            }
            throw error;
        }
        }
        break;
    }
    } finally {
        App.events.removeEventListener('wallet:account-rebind', onAccountRebind);
        App.events.removeEventListener('wallet:disconnected', onWalletDisconnected);
        clearRebindDebounce();
    }

    hideModal();
}
