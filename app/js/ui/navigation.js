import { connectWallet, getWalletNetwork, startWalletWatcher } from '../wallet.js';
import { createWalletSessionMonitor, requireTestnetNetwork, UNREADABLE_WALLET_MESSAGE } from '../wallet-session-policy.js';
import { FreighterSigner } from 'stellar-private-payments/freighter';
import { DEFAULT_BOOTNODE_URL } from '../app-storage.js';
import { client, initializeRuntime, disposeClient, bootnodeRequired, ensureStorage, configureTelemetrySettings, dumpTelemetryLogs, debugLogsEnabled, isRuntimeReady } from '../wasm-facade.js';
import { App, Toast, Utils } from './core.js';
import {
    closeAppPool,
    createAppPool,
    hasInFlightPoolOps,
    waitForPoolOpsToDrain,
    waitForPoolOpsToDrainNotified,
    beginPoolOp,
    endPoolOp,
} from './pool.js';
import { runOnboardingWizard } from './onboarding-wizard.js';
import { runConnectStages } from '../connect-pipeline.js';
import { isDbLockedError, showDbLockedModal } from '../db-locked.js';

const HIDDEN_SECRET_PLACEHOLDER = '••••••••••••';
let revealedAspSecret = null;

function clearRevealedAspSecret() {
    revealedAspSecret = null;
    const revealBtn = document.getElementById('settings-reveal-secret');
    if (revealBtn) revealBtn.dataset.revealed = 'false';
}

async function fetchAspSecretForUser() {
    if (!App.state.keys.notePublicKey) {
        throw new Error('Still connecting to your wallet. Please wait a moment and try again.');
    }
    const secret = await client().account().aspSecret();
    return secret != null ? String(secret) : null;
}

function showBootnodeConsentModal({ defaultUrl, rpcUrl, errorMessage }) {
    const modal = document.getElementById('bootnode-consent-modal');
    const urlInput = document.getElementById('bootnode-consent-url');
    const errorEl = document.getElementById('bootnode-consent-error');
    const acceptBtn = document.getElementById('bootnode-consent-accept');
    const cancelBtn = document.getElementById('bootnode-consent-cancel');
    const closeBtn = document.getElementById('bootnode-consent-close');
    const rpcUrlEl = document.getElementById('bootnode-consent-rpc-url');
    const detailsEl = document.getElementById('bootnode-consent-details');

    errorEl.textContent = '';
    errorEl.classList.add('hidden');
    urlInput.value = defaultUrl || '';
    rpcUrlEl.textContent = rpcUrl || '';
    detailsEl.textContent = errorMessage || '';
    modal.classList.remove('hidden');

    return new Promise(resolve => {
        const cleanup = (accepted = false) => {
            acceptBtn.removeEventListener('click', onAccept);
            cancelBtn.removeEventListener('click', onCancel);
            closeBtn.removeEventListener('click', onCancel);
            modal.classList.add('hidden');
            resolve(accepted ? { accepted: true, url: urlInput.value.trim() } : { accepted: false });
        };
        const onCancel = () => cleanup(false);
        const onAccept = () => {
            if (urlInput.value.trim() && !urlInput.value.trim().startsWith('https://')) {
                errorEl.textContent = 'Bootnode URL must start with https://';
                errorEl.classList.remove('hidden');
                return;
            }
            cleanup(true);
        };
        acceptBtn.addEventListener('click', onAccept);
        cancelBtn.addEventListener('click', onCancel);
        closeBtn.addEventListener('click', onCancel);
    });
}

let disclosureLoaded = false;

function setActiveView(view) {
    const currentHashView = window.location.hash.split('?')[0];
    if (currentHashView !== `#${view}`) {
        window.history.replaceState(null, '', `#${view}`);
    }
    App.state.views.active = view;
    document.querySelectorAll('[data-view]').forEach(btn => {
        const active = btn.dataset.view === view;
        btn.classList.toggle('bg-cyan-400/15', active);
        btn.classList.toggle('text-cyan-100', active);
        btn.classList.toggle('text-slate-400', !active);
        btn.dataset.state = active ? 'active' : 'inactive';
        if (active) btn.setAttribute('aria-current', 'page');
        else btn.removeAttribute('aria-current');
    });
    document.querySelectorAll('.view-panel').forEach(panel => {
        const active = panel.dataset.viewPanel === view;
        panel.classList.toggle('hidden', !active);
        panel.dataset.state = active ? 'active' : 'inactive';
        panel.setAttribute('aria-hidden', String(!active));
    });

    if (view === 'disclosure' && !disclosureLoaded) {
        disclosureLoaded = true;
        import('../disclosure.js').then(m => {
            if (m.initDisclosure) m.initDisclosure();
        }).catch(err => {
            console.error('Failed to load disclosure.js', err);
            disclosureLoaded = false;
        });
    }
}

function setMoveFlow(flow) {
    App.state.views.moveFlow = flow;
    document.querySelectorAll('[data-move-flow]').forEach(btn => {
        const active = btn.dataset.moveFlow === flow;
        btn.classList.toggle('bg-cyan-400', active);
        btn.classList.toggle('text-slate-950', active);
        btn.classList.toggle('text-slate-300', !active);
        btn.dataset.state = active ? 'active' : 'inactive';
        btn.setAttribute('aria-pressed', String(active));
    });
    document.querySelectorAll('.move-flow-panel').forEach(panel => {
        const active = panel.dataset.movePanel === flow;
        panel.classList.toggle('hidden', !active);
        panel.dataset.state = active ? 'active' : 'inactive';
        panel.setAttribute('aria-hidden', String(!active));
    });
}

async function bootnodeCheck(rpcUrl, address) {
    const storage = await ensureStorage();
    // The archive endpoint is account-scoped. Passed explicitly rather
    // than read from App.state here, so the caller is forced to have an
    // account in hand before this can ask for one account's bootnode.
    const stored = await storage.getStoredBootnodeUrl(address);
    const required = await bootnodeRequired(rpcUrl);

    if (required && !stored) {
        const modal = await showBootnodeConsentModal({
            defaultUrl: stored || DEFAULT_BOOTNODE_URL,
            rpcUrl,
            errorMessage: 'RPC sync gap: configure a bootnode to sync historical events',
        });
        if (!modal.accepted || !modal.url) {
            throw new Error('RPC_SYNC_GAP: bootnode required');
        }
        await storage.setBootnodeConfig(modal.url, address);
    }

    return { bootnodeRequired: required };
}

async function loadRuntimeState() {
    const config = client().contractConfig();
    App.state.pools = (config?.pools || []).filter(pool => pool.enabled);
    App.state.selectedPoolId = App.state.selectedPoolId || App.state.pools[0]?.poolContractId || null;
    const poolSelects = document.querySelectorAll('[data-pool-select]');
    poolSelects.forEach(select => {
        select.replaceChildren();
        App.state.pools.forEach(pool => {
            const option = document.createElement('option');
            option.value = pool.poolContractId;
            option.textContent = Utils.poolLabel(pool);
            select.appendChild(option);
        });
        select.value = App.state.selectedPoolId || '';
    });

    const storage = client().storage();
    const explorerSetting = await storage.getExplorerSetting();
    App.state.settings.explorerBaseUrl = explorerSetting?.baseUrl || Utils.defaultExplorerBaseUrl;

    // Both are account-scoped, so they follow whichever account is live
    // now. loadRuntimeState() runs after the post-wizard hand-off, by which
    // point App.state.wallet.address is the re-bound account if the user
    // switched mid-wizard -- reading it here rather than a captured
    // value is what makes these settings follow the re-bind.
    const settingsAddress = App.state.wallet.address;
    const bootnodeSetting = await storage.getBootnodeConfig(settingsAddress);
    App.state.settings.bootnode = bootnodeSetting || { enabled: false, url: '' };

    const telemetrySetting = await storage.getTelemetryConfig(settingsAddress);
    App.state.settings.telemetry = telemetrySetting || { level: 'info', revealSensitive: false };
    try {
        await configureTelemetrySettings({
            level: App.state.settings.telemetry.level,
            revealSensitive: App.state.settings.telemetry.revealSensitive,
        });
    } catch (e) {
        console.warn('Failed to configure telemetry:', e);
    }

    App.events.dispatchEvent(new CustomEvent('pool:config'));
    App.events.dispatchEvent(new CustomEvent('settings:updated'));
}

function renderWallet() {
    const connected = App.state.wallet.connected;
    const walletText = document.getElementById('wallet-text');
    const walletBtn = document.getElementById('wallet-btn');
    const walletAddress = document.getElementById('settings-wallet-address');
    walletText.textContent = connected ? Utils.shortAddress(App.state.wallet.address, 8, 6) : '';
    walletText.classList.toggle('hidden', !connected);
    walletBtn?.classList.toggle('hidden', connected);
    walletAddress.textContent = App.state.wallet.address || 'Not connected';
    document.getElementById('network-name').textContent = App.state.wallet.network?.toUpperCase() || 'NETWORK';
    renderSyncStatus();
}

// Sync indicator lives inside the network pill: grey/Offline when disconnected,
// pulsing amber/Syncing until the registry is caught up, green/Synced after.
function renderSyncStatus() {
    const dot = document.getElementById('sync-dot');
    const text = document.getElementById('sync-status');
    if (!dot || !text) return;
    if (!App.state.wallet.connected) {
        text.textContent = 'Offline';
        dot.className = 'h-2 w-2 rounded-full bg-slate-500';
        return;
    }
    const synced = !!App.state.profile?.registryLookup?.registryFullySynced;
    text.textContent = synced ? 'Synced' : 'Syncing';
    dot.className = synced
        ? 'h-2 w-2 rounded-full bg-emerald-400 shadow-[0_0_18px_rgba(52,211,153,0.7)]'
        : 'h-2 w-2 rounded-full bg-amber-300 animate-pulse-dot';
}

function renderSettingsDrawer() {
    document.getElementById('settings-note-key').textContent = App.state.keys.notePublicKey || '—';
    document.getElementById('settings-enc-key').textContent = App.state.keys.encryptionPublicKey || '—';
    const hasKeys = !!App.state.keys.notePublicKey;
    const aspMasked = hasKeys ? HIDDEN_SECRET_PLACEHOLDER : '—';
    const aspValue = document.getElementById('settings-asp-secret');
    const revealBtn = document.getElementById('settings-reveal-secret');
    const revealed = revealBtn?.dataset.revealed === 'true';
    aspValue.textContent = revealed ? (revealedAspSecret || '—') : aspMasked;
    revealBtn?.classList.toggle('hidden', !hasKeys);
    revealBtn?.querySelector('.settings-eye')?.classList.toggle('hidden', revealed);
    revealBtn?.querySelector('.settings-eye-off')?.classList.toggle('hidden', !revealed);
    if (revealBtn) revealBtn.title = revealed ? 'Hide ASP secret' : 'Reveal ASP secret';
    document.getElementById('settings-registration-status').textContent = App.state.profile.registered ? 'Registered' : 'Not registered';
    const registerBtn = document.getElementById('settings-register-btn');
    if (registerBtn) {
        registerBtn.disabled = App.state.profile.registered;
        registerBtn.textContent = App.state.profile.registered ? 'Registered' : 'Register now';
    }
    document.getElementById('settings-explorer-input').value = App.state.settings.explorerBaseUrl || Utils.defaultExplorerBaseUrl;
    document.getElementById('settings-bootnode-enabled').checked = !!App.state.settings.bootnode?.enabled;
    document.getElementById('settings-bootnode-url').value = App.state.settings.bootnode?.url || '';
    document.getElementById('settings-log-level').value = App.state.settings.telemetry?.level || 'info';
    document.getElementById('settings-reveal-sensitive').checked = !!App.state.settings.telemetry?.revealSensitive;
    // Production release compiles out debug/trace logging and sensitive
    // reveal; disable those controls when the build doesn't support them.
    const debugSupported = debugLogsEnabled();
    document.querySelectorAll('#settings-log-level option').forEach((opt) => {
        if (opt.value !== 'info') {
            opt.disabled = !debugSupported;
            opt.title = debugSupported ? '' : 'Requires a debug (release-with-logs) build';
        }
    });
    const revealSensitiveInput = document.getElementById('settings-reveal-sensitive');
    if (revealSensitiveInput) {
        revealSensitiveInput.disabled = !debugSupported;
        revealSensitiveInput.title = debugSupported ? '' : 'Requires a debug (release-with-logs) build';
    }
}

export const Shell = {
    init() {
        document.querySelectorAll('[data-view]').forEach(btn => btn.addEventListener('click', () => setActiveView(btn.dataset.view)));
        document.getElementById('home-link')?.addEventListener('click', () => setActiveView('dashboard'));
        document.querySelectorAll('[data-move-flow]').forEach(btn => btn.addEventListener('click', () => setMoveFlow(btn.dataset.moveFlow)));
        document.querySelectorAll('[data-pool-select]').forEach(select => {
            select.addEventListener('change', () => {
                App.state.selectedPoolId = select.value;
                document.querySelectorAll('[data-pool-select]').forEach(other => {
                    if (other !== select) other.value = select.value;
                });
                App.events.dispatchEvent(new CustomEvent('pool:selected', { detail: { poolId: select.value } }));
            });
        });
        document.getElementById('open-settings-btn')?.addEventListener('click', () => Wallet.openSettings());
        document.getElementById('settings-close-btn')?.addEventListener('click', () => Wallet.closeSettings());
        document.getElementById('settings-overlay')?.addEventListener('click', () => Wallet.closeSettings());
        document.addEventListener('keydown', (event) => {
            if (event.key === 'Escape' && App.state.ui.settingsOpen) {
                Wallet.closeSettings();
            }
        });
        document.getElementById('settings-save-btn')?.addEventListener('click', () => Wallet.saveSettings());
        document.getElementById('settings-register-btn')?.addEventListener('click', () => Wallet.registerPublicKey());
        document.getElementById('wallet-disconnect-btn')?.addEventListener('click', () => Wallet.disconnect());
        document.getElementById('settings-copy-logs-btn')?.addEventListener('click', async () => {
            try {
                const logs = await dumpTelemetryLogs();
                await navigator.clipboard.writeText(logs);
                Toast.show('Diagnostic logs copied to clipboard', 'success');
            } catch (error) {
                Toast.show('Failed to copy logs: ' + error.message, 'error');
            }
        });
        document.getElementById('settings-download-logs-btn')?.addEventListener('click', async () => {
            try {
                const logs = await dumpTelemetryLogs();
                const blob = new Blob([logs], { type: 'text/plain;charset=utf-8' });
                const url = URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.href = url;
                a.download = 'spp-diagnostics.log';
                document.body.appendChild(a);
                a.click();
                document.body.removeChild(a);
                URL.revokeObjectURL(url);
                Toast.show('Diagnostic logs download started', 'success');
            } catch (error) {
                Toast.show('Failed to download logs: ' + error.message, 'error');
            }
        });
        document.getElementById('settings-reveal-secret')?.addEventListener('click', async (e) => {
            const btn = e.currentTarget;
            const revealing = btn.dataset.revealed !== 'true';
            if (revealing) {
                const address = App.state.wallet.address;
                if (!address) return;
                try {
                    revealedAspSecret = await fetchAspSecretForUser();
                    if (!revealedAspSecret) {
                        Toast.show('ASP secret not found', 'error');
                        return;
                    }
                    btn.dataset.revealed = 'true';
                } catch (error) {
                    Toast.show(error?.message || 'Failed to load ASP secret', 'error');
                    return;
                }
            } else {
                clearRevealedAspSecret();
            }
            renderSettingsDrawer();
        });
        // Click any identity value to copy it (copies the real value, even when masked).
        const identityCopyTargets = {
            'settings-wallet-address': () => App.state.wallet.address,
            'settings-note-key': () => App.state.keys.notePublicKey,
            'settings-enc-key': () => App.state.keys.encryptionPublicKey,
            'settings-asp-secret': async () => {
                if (revealedAspSecret) return revealedAspSecret;
                const address = App.state.wallet.address;
                if (!address) return null;
                return fetchAspSecretForUser();
            },
        };
        Object.entries(identityCopyTargets).forEach(([id, getValue]) => {
            document.getElementById(id)?.addEventListener('click', async () => {
                const value = await getValue();
                if (value) Utils.copyToClipboard(value);
            });
        });

        App.events.addEventListener('dashboard:quick-flow', (event) => {
            const { flow, poolId } = event.detail;
            if (poolId) {
                App.state.selectedPoolId = poolId;
                document.querySelectorAll('[data-pool-select]').forEach(select => {
                    select.value = poolId;
                });
            }
            setActiveView('move-funds');
            setMoveFlow(flow);
            App.events.dispatchEvent(new CustomEvent('pool:selected', { detail: { poolId } }));
        });

        App.events.addEventListener('dashboard:view-notes', (event) => {
            const { poolId } = event.detail;
            if (poolId) {
                App.state.selectedPoolId = poolId;
                document.querySelectorAll('[data-pool-select]').forEach(select => {
                    select.value = poolId;
                });
            }
            setActiveView('advanced');
            App.events.dispatchEvent(new CustomEvent('pool:selected', { detail: { poolId } }));
        });

        App.events.addEventListener('dashboard:view-receipt', (event) => {
            const { noteId } = event.detail;
            // This used to also do
            //   history.replaceState(null, '', `#disclosure?commitment=${noteId}`)
            // which put a note commitment -- an identifier for one specific
            // payment -- into session history, browser profile sync and the
            // omnibox, where it outlives the session and syncs to the user's
            // other devices. It was there to cover the case where the
            // disclosure view had not loaded its notes yet; disclosure.js now
            // holds that hand-off in memory instead (pendingNoteSelection).
            setActiveView('disclosure');
            // Give the disclosure view a moment to load if it hasn't already
            setTimeout(() => {
                App.events.dispatchEvent(new CustomEvent('disclosure:select-note', { detail: { noteId } }));
            }, 50);
        });

        App.events.addEventListener('profile:updated', renderSyncStatus);

        window.addEventListener('hashchange', () => {
            const hashStr = window.location.hash.replace('#', '');
            const hashView = hashStr.split('?')[0];
            if (hashView && document.querySelector(`[data-view="${hashView}"]`)) {
                setActiveView(hashView);
            }
        });

        const initialHashStr = window.location.hash.replace('#', '');
        const initialHash = initialHashStr.split('?')[0];
        if (initialHash && document.querySelector(`[data-view="${initialHash}"]`)) {
            setActiveView(initialHash);
        } else {
            setActiveView('dashboard');
        }
        setMoveFlow('deposit');
        renderSyncStatus();
    },
};

export const Wallet = {
    _connectPromise: null,
    _stopWatcher: null,
    // Bumped on connect() and disconnect(). connect() re-checks it after each
    // await so a torn-down session cannot be resurrected, and a new connect()
    // cannot be clobbered by an old one finishing late.
    _sessionEpoch: 0,
    // Guards the watcher's change path against re-entry. Declared here rather
    // than materialised on first assignment so it sits with the other
    // session-lifetime fields.
    _pendingChange: false,

    init() {
        document.getElementById('wallet-btn')?.addEventListener('click', () => {
            if (App.state.wallet.connected) {
                this.openSettings();
            } else {
                this.connect({ auto: false }).catch(() => {});
            }
        });
        renderWallet();
    },

    async connect({ auto = false } = {}) {
        if (this._connectPromise) return this._connectPromise;

        this._connectPromise = (async () => {
            const epoch = ++this._sessionEpoch;
            const superseded = () => this._sessionEpoch !== epoch;
            const signer = new FreighterSigner();

            try {
                const result = await runConnectStages({
                    superseded,
                    setWalletState: (state) => {
                        document.body.dataset.walletState = state;
                    },
                    connectWallet,
                    getNetwork: async () => requireTestnetNetwork(await getWalletNetwork()),
                    publishWallet: ({ address, network, networkPassphrase, sorobanRpcUrl }) => {
                        App.state.wallet.connected = true;
                        App.state.wallet.address = address;
                        App.state.wallet.sorobanRpcUrl = sorobanRpcUrl;
                        App.state.wallet.network = network;
                        App.state.wallet.networkPassphrase = networkPassphrase;
                        renderWallet();
                    },
                    bootnodeCheck,
                    initializeRuntime,
                    startWatcher: () => this.startWatcher(),
                    runOnboardingWizard: (args) => runOnboardingWizard({ ...args, signer }),
                    liveAddress: () => App.state.wallet.address,
                    openAccount: ({ networkPassphrase, userAddress }) =>
                        client().openAccount({ networkPassphrase, userAddress }, signer),
                    backgroundSync: () => client().backgroundSync(),
                    userPublicKeys: () => client().account().userPublicKeys(),
                    publishKeys: (keys) => {
                        App.state.keys.notePublicKey = keys.notePublicKey;
                        App.state.keys.encryptionPublicKey = keys.encryptionPublicKey;
                    },
                    loadRuntimeState,
                    publishReady: ({ address }) => {
                        renderSettingsDrawer();
                        renderWallet();
                        App.events.dispatchEvent(new CustomEvent('wallet:ready', { detail: { address } }));
                    },
                    createAppPool,
                });
                if (result.connected && !auto) Toast.show('Wallet connected', 'success');
            } catch (error) {
                const message = error?.message || '';
                this.disconnect();
                if (isDbLockedError(message)) {
                    // Blocking condition: another tab/window holds the local DB lock.
                    // Surface it even on auto-connect (the common multi-tab trigger).
                    showDbLockedModal(message);
                } else if (!auto) {
                    Toast.show(message || 'Failed to connect wallet', 'error');
                }
                throw error;
            } finally {
                this._connectPromise = null;
            }
        })();

        return this._connectPromise;
    },

    /**
     * End the wallet session for a reason the user must act on.
     *
     * Freezes new wallet-bound work (requireWallet() reads walletState), then
     * waits for anything already running: its OpHistory write still needs the
     * client this teardown nulls out.
     *
     * The try/finally matters — if disconnect() throws, _pendingChange would
     * stay true and mute every later change, including after a reconnect.
     */
    async _endSession(message) {
        if (this._pendingChange) return;
        this._pendingChange = true;
        try {
            document.body.dataset.walletState = 'changing';
            if (hasInFlightPoolOps()) {
                await waitForPoolOpsToDrainNotified({
                    onTimeout: () => console.warn(
                        '[Wallet] pool operations did not drain in time; disconnecting anyway',
                    ),
                });
            }
            this.disconnect();
            Toast.show(message, 'info', 6000);
        } finally {
            this._pendingChange = false;
        }
    },

    startWatcher() {
        if (this._stopWatcher) return;
        // One monitor per watcher, so the unreadable streak cannot outlive the
        // session it belongs to (disconnect() drops the watcher; the next
        // startWatcher() builds a fresh pair).
        const monitor = createWalletSessionMonitor();
        this._stopWatcher = startWalletWatcher({
            intervalMs: 2_000,
            onChange: async (info) => {
                if (!App.state.wallet.connected) return;

                // Detection is shared with admin.js; the response is not.
                const { networkChanged, changed, sessionUnverifiable } =
                    monitor.observe(info, App.state.wallet);

                // The watcher can no longer name the active account, for long
                // enough that this is not a blip. Handled before the lifecycle
                // branches below: the rebind branch cannot rebind to an account
                // it cannot name.
                if (sessionUnverifiable) {
                    await this._endSession(UNREADABLE_WALLET_MESSAGE);
                    return;
                }
                if (!changed) return;

                // 'binding' is the post-wizard hand-off: no wizard on screen
                // to re-point, and a session being bound for one account.
                const state = document.body.dataset.walletState;
                if (state === 'ready' || state === 'binding') {
                    // Past onboarding, both a network change and an account
                    // change end the session; there is no wizard left to
                    // re-point at the new account.
                    await this._endSession(
                        networkChanged
                            ? 'Freighter network changed. Reconnect to continue.'
                            : 'Freighter account changed. Reconnect to continue.',
                    );
                    return;
                }

                // Still onboarding: a network change blocks, but an account
                // change means the user wants THIS account, so re-bind rather
                // than leave the remaining steps written under the old one.
                if (networkChanged) {
                    this.disconnect();
                    Toast.show('Freighter network changed. Reconnect to continue.', 'info', 6000);
                    return;
                }
                App.state.wallet.address = info.address;
                renderWallet();
                App.events.dispatchEvent(new CustomEvent('wallet:account-rebind', { detail: { address: info.address } }));
            },
        });
    },

    disconnect() {
        // Invalidate any connect() still in flight before tearing anything
        // down, so its remaining awaits abort instead of publishing a
        // session over the top of this teardown.
        this._sessionEpoch += 1;
        this._stopWatcher?.();
        this._stopWatcher = null;
        disposeClient();
        closeAppPool();
        clearRevealedAspSecret();
        App.state.wallet = {
            connected: false,
            address: null,
            sorobanRpcUrl: null,
            network: null,
            networkPassphrase: null,
        };
        App.state.keys = { notePublicKey: null, encryptionPublicKey: null };
        // Cleared, not just re-read on the next connect: the settings drawer
        // is reachable while connecting, so a stale value would be shown to the
        // next account. `explorer` is global and stays.
        App.state.settings.bootnode = { enabled: false, url: '' };
        App.state.settings.telemetry = { level: 'info', revealSensitive: false };
        // revealSensitive is a process-global inside the wasm, not part of the
        // client this teardown disposes, so it would stay armed for the next
        // account. Fire-and-forget: it must not reject the teardown.
        void Promise.resolve(
            configureTelemetrySettings({ level: 'info', revealSensitive: false }),
        ).catch((e) => console.warn('[Wallet] failed to reset telemetry posture:', e));
        document.body.dataset.walletState = 'disconnected';
        renderWallet();
        this.closeSettings();
        App.events.dispatchEvent(new CustomEvent('wallet:disconnected'));
    },

    openSettings() {
        App.state.ui.settingsOpen = true;
        document.getElementById('settings-drawer')?.classList.remove('hidden', 'translate-x-full');
        document.getElementById('settings-overlay')?.classList.remove('hidden');
        renderSettingsDrawer();
    },

    closeSettings() {
        App.state.ui.settingsOpen = false;
        document.getElementById('settings-drawer')?.classList.add('hidden', 'translate-x-full');
        document.getElementById('settings-overlay')?.classList.add('hidden');
        clearRevealedAspSecret();
    },

    async saveSettings() {
        try {
            if (!isRuntimeReady()) {
                throw new Error('Still connecting. Please wait a moment and try again.');
            }
            const explorerBaseUrl = document.getElementById('settings-explorer-input')?.value?.trim() || Utils.defaultExplorerBaseUrl;
            const bootnodeEnabled = document.getElementById('settings-bootnode-enabled')?.checked;
            const bootnodeUrl = document.getElementById('settings-bootnode-url')?.value?.trim() || '';
            const debugSupported = debugLogsEnabled();
            const logLevel = debugSupported ? (document.getElementById('settings-log-level')?.value || 'info') : 'info';
            const revealSensitive = debugSupported && !!document.getElementById('settings-reveal-sensitive')?.checked;

            const storage = client().storage();
            // `explorer` is global; bootnode and telemetry are written
            // under the account currently in front of the user.
            const settingsAddress = App.state.wallet.address;
            if (!settingsAddress) {
                throw new Error('Connect a wallet before saving account settings.');
            }
            await storage.setSetting('explorer', { baseUrl: explorerBaseUrl });
            await storage.setSetting('bootnode_config', {
                enabled: !!bootnodeEnabled,
                url: bootnodeEnabled ? bootnodeUrl : '',
            }, settingsAddress);
            await storage.setTelemetryConfig({ level: logLevel, revealSensitive }, settingsAddress);

            App.state.settings.explorerBaseUrl = explorerBaseUrl;
            App.state.settings.bootnode = { enabled: !!bootnodeEnabled, url: bootnodeEnabled ? bootnodeUrl : '' };
            App.state.settings.telemetry = { level: logLevel, revealSensitive };

            await configureTelemetrySettings({
                level: logLevel,
                revealSensitive,
            });

            Toast.show('Settings saved', 'success');
            App.events.dispatchEvent(new CustomEvent('settings:updated'));
        } catch (error) {
            Toast.show(error?.message || 'Failed to save settings', 'error');
        }
    },

    async registerPublicKey() {
        const btn = document.getElementById('settings-register-btn');
        if (btn?.disabled) return; // already in-flight or already registered
        try {
            if (!App.state.wallet.address || !App.state.wallet.networkPassphrase) {
                throw new Error('Connect wallet first');
            }
            if (!App.state.keys.notePublicKey || !App.state.keys.encryptionPublicKey) {
                throw new Error('Privacy keys are not ready yet');
            }

            if (btn) btn.disabled = true; // prevent duplicate registrations
            // registerPublicKeys signs and submits on-chain, so the watcher's
            // drain has to be able to see it.
            beginPoolOp();
            let hash;
            try {
                // No keys passed: the SDK then reads them from storage for the
                // bound account rather than taking whatever the UI last rendered.
                hash = await client().account().registerPublicKeys();
            } finally {
                endPoolOp();
            }
            App.state.profile.registered = true;
            renderSettingsDrawer();
            Toast.show(`Public keys registered: ${Utils.truncateHex(hash, 10, 8)}`, 'success', 7000, {
                linkUrl: Utils.explorerTxUrl(hash),
                linkAriaLabel: 'Open transaction in explorer',
            });
            App.events.dispatchEvent(new CustomEvent('profile:updated'));
        } catch (error) {
            Toast.show(error?.message || 'Registration failed', 'error');
            if (btn) btn.disabled = false; // re-enable so the user can retry
        }
    },
};
