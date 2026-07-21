import { connectWallet, getWalletNetwork, startWalletWatcher } from '../wallet.js';
import { FreighterSigner } from 'stellar-private-payments-sdk-web';
import { DEFAULT_BOOTNODE_URL } from '../app-storage.js';
import { client, initializeRuntime, disposeClient, bootnodeRequired, ensureStorage, configureTelemetrySettings, dumpTelemetryLogs } from '../wasm-facade.js';
import { App, Toast, Utils } from './core.js';
import { closeAppPool, createAppPool } from './pool.js';
import { runOnboardingWizard } from './onboarding-wizard.js';
import { isDbLockedError, showDbLockedModal } from '../db-locked.js';

const HIDDEN_SECRET_PLACEHOLDER = '••••••••••••';
let revealedAspSecret = null;

function clearRevealedAspSecret() {
    revealedAspSecret = null;
    const revealBtn = document.getElementById('settings-reveal-secret');
    if (revealBtn) revealBtn.dataset.revealed = 'false';
}

async function fetchAspSecretForUser() {
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
    });
    document.querySelectorAll('.view-panel').forEach(panel => {
        panel.classList.toggle('hidden', panel.dataset.viewPanel !== view);
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
    });
    document.querySelectorAll('.move-flow-panel').forEach(panel => {
        panel.classList.toggle('hidden', panel.dataset.movePanel !== flow);
    });
}

async function bootnodeCheck(rpcUrl) {
    const storage = await ensureStorage();
    const stored = await storage.getStoredBootnodeUrl();
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
        await storage.setBootnodeConfig(modal.url);
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

    const bootnodeSetting = await storage.getBootnodeConfig();
    App.state.settings.bootnode = bootnodeSetting || { enabled: false, url: '' };

    const telemetrySetting = await storage.getSetting('telemetry_config');
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
            window.history.replaceState(null, '', `#disclosure?commitment=${encodeURIComponent(noteId)}`);
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
            const signer = new FreighterSigner();

            try {
                const address = await connectWallet();
                const { network, networkPassphrase, sorobanRpcUrl } = await getWalletNetwork();
                const rpcUrl = sorobanRpcUrl || '';
                if (!rpcUrl.toLowerCase().includes('testnet')) {
                    throw new Error('This app supports Stellar testnet only.');
                }

                App.state.wallet.connected = true;
                App.state.wallet.address = address;
                App.state.wallet.sorobanRpcUrl = rpcUrl;
                App.state.wallet.network = network;
                App.state.wallet.networkPassphrase = networkPassphrase;
                renderWallet();

                const { bootnodeRequired } = await bootnodeCheck(rpcUrl);
                await initializeRuntime(rpcUrl);
                await client().backgroundSync();

                await runOnboardingWizard({
                    address,
                    networkPassphrase,
                    bootnodeRequired,
                    signer,
                });

                await client().openAccount({ networkPassphrase, userAddress: address }, signer);
                const keys = await client().account().userPublicKeys();
                App.state.keys.notePublicKey = keys.notePublicKey;
                App.state.keys.encryptionPublicKey = keys.encryptionPublicKey;

                await loadRuntimeState();
                renderSettingsDrawer();
                renderWallet();
                App.events.dispatchEvent(new CustomEvent('wallet:ready', { detail: { address } }));
                await createAppPool();
                this.startWatcher();
                if (!auto) Toast.show('Wallet connected', 'success');
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

    startWatcher() {
        if (this._stopWatcher) return;
        this._stopWatcher = startWalletWatcher({
            intervalMs: 2_000,
            onChange: async (info) => {
                if (!App.state.wallet.connected || info?.error) return;
                if (info.address && info.address !== App.state.wallet.address) {
                    this.disconnect();
                    Toast.show('Freighter account changed. Reconnect to continue.', 'info', 6000);
                }
            },
        });
    },

    disconnect() {
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
            const explorerBaseUrl = document.getElementById('settings-explorer-input')?.value?.trim() || Utils.defaultExplorerBaseUrl;
            const bootnodeEnabled = document.getElementById('settings-bootnode-enabled')?.checked;
            const bootnodeUrl = document.getElementById('settings-bootnode-url')?.value?.trim() || '';
            const logLevel = document.getElementById('settings-log-level')?.value || 'info';
            const revealSensitive = !!document.getElementById('settings-reveal-sensitive')?.checked;

            const storage = client().storage();
            await storage.setSetting('explorer', { baseUrl: explorerBaseUrl });
            await storage.setSetting('bootnode_config', {
                enabled: !!bootnodeEnabled,
                url: bootnodeEnabled ? bootnodeUrl : '',
            });
            await storage.setSetting('telemetry_config', { level: logLevel, revealSensitive });

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
            const hash = await client().account().registerPublicKeys({
                notePublicKeyHex: App.state.keys.notePublicKey,
                encryptionPublicKeyHex: App.state.keys.encryptionPublicKey,
            });
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
