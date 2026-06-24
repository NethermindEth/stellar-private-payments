import { connectWallet, getWalletNetwork, startWalletWatcher } from '../wallet.js';
import { getHandle, initializeWasm } from '../wasm-facade.js';
import { App, Toast, Utils } from './core.js';
import { runOnboardingWizard } from './onboarding-wizard.js';

function setHidden(el, hidden) {
    el?.classList.toggle('hidden', !!hidden);
}

function isRpcSyncGapError(message) {
    return typeof message === 'string' && (message.startsWith('RPC_SYNC_GAP') || message.includes('RPC sync gap'));
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

function setActiveView(view) {
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

async function loadRuntimeState() {
    const config = await getHandle().webClient.contractConfig();
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

    const explorerSetting = await getHandle().webClient.getExplorerSetting();
    App.state.settings.explorerBaseUrl = explorerSetting?.baseUrl || Utils.defaultExplorerBaseUrl;

    const bootnodeSetting = await getHandle().webClient.getBootnodeConfig();
    App.state.settings.bootnode = bootnodeSetting || { enabled: false, url: '' };

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
}

function renderSettingsDrawer() {
    document.getElementById('settings-note-key').textContent = App.state.keys.notePublicKey || '—';
    document.getElementById('settings-enc-key').textContent = App.state.keys.encryptionPublicKey || '—';
    const aspMasked = App.state.keys.aspSecret ? `${'*'.repeat(12)}${App.state.keys.aspSecret.slice(-6)}` : '—';
    const aspValue = document.getElementById('settings-asp-secret');
    const revealBtn = document.getElementById('settings-reveal-secret');
    const revealed = revealBtn?.dataset.revealed === 'true';
    aspValue.textContent = revealed ? (App.state.keys.aspSecret || '—') : aspMasked;
    document.getElementById('settings-registration-status').textContent = App.state.profile.registered ? 'Registered' : 'Not registered';
    document.getElementById('settings-explorer-input').value = App.state.settings.explorerBaseUrl || Utils.defaultExplorerBaseUrl;
    document.getElementById('settings-bootnode-enabled').checked = !!App.state.settings.bootnode?.enabled;
    document.getElementById('settings-bootnode-url').value = App.state.settings.bootnode?.url || '';
}

export const Shell = {
    init() {
        document.querySelectorAll('[data-view]').forEach(btn => btn.addEventListener('click', () => setActiveView(btn.dataset.view)));
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
        document.getElementById('settings-reveal-secret')?.addEventListener('click', (e) => {
            e.currentTarget.dataset.revealed = e.currentTarget.dataset.revealed === 'true' ? 'false' : 'true';
            renderSettingsDrawer();
        });
        document.getElementById('settings-copy-secret')?.addEventListener('click', () => {
            if (App.state.keys.aspSecret) Utils.copyToClipboard(App.state.keys.aspSecret);
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

        setActiveView('dashboard');
        setMoveFlow('deposit');
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

                let bootnodeRequired = false;
                try {
                    await initializeWasm(rpcUrl);
                } catch (error) {
                    const message = error?.message || 'Failed to initialize app runtime';
                    if (!isRpcSyncGapError(message)) throw error;
                    const modal = await showBootnodeConsentModal({ defaultUrl: '', rpcUrl, errorMessage: message });
                    if (!modal.accepted || !modal.url) throw error;
                    await initializeWasm(rpcUrl, modal.url);
                    await getHandle().webClient.setBootnodeConfig(modal.url);
                    bootnodeRequired = true;
                }

                const keys = await runOnboardingWizard({
                    address,
                    networkPassphrase,
                    bootnodeRequired,
                });
                App.state.keys.notePublicKey = keys?.pubKey || null;
                App.state.keys.encryptionPublicKey = keys?.encryptionKeypair?.publicKey || null;
                App.state.keys.aspSecret = keys?.aspSecret || null;

                await loadRuntimeState();
                renderSettingsDrawer();
                renderWallet();
                App.events.dispatchEvent(new CustomEvent('wallet:ready', { detail: { address } }));
                this.startWatcher();
                if (!auto) Toast.show('Wallet connected', 'success');
            } catch (error) {
                this.disconnect();
                if (!auto) Toast.show(error?.message || 'Failed to connect wallet', 'error');
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
        App.state.wallet = {
            connected: false,
            address: null,
            sorobanRpcUrl: null,
            network: null,
            networkPassphrase: null,
        };
        App.state.keys = { notePublicKey: null, encryptionPublicKey: null, aspSecret: null };
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
    },

    async saveSettings() {
        try {
            const explorerBaseUrl = document.getElementById('settings-explorer-input')?.value?.trim() || Utils.defaultExplorerBaseUrl;
            const bootnodeEnabled = document.getElementById('settings-bootnode-enabled')?.checked;
            const bootnodeUrl = document.getElementById('settings-bootnode-url')?.value?.trim() || '';

            await getHandle().webClient.setSetting('explorer', { baseUrl: explorerBaseUrl });
            await getHandle().webClient.setSetting('bootnode_config', {
                enabled: !!bootnodeEnabled,
                url: bootnodeEnabled ? bootnodeUrl : '',
            });

            App.state.settings.explorerBaseUrl = explorerBaseUrl;
            App.state.settings.bootnode = { enabled: !!bootnodeEnabled, url: bootnodeEnabled ? bootnodeUrl : '' };
            Toast.show('Settings saved', 'success');
            App.events.dispatchEvent(new CustomEvent('settings:updated'));
        } catch (error) {
            Toast.show(error?.message || 'Failed to save settings', 'error');
        }
    },

    async registerPublicKey() {
        try {
            if (!App.state.wallet.address || !App.state.wallet.networkPassphrase) {
                throw new Error('Connect wallet first');
            }
            if (!App.state.keys.notePublicKey || !App.state.keys.encryptionPublicKey) {
                throw new Error('Privacy keys are not ready yet');
            }

            const hash = await getHandle().webClient.registerPublicKeys(
                App.state.wallet.address,
                App.state.keys.notePublicKey,
                App.state.keys.encryptionPublicKey,
                App.state.wallet.networkPassphrase,
                null,
            );
            App.state.profile.registered = true;
            renderSettingsDrawer();
            Toast.show(`Public keys registered: ${Utils.truncateHex(hash, 10, 8)}`, 'success', 7000, {
                linkUrl: Utils.explorerTxUrl(hash),
                linkAriaLabel: 'Open transaction in explorer',
            });
            App.events.dispatchEvent(new CustomEvent('profile:updated'));
        } catch (error) {
            Toast.show(error?.message || 'Registration failed', 'error');
        }
    },
};
