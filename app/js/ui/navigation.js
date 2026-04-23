/**
 * Navigation - tab switching and wallet onboarding.
 * @module ui/navigation
 */

import { connectWallet, getWalletNetwork, startWalletWatcher } from '../wallet.js';
import { getHandle, initializeWasm } from '../wasm-facade.js';
import { submitPublicKeyRegistration } from '../stellar.js';
import { App, Utils, Toast } from './core.js';
import { setTabsRef } from './templates.js';
import { runOnboardingWizard } from './onboarding-wizard.js';

const BOOTNODE_ENABLED_KEY = 'poolstellar_bootnode_enabled';
const BOOTNODE_URL_KEY = 'poolstellar_bootnode_url';
const DEFAULT_BOOTNODE_URL_TESTNET = 'https://bootnode.testnet.poolstellar.org';

function getBootnodeSettings() {
    try {
        const enabled = window.localStorage.getItem(BOOTNODE_ENABLED_KEY) === '1';
        const url = window.localStorage.getItem(BOOTNODE_URL_KEY) || DEFAULT_BOOTNODE_URL_TESTNET;
        return { enabled, url };
    } catch {
        return { enabled: false, url: DEFAULT_BOOTNODE_URL_TESTNET };
    }
}

function setBootnodeSettings({ enabled, url }) {
    try {
        window.localStorage.setItem(BOOTNODE_ENABLED_KEY, enabled ? '1' : '0');
        if (url) window.localStorage.setItem(BOOTNODE_URL_KEY, url);
    } catch {
        // ignore
    }
}

function isRpcSyncGapError(message) {
    return typeof message === 'string' && message.startsWith('RPC_SYNC_GAP');
}

function showBootnodeConsentModal({ defaultUrl, rpcUrl, errorMessage }) {
    const existing = document.getElementById('bootnode-consent-modal');
    if (existing) existing.remove();

    const overlay = document.createElement('div');
    overlay.id = 'bootnode-consent-modal';
    overlay.className = 'fixed inset-0 z-50';
    overlay.innerHTML = `
      <div class="absolute inset-0 bg-black/70"></div>
      <div class="relative min-h-full flex items-center justify-center p-4">
        <div class="w-full max-w-2xl bg-dark-900 border border-dark-700 rounded-xl shadow-xl">
          <div class="px-5 py-4 border-b border-dark-700 flex items-center justify-between gap-3">
            <h2 class="text-lg font-semibold text-dark-100">Use bootnode to recover history?</h2>
            <button id="bootnode-consent-close" type="button" class="p-1 text-dark-400 hover:text-dark-200 transition-colors" aria-label="Close">
              <svg class="w-5 h-5" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>
            </button>
          </div>
          <div class="px-5 py-4 space-y-3 text-sm text-dark-200">
            <p>Your current RPC node cannot serve historical events back to the contract deployment ledger (RPC retention window).</p>
            <div class="p-3 bg-dark-800 border border-dark-700 rounded-lg space-y-2">
              <p class="text-dark-100 font-semibold">Trust assumptions</p>
              <ul class="list-disc pl-5 space-y-1 text-dark-300">
                <li>The bootnode can omit, censor, or serve incorrect historical event data.</li>
                <li>The bootnode operator can observe your IP address and request timing.</li>
                <li>Near the chain tip, the bootnode will redirect requests to your upstream RPC.</li>
              </ul>
              <p class="text-xs text-dark-400">Learn more: <a class="text-brand-400 hover:text-brand-300 underline underline-offset-2" href="docs/bootnode.html" target="_blank" rel="noreferrer noopener">Bootnode docs</a></p>
            </div>
            <label class="block text-xs text-dark-400">Bootnode URL (indexer only)</label>
            <input id="bootnode-consent-url" type="text" class="w-full px-3 py-2 bg-dark-700 border border-dark-600 rounded font-mono text-xs text-dark-100 focus:outline-none focus:border-brand-500" />
            <p class="text-xs text-dark-500 break-words">Wallet RPC (unchanged): <span class="font-mono">${rpcUrl || ''}</span></p>
            <details class="text-xs text-dark-500">
              <summary class="cursor-pointer select-none">Show technical details</summary>
              <pre class="mt-2 p-3 bg-dark-950 border border-dark-800 rounded whitespace-pre-wrap break-words">${(errorMessage || '').replaceAll('<', '&lt;')}</pre>
            </details>
            <p id="bootnode-consent-error" class="hidden text-xs text-red-400"></p>
          </div>
          <div class="px-5 py-4 border-t border-dark-700 flex flex-col sm:flex-row gap-3 sm:justify-end">
            <button id="bootnode-consent-cancel" type="button" class="px-4 py-2 rounded-lg border border-dark-600 bg-dark-800 text-dark-200 hover:bg-dark-700 transition-colors">Cancel</button>
            <button id="bootnode-consent-accept" type="button" class="px-4 py-2 rounded-lg bg-brand-500 text-dark-950 font-semibold hover:bg-brand-400 transition-colors">Use bootnode</button>
          </div>
        </div>
      </div>
    `;

    document.body.appendChild(overlay);

    const urlInput = overlay.querySelector('#bootnode-consent-url');
    const errorEl = overlay.querySelector('#bootnode-consent-error');
    const acceptBtn = overlay.querySelector('#bootnode-consent-accept');
    const cancelBtn = overlay.querySelector('#bootnode-consent-cancel');
    const closeBtn = overlay.querySelector('#bootnode-consent-close');

    if (urlInput) urlInput.value = defaultUrl || '';

    return new Promise((resolve) => {
        const cleanup = () => {
            acceptBtn?.removeEventListener('click', onAccept);
            cancelBtn?.removeEventListener('click', onCancel);
            closeBtn?.removeEventListener('click', onCancel);
            overlay.remove();
        };

        const onCancel = () => {
            cleanup();
            resolve({ accepted: false, url: null });
        };

        const onAccept = () => {
            const url = (urlInput?.value || '').trim();
            if (!url.startsWith('https://')) {
                if (errorEl) {
                    errorEl.textContent = 'Bootnode URL must start with https://';
                    errorEl.classList.remove('hidden');
                }
                return;
            }
            cleanup();
            resolve({ accepted: true, url });
        };

        acceptBtn?.addEventListener('click', onAccept);
        cancelBtn?.addEventListener('click', onCancel);
        closeBtn?.addEventListener('click', onCancel);
    });
}

/**
 * Updates the disabled state of all submit buttons and disclaimers based on wallet connection.
 * @param {boolean} connected
 */
function updateSubmitButtons(connected) {
    const modes = ['deposit', 'withdraw', 'transfer', 'transact'];
    for (const mode of modes) {
        const btn = document.getElementById(`btn-${mode}`);
        const disclaimer = document.getElementById(`wallet-disclaimer-${mode}`);
        if (btn) btn.disabled = !connected;
        if (disclaimer) disclaimer.classList.toggle('hidden', connected);
    }
}

export const Tabs = {
    init() {
        document.querySelectorAll('.tab-btn').forEach(btn => {
            btn.addEventListener('click', () => this.switch(btn.dataset.tab));
        });
        setTabsRef(this);
    },

    switch(tabId) {
        App.state.activeTab = tabId;

        document.querySelectorAll('.tab-btn').forEach(btn => {
            const isActive = btn.dataset.tab === tabId;
            btn.setAttribute('aria-selected', isActive);
            if (isActive) {
                btn.classList.add('bg-dark-800', 'text-brand-500', 'border', 'border-brand-500/30', 'shadow-lg', 'shadow-brand-500/10');
                btn.classList.remove('text-dark-400', 'hover:text-dark-200', 'hover:bg-dark-800');
            } else {
                btn.classList.remove('bg-dark-800', 'text-brand-500', 'border', 'border-brand-500/30', 'shadow-lg', 'shadow-brand-500/10');
                btn.classList.add('text-dark-400', 'hover:text-dark-200', 'hover:bg-dark-800');
            }
        });

        document.querySelectorAll('.tab-panel').forEach(panel => {
            const isActive = panel.id === `panel-${tabId}`;
            panel.classList.toggle('hidden', !isActive);
        });
    }
};

export const Wallet = {
    dropdownOpen: false,
    _connectPromise: null,
    _lastInitError: { msg: null, at: 0 },
    _stopWatcher: null,
    _walletChangeInFlight: null,

    init() {
        const btn = document.getElementById('wallet-btn');
        const dropdown = document.getElementById('wallet-dropdown');
        const disconnectBtn = document.getElementById('wallet-disconnect-btn');
        const registerBtn = document.getElementById('wallet-register-btn');

        btn?.addEventListener('click', (e) => {
            if (App.state.wallet.connected) {
                e.stopPropagation();
                this.toggleDropdown();
            } else {
                this.connect({ auto: false });
            }
        });

        disconnectBtn?.addEventListener('click', () => {
            this.closeDropdown();
            this.disconnect();
        });

        registerBtn?.addEventListener('click', () => {
            this.closeDropdown();
            this.registerPublicKey().catch(e => {
                Toast.show(e?.message || 'Public key registration failed', 'error', 8000);
            });
        });

        document.addEventListener('click', (e) => {
            if (this.dropdownOpen && !dropdown?.contains(e.target) && e.target !== btn) {
                this.closeDropdown();
            }
        });

        updateSubmitButtons(false);
    },

    toggleDropdown() {
        if (this.dropdownOpen) this.closeDropdown();
        else this.openDropdown();
    },

    openDropdown() {
        const dropdown = document.getElementById('wallet-dropdown');
        const btn = document.getElementById('wallet-btn');
        const dropdownIcon = document.getElementById('wallet-dropdown-icon');
        const addressDisplay = document.getElementById('wallet-dropdown-address');

        if (addressDisplay && App.state.wallet.address) {
            addressDisplay.textContent = App.state.wallet.address;
        }

        dropdown?.classList.remove('hidden');
        btn?.setAttribute('aria-expanded', 'true');
        dropdownIcon?.classList.add('rotate-180');
        this.dropdownOpen = true;
    },

    closeDropdown() {
        const dropdown = document.getElementById('wallet-dropdown');
        const btn = document.getElementById('wallet-btn');
        const dropdownIcon = document.getElementById('wallet-dropdown-icon');

        dropdown?.classList.add('hidden');
        btn?.setAttribute('aria-expanded', 'false');
        dropdownIcon?.classList.remove('rotate-180');
        this.dropdownOpen = false;
    },

    /**
     * Connect to Freighter, assert testnet, initialize WASM, and derive keys.
     * @param {{auto?: boolean}} opts
     */
    async connect({ auto = false } = {}) {
        if (this._connectPromise) return this._connectPromise;

        const btn = document.getElementById('wallet-btn');
        const text = document.getElementById('wallet-text');
        const dropdownIcon = document.getElementById('wallet-dropdown-icon');
        const addressDisplay = document.getElementById('wallet-dropdown-address');
        const networkName = document.getElementById('network-name');

        const setButtonLoading = (msg) => {
            if (text) text.textContent = msg;
            if (btn) btn.disabled = true;
        };

        const run = async () => {
            setButtonLoading('Connecting...');
            const address = await connectWallet();

            const { network, networkPassphrase, sorobanRpcUrl } = await getWalletNetwork();
            const rpcUrl = sorobanRpcUrl || '';

            if (!rpcUrl.toLowerCase().includes('testnet')) {
                Toast.show('This app works only on Stellar testnet. Please switch Freighter to testnet.', 'error', 8000);
                this.disconnect();
                return;
            }

            App.state.wallet.connected = true;
            App.state.wallet.address = address;
            App.state.wallet.sorobanRpcUrl = rpcUrl;
            App.state.wallet.network = network;
            App.state.wallet.networkPassphrase = networkPassphrase;

            if (networkName) networkName.textContent = (network || 'TESTNET').toUpperCase();

            setButtonLoading('Loading WASM...');
            try {
                const bootnode = getBootnodeSettings();
                await initializeWasm(rpcUrl, bootnode.enabled ? bootnode.url : null);
            } catch (e) {
                let msg = e?.message || 'Failed to initialize WASM';
                const bootnode = getBootnodeSettings();

                // Retention-window bootstrap: offer an opt-in bootnode for the indexer only.
                if (isRpcSyncGapError(msg) && !bootnode.enabled) {
                    try {
                        const modal = await showBootnodeConsentModal({
                            defaultUrl: bootnode.url,
                            rpcUrl,
                            errorMessage: msg,
                        });
                        if (modal?.accepted && modal?.url) {
                            setBootnodeSettings({ enabled: true, url: modal.url });
                            setButtonLoading('Loading WASM (bootnode)...');
                            await initializeWasm(rpcUrl, modal.url);
                            msg = null;
                        }
                    } catch (modalErr) {
                        console.debug('[Bootnode] consent flow failed:', modalErr);
                    }
                }

                if (msg) {
                    // Always toast init failures (even on auto-connect) because it's actionable.
                    const now = Date.now();
                    const last = this._lastInitError || { msg: null, at: 0 };
                    if (msg !== last.msg || (now - last.at) > 20_000) {
                        Toast.show(msg, 'error', 20_000);
                        this._lastInitError = { msg, at: now };
                    }
                    throw e;
                }
            }

            setButtonLoading('Onboarding…');
            const keys = await runOnboardingWizard({ address, setButtonLoading });

            App.state.keys.notePublicKey = keys?.pubKey || null;
            App.state.keys.encryptionPublicKey = keys?.encryptionKeypair?.publicKey || null;

            if (text) text.textContent = Utils.truncateHex(address, 7, 6);
            if (dropdownIcon) dropdownIcon.classList.remove('hidden');
            if (addressDisplay) addressDisplay.textContent = address;

            updateSubmitButtons(true);
            App.events.dispatchEvent(new CustomEvent('wallet:ready', { detail: { address } }));

            this._startWatcher();

            if (!auto) {
                Toast.show('Wallet connected. Privacy keys ready.', 'success');
            }
        };

        this._connectPromise = (async () => {
            try {
                await run();
            } catch (e) {
                if (!auto) Toast.show(e?.message || 'Failed to connect wallet', 'error');
                this.disconnect();
                throw e;
            } finally {
                this._connectPromise = null;
                if (btn) btn.disabled = false;
                if (!App.state.wallet.connected && text) text.textContent = 'Connect Freighter';
            }
        })();

        return this._connectPromise;
    },

    disconnect() {
        this._stopWatcher?.();
        this._stopWatcher = null;
        this._walletChangeInFlight = null;

        App.state.wallet.connected = false;
        App.state.wallet.address = null;
        App.state.wallet.sorobanRpcUrl = null;
        App.state.wallet.network = null;
        App.state.wallet.networkPassphrase = null;
        App.state.keys.notePublicKey = null;
        App.state.keys.encryptionPublicKey = null;

        const text = document.getElementById('wallet-text');
        const dropdownIcon = document.getElementById('wallet-dropdown-icon');
        const addressDisplay = document.getElementById('wallet-dropdown-address');
        if (text) text.textContent = 'Connect Freighter';
        if (dropdownIcon) dropdownIcon.classList.add('hidden');
        if (addressDisplay) addressDisplay.textContent = '';

        updateSubmitButtons(false);
        App.events.dispatchEvent(new CustomEvent('wallet:disconnected'));
    }

    ,

    _startWatcher() {
        if (this._stopWatcher) return;

        try {
            this._stopWatcher = startWalletWatcher({
                intervalMs: 2000,
                onChange: (info) => {
                    void this._handleWalletChange(info);
                },
            });
        } catch (e) {
            console.warn('[Wallet] Failed to start watcher:', e);
        }
    },

    async _handleWalletChange(info) {
        if (!App.state.wallet.connected) return;
        if (this._connectPromise) return;
        if (!info || info.error) return;

        const nextAddress = info.address || '';
        const nextNetwork = info.network || '';
        const nextNetworkPassphrase = info.networkPassphrase || '';

        const addressChanged =
            nextAddress &&
            App.state.wallet.address &&
            nextAddress !== App.state.wallet.address;

        const networkChanged =
            (nextNetwork && nextNetwork !== App.state.wallet.network) ||
            (nextNetworkPassphrase && nextNetworkPassphrase !== App.state.wallet.networkPassphrase);

        if (!addressChanged && !networkChanged) return;
        if (this._walletChangeInFlight) return;

        this._walletChangeInFlight = (async () => {
            const btn = document.getElementById('wallet-btn');
            const text = document.getElementById('wallet-text');
            const addressDisplay = document.getElementById('wallet-dropdown-address');
            const networkNameEl = document.getElementById('network-name');

            const setButtonLoading = (msg) => {
                if (text) text.textContent = msg;
                if (btn) btn.disabled = true;
            };

            try {
                setButtonLoading('Wallet changed…');
                updateSubmitButtons(false);

                const { network, networkPassphrase, sorobanRpcUrl } = await getWalletNetwork();
                const rpcUrl = sorobanRpcUrl || App.state.wallet.sorobanRpcUrl || '';

                if (!rpcUrl.toLowerCase().includes('testnet')) {
                    Toast.show('This app works only on Stellar testnet. Please switch Freighter to testnet.', 'error', 8000);
                    this.disconnect();
                    return;
                }

                App.state.wallet.network = network;
                App.state.wallet.networkPassphrase = networkPassphrase;
                App.state.wallet.sorobanRpcUrl = rpcUrl;
                if (networkNameEl) networkNameEl.textContent = (network || 'TESTNET').toUpperCase();

                if (addressChanged) {
                    await this._applyWalletIdentityChange(nextAddress, setButtonLoading);
                } else {
                    if (btn) btn.disabled = false;
                }
            } catch (e) {
                Toast.show(e?.message || 'Wallet changed; failed to re-onboard', 'error', 8000);
                this.disconnect();
            } finally {
                const btn = document.getElementById('wallet-btn');
                if (btn) btn.disabled = false;
            }
        })().finally(() => {
            this._walletChangeInFlight = null;
        });
    },

    async _applyWalletIdentityChange(nextAddress, setButtonLoading) {
        const text = document.getElementById('wallet-text');
        const dropdownIcon = document.getElementById('wallet-dropdown-icon');
        const addressDisplay = document.getElementById('wallet-dropdown-address');

        App.state.wallet.address = nextAddress;
        if (addressDisplay) addressDisplay.textContent = nextAddress;

        setButtonLoading?.('Onboarding new account…');
        const keys = await runOnboardingWizard({ address: nextAddress, setButtonLoading });

        App.state.keys.notePublicKey = keys?.pubKey || null;
        App.state.keys.encryptionPublicKey = keys?.encryptionKeypair?.publicKey || null;

        if (text) text.textContent = Utils.truncateHex(nextAddress, 7, 6);
        if (dropdownIcon) dropdownIcon.classList.remove('hidden');

        updateSubmitButtons(true);
        App.events.dispatchEvent(new CustomEvent('wallet:ready', { detail: { address: nextAddress } }));

        Toast.show('Freighter account changed. Privacy keys ready.', 'info');
    },

    async registerPublicKey() {
        if (!App.state.wallet.connected || !App.state.wallet.address) {
            Toast.show('Please connect your wallet first', 'error');
            return;
        }
        if (!App.state.wallet.sorobanRpcUrl || !App.state.wallet.networkPassphrase) {
            Toast.show('Wallet network details unavailable', 'error');
            return;
        }
        if (!App.state.keys.notePublicKey || !App.state.keys.encryptionPublicKey) {
            Toast.show('Privacy keys not ready yet. Please reconnect your wallet.', 'error', 8000);
            return;
        }

        const registerBtn = document.getElementById('wallet-register-btn');
        const originalText = registerBtn?.textContent || 'Register Public Key';
        const setBtnText = (t) => {
            if (registerBtn) registerBtn.textContent = t;
        };

        try {
            if (registerBtn) registerBtn.disabled = true;
            setBtnText('Registering…');

            const config = await getHandle().webClient.contractConfig();
            const poolContractId = config?.pool;
            if (!poolContractId) throw new Error('Pool contract ID not available');

            const hash = await submitPublicKeyRegistration(
                {
                    address: App.state.wallet.address,
                    rpcUrl: App.state.wallet.sorobanRpcUrl,
                    networkPassphrase: App.state.wallet.networkPassphrase,
                    poolContractId,
                    notePublicKeyHex: App.state.keys.notePublicKey,
                    encryptionPublicKeyHex: App.state.keys.encryptionPublicKey,
                },
                {
                    onStatus: (p) => {
                        const msg = p?.message || '';
                        if (msg) setBtnText(msg);
                    },
                }
            );

            Toast.show(`Public keys registered: ${Utils.truncateHex(hash, 8, 6)}`, 'success', 6000);
            App.events.dispatchEvent(new CustomEvent('addressbook:refresh'));
        } catch (e) {
            if (e?.code === 'USER_REJECTED') {
                Toast.show('Registration cancelled in Freighter', 'error', 6000);
                return;
            }
            throw e;
        } finally {
            setBtnText(originalText);
            if (registerBtn) registerBtn.disabled = false;
        }
    }
};
