/**
 * Navigation - tab switching and wallet onboarding.
 * @module ui/navigation
 */

import { connectWallet, deriveKeysFromWallet, getWalletNetwork } from '../wallet.js';
import { initializeWasm } from '../wasm-facade.js';
import { App, Utils, Toast } from './core.js';
import { setTabsRef } from './templates.js';

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
            Toast.show('Public key registration is not implemented in this UI yet.', 'info');
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
                await initializeWasm(rpcUrl);
            } catch (e) {
                // Always toast init failures (even on auto-connect) because it's actionable.
                const msg = e?.message || 'Failed to initialize WASM';
                const now = Date.now();
                const last = this._lastInitError || { msg: null, at: 0 };
                if (msg !== last.msg || (now - last.at) > 20_000) {
                    Toast.show(msg, 'error', 20_000);
                    this._lastInitError = { msg, at: now };
                }
                throw e;
            }

            // Ask for two signatures only if keys aren't already stored in WASM storage.
            const keys = await deriveKeysFromWallet(address, {
                onStatus: setButtonLoading,
                signOptions: { address },
                signDelay: 300,
            });

            App.state.keys.notePublicKey = keys?.pubKey || null;
            App.state.keys.encryptionPublicKey = keys?.encryptionKeypair?.publicKey || null;

            if (text) text.textContent = Utils.truncateHex(address, 7, 6);
            if (dropdownIcon) dropdownIcon.classList.remove('hidden');
            if (addressDisplay) addressDisplay.textContent = address;

            updateSubmitButtons(true);
            App.events.dispatchEvent(new CustomEvent('wallet:ready', { detail: { address } }));

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
};
