/**
 * Navigation - tab switching and wallet onboarding.
 * @module ui/navigation
 */

import { connectWallet, deriveKeysFromWallet, getWalletNetwork, startWalletWatcher } from '../wallet.js';
import { getHandle, initializeWasm } from '../wasm-facade.js';
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

function showDisclaimerModal({ disclaimerTextMd, onAccept, onDecline }) {
    const modal = document.getElementById('disclaimer-modal');
    const content = document.getElementById('disclaimer-modal-content');
    const errorEl = document.getElementById('disclaimer-modal-error');
    const acceptBtn = document.getElementById('disclaimer-accept-btn');
    const declineBtn = document.getElementById('disclaimer-decline-btn');

    if (!modal || !content || !acceptBtn || !declineBtn || !errorEl) {
        throw new Error('Disclaimer modal is missing from the page');
    }

    errorEl.classList.add('hidden');
    errorEl.textContent = '';
    acceptBtn.disabled = false;
    declineBtn.disabled = false;

    renderDisclaimerMarkdown(disclaimerTextMd, content);
    modal.classList.remove('hidden');

    return new Promise((resolve, reject) => {
        const cleanup = () => {
            acceptBtn.removeEventListener('click', onAcceptClick);
            declineBtn.removeEventListener('click', onDeclineClick);
            modal.classList.add('hidden');
        };

        const onAcceptClick = async () => {
            try {
                acceptBtn.disabled = true;
                declineBtn.disabled = true;
                await onAccept?.();
                cleanup();
                resolve(true);
            } catch (e) {
                acceptBtn.disabled = false;
                declineBtn.disabled = false;
                errorEl.textContent = e?.message || 'Failed to accept Terms & Conditions';
                errorEl.classList.remove('hidden');
            }
        };

        const onDeclineClick = async () => {
            try {
                await onDecline?.();
            } finally {
                cleanup();
                reject(new Error('Terms & Conditions must be accepted to use this service.'));
            }
        };

        acceptBtn.addEventListener('click', onAcceptClick);
        declineBtn.addEventListener('click', onDeclineClick);
    });
}

async function ensureDisclaimerAccepted(address, setButtonLoading) {
    const client = getHandle().webClient;
    setButtonLoading?.('Checking Terms & Conditions…');
    const state = await client.getDisclaimerState(address);
    if (state?.accepted) return;

    await showDisclaimerModal({
        disclaimerTextMd: state?.disclaimerTextMd || '',
        onAccept: async () => {
            setButtonLoading?.('Accepting Terms & Conditions…');
            await client.acceptDisclaimer(address, state?.disclaimerHashHex || '');
        },
        onDecline: async () => {
            Toast.show('Terms & Conditions must be accepted to use this service.', 'error', 10_000);
        },
    });
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

            await ensureDisclaimerAccepted(address, setButtonLoading);

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
        await ensureDisclaimerAccepted(nextAddress, setButtonLoading);

        const keys = await deriveKeysFromWallet(nextAddress, {
            onStatus: setButtonLoading,
            signOptions: { address: nextAddress },
            signDelay: 300,
        });

        App.state.keys.notePublicKey = keys?.pubKey || null;
        App.state.keys.encryptionPublicKey = keys?.encryptionKeypair?.publicKey || null;

        if (text) text.textContent = Utils.truncateHex(nextAddress, 7, 6);
        if (dropdownIcon) dropdownIcon.classList.remove('hidden');

        updateSubmitButtons(true);
        App.events.dispatchEvent(new CustomEvent('wallet:ready', { detail: { address: nextAddress } }));

        Toast.show('Freighter account changed. Privacy keys ready.', 'info');
    }
};
