/**
 * Navigation - Tab switching and Wallet connection.
 * @module ui/navigation
 */

import { connectWallet, getWalletNetwork, signWalletTransaction, signWalletAuthEntry } from '../wallet.js';
import { validateWalletNetwork, registerPublicKey, getLatestLedger } from '../stellar.js';
import { App, Utils, Toast, deriveKeysFromWallet } from './core.js';
import { setTabsRef } from './templates.js';
import { fieldToHex } from '../bridge.js';
import { publicKeyStore } from '../state/index.js';

// Callbacks for wallet connection events (set by transaction modules)
const walletConnectCallbacks = [];
const walletDisconnectCallbacks = [];

/**
 * Registers a callback to be called when wallet connects.
 * Used by Withdraw and Transact to prefill recipient fields.
 * @param {function} callback
 */
export function onWalletConnect(callback) {
    walletConnectCallbacks.push(callback);
}

/**
 * Registers a callback to be called when wallet disconnects.
 * @param {function} callback
 */
export function onWalletDisconnect(callback) {
    walletDisconnectCallbacks.push(callback);
}

/**
 * Updates the disabled state of all submit buttons and disclaimers based on wallet connection.
 * @param {boolean} connected - Whether wallet is connected
 */
function updateSubmitButtons(connected) {
    const modes = ['deposit', 'withdraw', 'transfer', 'transact'];
    for (const mode of modes) {
        const btn = document.getElementById(`btn-${mode}`);
        const disclaimer = document.getElementById(`wallet-disclaimer-${mode}`);
        
        if (btn) {
            btn.disabled = !connected;
        }
        if (disclaimer) {
            disclaimer.classList.toggle('hidden', connected);
        }
    }
}

export const Tabs = {
    init() {
        document.querySelectorAll('.tab-btn').forEach(btn => {
            btn.addEventListener('click', () => this.switch(btn.dataset.tab));
        });
        
        // Register with templates for cross-module access
        setTabsRef(this);
    },
    
    switch(tabId) {
        App.state.activeTab = tabId;
        
        // Update tab buttons
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
        
        // Update panels
        document.querySelectorAll('.tab-panel').forEach(panel => {
            const isActive = panel.id === `panel-${tabId}`;
            panel.classList.toggle('hidden', !isActive);
        });
    }
};

export const Wallet = {
    dropdownOpen: false,
    
    init() {
        const btn = document.getElementById('wallet-btn');
        const dropdown = document.getElementById('wallet-dropdown');
        const disconnectBtn = document.getElementById('wallet-disconnect-btn');
        const registerBtn = document.getElementById('wallet-register-btn');
        
        btn.addEventListener('click', (e) => {
            if (App.state.wallet.connected) {
                e.stopPropagation();
                this.toggleDropdown();
            } else {
                this.connect();
            }
        });
        
        disconnectBtn?.addEventListener('click', () => {
            this.closeDropdown();
            this.disconnect();
        });
        
        registerBtn?.addEventListener('click', () => {
            this.closeDropdown();
            this.registerPublicKey();
        });
        
        // Close dropdown when clicking outside
        document.addEventListener('click', (e) => {
            if (this.dropdownOpen && !dropdown?.contains(e.target) && e.target !== btn) {
                this.closeDropdown();
            }
        });
        
        // Initially disable submit buttons until wallet is connected
        updateSubmitButtons(false);
    },
    
    toggleDropdown() {
        if (this.dropdownOpen) {
            this.closeDropdown();
        } else {
            this.openDropdown();
        }
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
    
    async connect() {
        const btn = document.getElementById('wallet-btn');
        const text = document.getElementById('wallet-text');
        const network = document.getElementById('network-name');
        const dropdownIcon = document.getElementById('wallet-dropdown-icon');
        
        try {
            const publicKey = await connectWallet();
            App.state.wallet = { connected: true, address: publicKey };
            
            btn.classList.add('border-emerald-500', 'bg-emerald-500/10');
            text.textContent = Utils.truncateHex(App.state.wallet.address, 7, 6);
            dropdownIcon?.classList.remove('hidden');
        } catch (e) {
            console.error('Wallet connection error:', e);
            const message = e?.code === 'USER_REJECTED'
                ? 'Wallet connection cancelled'
                : (e?.message || 'Failed to connect wallet');
            Toast.show(message, 'error');
            return;
        }

        // Validate wallet is on the correct network
        if (network) {
            try {
                const details = await getWalletNetwork();
                validateWalletNetwork(details.network);
                network.textContent = details.network || 'Unknown';
            } catch (e) {
                console.error('Wallet network error:', e);
                network.textContent = 'Unknown';
                Toast.show(e?.message || 'Failed to fetch wallet network', 'error');
                this.disconnect();
                return;
            }
        }

        Toast.show('Wallet connected!', 'success');
        
        // Enable submit buttons
        updateSubmitButtons(true);
        
        // Notify registered callbacks (Withdraw, Transact prefill recipient)
        for (const callback of walletConnectCallbacks) {
            try {
                callback();
            } catch (e) {
                console.error('[Wallet] Callback error:', e);
            }
        }
    },
    
    disconnect() {
        const btn = document.getElementById('wallet-btn');
        const text = document.getElementById('wallet-text');
        const network = document.getElementById('network-name');
        const dropdownIcon = document.getElementById('wallet-dropdown-icon');
        
        App.state.wallet = { connected: false, address: null };
        btn.classList.remove('border-emerald-500', 'bg-emerald-500/10');
        text.textContent = 'Connect Freighter';
        dropdownIcon?.classList.add('hidden');
        if (network) {
            network.textContent = 'Network';
        }
        
        // Disable submit buttons
        updateSubmitButtons(false);
        
        // Notify disconnect callbacks
        for (const callback of walletDisconnectCallbacks) {
            try {
                callback();
            } catch (e) {
                console.error('[Wallet] Disconnect callback error:', e);
            }
        }
        
        Toast.show('Wallet disconnected', 'success');
    },
    
    /**
     * Registers the user's public key on-chain for address book discovery.
     */
    async registerPublicKey() {
        if (!App.state.wallet.connected) {
            Toast.show('Please connect your wallet first', 'error');
            return;
        }
        
        Toast.show('Preparing registration...', 'info');
        
        try {
            // Derive keys from wallet signatures
            const { encryptionKeypair } = await deriveKeysFromWallet({
                onStatus: (msg) => console.log('[Register]', msg),
                signDelay: 300,
            });
            
            // Get the public key as hex string
            const publicKeyHex = fieldToHex(encryptionKeypair.publicKey);
            
            console.log('[Register] Registering public key:', publicKeyHex.slice(0, 20) + '...');
            
            // Call the pool.register() function
            const result = await registerPublicKey({
                owner: App.state.wallet.address,
                publicKey: encryptionKeypair.publicKey,
                signerOptions: {
                    publicKey: App.state.wallet.address,
                    signTransaction: signWalletTransaction,
                    signAuthEntry: signWalletAuthEntry,
                },
            });
            
            if (result.success) {
                // Add to local store immediately so address book updates
                try {
                    const ledger = await getLatestLedger();
                    await publicKeyStore.processPublicKeyEvent({
                        owner: App.state.wallet.address,
                        key: publicKeyHex,
                    }, ledger);
                    console.log('[Register] Added to local store');
                } catch (storeError) {
                    console.warn('[Register] Failed to add to local store:', storeError);
                }
                
                Toast.show('Public key registered successfully!', 'success');
                console.log('[Register] Transaction hash:', result.txHash);
            } else {
                throw new Error(result.error || 'Registration failed');
            }
        } catch (e) {
            console.error('[Register] Failed:', e);
            Toast.show('Registration failed: ' + e.message, 'error');
        }
    }
};
