/**
 * Navigation - Tab switching and Wallet connection.
 * @module ui/navigation
 */

import { connectWallet, getWalletNetwork, signWalletTransaction, signWalletAuthEntry } from '../wallet.js';
import { validateWalletNetwork, registerPublicKey, getLatestLedger } from '../stellar.js';
import { App, Utils, Toast, deriveKeysFromWallet, Storage } from './core.js';
import { setTabsRef } from './templates.js';
import { fieldToHex } from '../bridge.js';
import { publicKeyStore, notesStore } from '../state/index.js';
import { bytesToHex } from '../state/utils.js';
import { NotesTable } from './notes-table.js';

// Callbacks for wallet connection events (set by transaction modules)
const walletConnectCallbacks = [];
const walletDisconnectCallbacks = [];
const accountChangeCallbacks = [];

// Polling interval for account change detection
let accountCheckInterval = null;
const ACCOUNT_CHECK_INTERVAL_MS = 3000;

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
 * Registers a callback to be called when account changes (different address same wallet).
 * @param {function(string)} callback - Receives the new address
 */
export function onAccountChange(callback) {
    accountChangeCallbacks.push(callback);
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
    checkingAccount: false,
    
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
        
        // Check for account changes when window gains focus
        window.addEventListener('focus', () => {
            if (App.state.wallet.connected) {
                this.checkAccountChange();
            }
        });
        
        // Also check periodically while connected
        this.startAccountCheck();
        
        // Initially disable submit buttons until wallet is connected
        updateSubmitButtons(false);
    },
    
    startAccountCheck() {
        if (accountCheckInterval) return;
        accountCheckInterval = setInterval(() => {
            if (App.state.wallet.connected && document.visibilityState === 'visible') {
                this.checkAccountChange();
            }
        }, ACCOUNT_CHECK_INTERVAL_MS);
    },
    
    stopAccountCheck() {
        if (accountCheckInterval) {
            clearInterval(accountCheckInterval);
            accountCheckInterval = null;
        }
    },
    
    async checkAccountChange() {
        if (this.checkingAccount || !App.state.wallet.connected) return;
        
        this.checkingAccount = true;
        try {
            const currentAddress = await connectWallet();
            const previousAddress = App.state.wallet.address;
            
            if (currentAddress !== previousAddress) {
                console.log(`[Wallet] Account changed: ${previousAddress?.slice(0, 8)}... -> ${currentAddress.slice(0, 8)}...`);
                
                // Update state
                App.state.wallet.address = currentAddress;
                
                // Update notes store owner and clear keypairs
                notesStore.handleAccountChange(currentAddress);
                
                // Update UI
                const text = document.getElementById('wallet-text');
                const addressDisplay = document.getElementById('wallet-dropdown-address');
                if (text) text.textContent = Utils.truncateHex(currentAddress, 7, 6);
                if (addressDisplay) addressDisplay.textContent = currentAddress;
                
                // Reload notes for the new account
                await NotesTable.reload();
                
                // Notify callbacks
                for (const callback of accountChangeCallbacks) {
                    try {
                        callback(currentAddress);
                    } catch (e) {
                        console.error('[Wallet] Account change callback error:', e);
                    }
                }
                
                Toast.show('Account changed - notes updated', 'success');
            }
        } catch (e) {
            // Wallet may have been disconnected externally
            if (App.state.wallet.connected) {
                console.warn('[Wallet] Failed to check account:', e.message);
            }
        } finally {
            this.checkingAccount = false;
        }
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
            
            // Set the owner in notes store for filtering
            notesStore.handleAccountChange(publicKey);
            
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
        
        // Load notes for this account
        await NotesTable.reload();
        
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
        
        // Clear owner in notes store
        notesStore.handleAccountChange(null);
        
        // Clear notes from UI (no owner = empty list)
        App.state.notes = [];
        NotesTable.render();
        
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
     * Registers the user's public keys on-chain for address book discovery.
     * Registers both the X25519 encryption key and BN254 note key.
     */
    async registerPublicKey() {
        if (!App.state.wallet.connected) {
            Toast.show('Please connect your wallet first', 'error');
            return;
        }
        
        Toast.show('Preparing registration...', 'info');
        
        try {
            // Derive both keypairs from wallet signatures
            const { pubKeyBytes, encryptionKeypair } = await deriveKeysFromWallet({
                onStatus: (msg) => console.log('[Register]', msg),
                signDelay: 300,
            });
            
            // Get keys as hex strings for logging/storage
            // Note: X25519 keys are raw bytes (not field elements), so use bytesToHex
            // BN254 note keys are field elements, so use fieldToHex for BE hex representation
            const encryptionKeyHex = bytesToHex(encryptionKeypair.publicKey);
            const noteKeyHex = fieldToHex(pubKeyBytes);
            
            console.log('[Register] Registering keys:', {
                encryptionKey: encryptionKeyHex.slice(0, 20) + '...',
                noteKey: noteKeyHex.slice(0, 20) + '...',
            });
            
            // Call the pool.register() function with both keys
            const result = await registerPublicKey({
                owner: App.state.wallet.address,
                encryptionKey: encryptionKeypair.publicKey,
                noteKey: pubKeyBytes,
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
                        encryption_key: encryptionKeyHex,
                        note_key: noteKeyHex,
                    }, ledger);
                    console.log('[Register] Added to local store');
                } catch (storeError) {
                    console.warn('[Register] Failed to add to local store:', storeError);
                }
                
                Toast.show('Public keys registered successfully!', 'success');
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
