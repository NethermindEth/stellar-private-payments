/**
 * Navigation - Tab switching and Wallet connection.
 * @module ui/navigation
 */

import { connectWallet, getWalletNetwork } from '../wallet.js';
import { validateWalletNetwork } from '../stellar.js';
import { App, Utils, Toast } from './core.js';
import { setTabsRef } from './templates.js';

// Callbacks for wallet connection events (set by transaction modules)
const walletConnectCallbacks = [];

/**
 * Registers a callback to be called when wallet connects.
 * Used by Withdraw and Transact to prefill recipient fields.
 * @param {function} callback
 */
export function onWalletConnect(callback) {
    walletConnectCallbacks.push(callback);
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
    init() {
        document.getElementById('wallet-btn').addEventListener('click', () => this.toggle());
    },
    
    async toggle() {
        if (App.state.wallet.connected) {
            this.disconnect();
        } else {
            await this.connect();
        }
    },
    
    async connect() {
        const btn = document.getElementById('wallet-btn');
        const text = document.getElementById('wallet-text');
        const network = document.getElementById('network-name');
        
        try {
            const publicKey = await connectWallet();
            App.state.wallet = { connected: true, address: publicKey };
            
            btn.classList.add('border-emerald-500', 'bg-emerald-500/10');
            text.textContent = Utils.truncateHex(App.state.wallet.address, 7, 6);
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
        
        App.state.wallet = { connected: false, address: null };
        btn.classList.remove('border-emerald-500', 'bg-emerald-500/10');
        text.textContent = 'Connect Freighter';
        if (network) {
            network.textContent = 'Network';
        }
        Toast.show('Wallet disconnected', 'success');
    }
};
