/**
 * Core UI utilities and shared state.
 * @module ui/core
 */

import { signWalletMessage } from '../wallet.js';
import { 
    deriveNotePrivateKeyFromSignature, 
    deriveEncryptionKeypairFromSignature,
    derivePublicKey,
} from '../bridge.js';
import { notesStore } from '../state/index.js';

// Application State - shared across all UI modules
export const App = {
    state: {
        wallet: { connected: false, address: null },
        notes: [],
        activeTab: 'deposit'
    },
    
    // Template references (cached on init)
    templates: {},
    
    // DOM element references
    els: {}
};

/**
 * Derives spending and encryption keys from Freighter wallet signatures.
 * Consolidates the repeated pattern used by Deposit, Withdraw, Transact, and Transfer modules.
 * 
 * @param {Object} options
 * @param {function} options.onStatus - Callback for status updates (e.g., setLoadingText)
 * @param {Object} [options.signOptions] - Options to pass to signWalletMessage
 * @param {number} [options.signDelay=300] - Delay between signature requests (ms)
 * @returns {Promise<{privKeyBytes: Uint8Array, pubKeyBytes: Uint8Array, encryptionKeypair: Object}>}
 * @throws {Error} If user rejects signature requests
 */
export async function deriveKeysFromWallet({ onStatus, signOptions = {}, signDelay = 300 }) {
    onStatus?.('Sign message to derive keys (1/2)...');
    
    let spendingResult;
    try {
        spendingResult = await signWalletMessage('Privacy Pool Spending Key [v1]', signOptions);
    } catch (e) {
        if (e.code === 'USER_REJECTED') {
            throw new Error('Please approve the message signature to derive your spending key');
        }
        throw e;
    }
    
    if (!spendingResult?.signedMessage) {
        throw new Error('Spending key signature rejected');
    }
    
    if (signDelay > 0) {
        await new Promise(r => setTimeout(r, signDelay));
    }
    
    onStatus?.('Sign message to derive keys (2/2)...');
    
    let encryptionResult;
    try {
        encryptionResult = await signWalletMessage('Sign to access Privacy Pool [v1]', signOptions);
    } catch (e) {
        if (e.code === 'USER_REJECTED') {
            throw new Error('Please approve the message signature to derive your encryption key');
        }
        throw e;
    }
    
    if (!encryptionResult?.signedMessage) {
        throw new Error('Encryption key signature rejected');
    }
    
    const spendingSigBytes = Uint8Array.from(atob(spendingResult.signedMessage), c => c.charCodeAt(0));
    const encryptionSigBytes = Uint8Array.from(atob(encryptionResult.signedMessage), c => c.charCodeAt(0));
    
    const privKeyBytes = deriveNotePrivateKeyFromSignature(spendingSigBytes);
    const pubKeyBytes = derivePublicKey(privKeyBytes);
    const encryptionKeypair = deriveEncryptionKeypairFromSignature(encryptionSigBytes);
    
    console.log('[KeyDerivation] Derived keys from wallet signatures');
    
    return { privKeyBytes, pubKeyBytes, encryptionKeypair };
}

// Utilities
export const Utils = {
    generateHex(length = 64) {
        const chars = '0123456789abcdef';
        let result = '0x';
        for (let i = 0; i < length; i++) {
            result += chars.charAt(Math.floor(Math.random() * chars.length));
        }
        return result;
    },

    truncateHex(hex, start = 8, end = 8) {
        if (!hex || hex.length <= start + end + 3) return hex;
        return `${hex.slice(0, start)}...${hex.slice(-end)}`;
    },

    formatNumber(num) {
        return num.toString().replace(/\B(?=(\d{3})+(?!\d))/g, ',');
    },

    formatDate(dateStr) {
        const date = new Date(dateStr);
        return date.toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' });
    },

    async copyToClipboard(text) {
        try {
            await navigator.clipboard.writeText(text);
            Toast.show('Copied to clipboard!', 'success');
            return true;
        } catch {
            Toast.show('Failed to copy', 'error');
            return false;
        }
    },

    downloadFile(data, filename) {
        const blob = new Blob([data], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = filename;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
    }
};

// Storage - loads notes from IndexedDB filtered by current owner
export const Storage = {
    KEY: 'poolstellar_notes',
    
    /**
     * Saves a note to IndexedDB with the current owner.
     * @param {Object} note - Note to save
     */
    async save(note) {
        try {
            await notesStore.saveNote(note);
            // Reload the notes list to include the new one
            await this.load();
        } catch (e) {
            console.error('Storage save failed:', e);
        }
    },
    
    /**
     * Loads notes for the current owner from IndexedDB.
     * Notes are filtered by the connected wallet address.
     */
    async load() {
        try {
            // Get notes from IndexedDB, filtered by the current owner
            const notes = await notesStore.getNotes();
            App.state.notes = notes;
            console.log(`[Storage] Loaded ${notes.length} notes for current owner`);
        } catch (e) {
            console.error('Storage load failed:', e);
            App.state.notes = [];
        }
    },
    
    /**
     * Legacy method for backwards compatibility - just calls load()
     */
    loadFromLocalStorage() {
        // Keep for backwards compatibility with any code that still uses localStorage
        try {
            const data = localStorage.getItem(this.KEY);
            if (data) {
                const legacyNotes = JSON.parse(data);
                console.log(`[Storage] Found ${legacyNotes.length} legacy notes in localStorage`);
                // Could migrate these to IndexedDB if needed
            }
        } catch (e) {
            // Ignore
        }
    }
};

// Toast Notifications
export const Toast = {
    show(message, type = 'success', duration = 4000) {
        const container = document.getElementById('toast-container');
        const template = App.templates.toast;
        const toast = template.content.cloneNode(true).firstElementChild;
        
        // Set content
        toast.querySelector('.toast-message').textContent = message;
        
        // Set icon
        const icon = toast.querySelector('.toast-icon');
        if (type === 'success') {
            icon.innerHTML = '<path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/>';
            toast.classList.add('border-emerald-500/50');
            icon.classList.add('text-emerald-500');
        } else {
            icon.innerHTML = '<circle cx="12" cy="12" r="10"/><line x1="15" y1="9" x2="9" y2="15"/><line x1="9" y1="9" x2="15" y2="15"/>';
            toast.classList.add('border-red-500/50');
            icon.classList.add('text-red-500');
        }
        
        // Close button handler
        toast.querySelector('.toast-close').addEventListener('click', () => toast.remove());
        
        container.appendChild(toast);
        
        // Auto-remove
        setTimeout(() => {
            toast.style.opacity = '0';
            toast.style.transform = 'translateX(100%)';
            setTimeout(() => toast.remove(), 200);
        }, duration);
    }
};
