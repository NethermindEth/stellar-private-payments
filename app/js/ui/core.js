/**
 * Core UI utilities and shared state.
 * @module ui/core
 */

// Application State - shared across all UI modules
export const App = {
    state: {
        wallet: {
            connected: false,
            address: null,
            sorobanRpcUrl: null,
            network: null,
            networkPassphrase: null,
        },
        keys: {
            notePublicKey: null,
            encryptionPublicKey: null,
        },
        notes: [],
        activeTab: 'deposit',
    },

    // Lightweight event bus for cross-module coordination
    events: new EventTarget(),

    // Template references (cached on init)
    templates: {},

    // DOM element references
    els: {},
};

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
        const day = String(date.getDate()).padStart(2, '0');
        const month = String(date.getMonth() + 1).padStart(2, '0');
        const year = date.getFullYear();
        const hours = String(date.getHours()).padStart(2, '0');
        const minutes = String(date.getMinutes()).padStart(2, '0');
        return `${day}/${month}/${year} ${hours}:${minutes}`;
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
        // Handle both Blob and string/object data
        const blob = data instanceof Blob 
            ? data 
            : new Blob([typeof data === 'string' ? data : JSON.stringify(data)], { type: 'application/json' });
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

// Toast Notifications
export const Toast = {
    show(message, type = 'success', duration = 4000) {
        const container = document.getElementById('toast-container');
        const template = App.templates.toast;
        const toast = template.content.cloneNode(true).firstElementChild;
        
        // Set content
        toast.querySelector('.toast-message').textContent = message;
        
        // Set icon and color based on type
        const icon = toast.querySelector('.toast-icon');
        if (type === 'success') {
            icon.innerHTML = '<path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/>';
            toast.classList.add('border-emerald-500/50');
            icon.classList.add('text-emerald-500');
        } else if (type === 'info') {
            icon.innerHTML = '<circle cx="12" cy="12" r="10"/><line x1="12" y1="16" x2="12" y2="12"/><circle cx="12" cy="8" r="1"/>';
            toast.classList.add('border-brand-500/50');
            icon.classList.add('text-brand-500');
        } else {
            // error
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
