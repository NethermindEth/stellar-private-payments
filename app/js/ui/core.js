/**
 * Core UI utilities and shared state.
 */

const DEFAULT_EXPLORER_BASE_URL = 'https://stellar.expert/explorer/testnet';

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
            aspSecret: null,
        },
        views: {
            active: 'dashboard',
            moveFlow: 'deposit',
        },
        pools: [],
        selectedPoolId: null,
        notes: [],
        balances: [],
        feed: [],
        profile: {
            registered: false,
            registryLookup: null,
        },
        settings: {
            explorerBaseUrl: DEFAULT_EXPLORER_BASE_URL,
            bootnode: {
                enabled: false,
                url: '',
            },
        },
        ui: {
            settingsOpen: false,
        },
    },

    events: new EventTarget(),
    templates: {},
};

export const Utils = {
    defaultExplorerBaseUrl: DEFAULT_EXPLORER_BASE_URL,

    truncateHex(hex, start = 8, end = 8) {
        if (!hex || hex.length <= start + end + 3) return hex;
        return `${hex.slice(0, start)}...${hex.slice(-end)}`;
    },

    formatNumber(num) {
        return Number(num || 0).toLocaleString('en-US');
    },

    shortAddress(address, start = 7, end = 6) {
        return this.truncateHex(address, start, end);
    },

    poolLabel(pool) {
        if (!pool) return 'Token';
        const asset = pool.asset || {};
        if (asset.kind === 'native') return 'XLM';
        if (asset.kind === 'classic') return asset.code || 'Asset';
        if (asset.kind === 'contract') {
            const contractId = asset.contractId || '';
            return `Token ${contractId.slice(-6) || ''}`.trim();
        }
        return 'Token';
    },

    selectedPool() {
        return App.state.pools.find(pool => pool.poolContractId === App.state.selectedPoolId) || App.state.pools[0] || null;
    },

    formatTokenAmount(amount, symbol = 'XLM', decimals = 7) {
        try {
            let value = typeof amount === 'bigint' ? amount : BigInt(amount || 0);
            const negative = value < 0n;
            if (negative) value = -value;
            const abs = value.toString().padStart(decimals + 1, '0');
            const intPart = abs.slice(0, -decimals);
            const frac = abs.slice(-decimals).replace(/0+$/, '');
            const out = frac ? `${intPart}.${frac}` : intPart;
            return `${negative ? '-' : ''}${out} ${symbol}`;
        } catch {
            return `0 ${symbol}`;
        }
    },

    explorerBaseUrl() {
        return App.state.settings.explorerBaseUrl || DEFAULT_EXPLORER_BASE_URL;
    },

    explorerTxUrl(hash) {
        return `${this.explorerBaseUrl()}/tx/${hash}`;
    },

    explorerLedgerUrl(ledger) {
        return `${this.explorerBaseUrl()}/ledger/${ledger}`;
    },

    explorerAddressUrl(address) {
        return `${this.explorerBaseUrl()}/account/${address}`;
    },

    async copyToClipboard(text) {
        try {
            await navigator.clipboard.writeText(text);
            Toast.show('Copied to clipboard', 'success');
            return true;
        } catch {
            Toast.show('Failed to copy', 'error');
            return false;
        }
    },
};

export const Toast = {
    show(message, type = 'success', duration = 4000, opts = {}) {
        const container = document.getElementById('toast-container');
        const template = App.templates.toast;
        if (!container || !template) return;

        const toast = template.content.cloneNode(true).firstElementChild;
        const icon = toast.querySelector('.toast-icon');
        const msgEl = toast.querySelector('.toast-message');
        const open = toast.querySelector('.toast-open');

        msgEl.textContent = String(message ?? '');
        msgEl.title = String(message ?? '');

        if (type === 'success') {
            icon.innerHTML = '<path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/>';
            toast.classList.add('border-cyan-400/40');
            icon.classList.add('text-cyan-300');
        } else if (type === 'info') {
            icon.innerHTML = '<circle cx="12" cy="12" r="10"/><line x1="12" y1="16" x2="12" y2="12"/><circle cx="12" cy="8" r="1"/>';
            toast.classList.add('border-slate-400/40');
            icon.classList.add('text-slate-200');
        } else {
            icon.innerHTML = '<circle cx="12" cy="12" r="10"/><line x1="15" y1="9" x2="9" y2="15"/><line x1="9" y1="9" x2="15" y2="15"/>';
            toast.classList.add('border-rose-400/40');
            icon.classList.add('text-rose-300');
        }

        if (opts.linkUrl) {
            open.href = opts.linkUrl;
            if (opts.linkAriaLabel) open.setAttribute('aria-label', opts.linkAriaLabel);
            open.classList.remove('hidden');
        }

        toast.querySelector('.toast-close')?.addEventListener('click', () => toast.remove());
        container.appendChild(toast);

        setTimeout(() => {
            toast.style.opacity = '0';
            toast.style.transform = 'translateY(8px)';
            setTimeout(() => toast.remove(), 200);
        }, duration);
    },
};
