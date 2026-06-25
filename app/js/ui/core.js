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
        if (asset.kind === 'contract') return asset.symbol || 'Token';
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

    explorerContractUrl(contractId) {
        return `${this.explorerBaseUrl()}/contract/${contractId}`;
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
        const link = toast.querySelector('.toast-link');

        msgEl.textContent = String(message ?? '');
        msgEl.title = String(message ?? '');

        const dot = type === 'info' ? 'bg-slate-300' : type === 'error' ? 'bg-rose-400' : 'bg-cyan-300';
        const border = type === 'info' ? 'border-slate-400/40' : type === 'error' ? 'border-rose-400/40' : 'border-cyan-400/40';
        icon?.classList.remove('bg-cyan-300');
        icon?.classList.add(dot);
        toast.classList.add(border);

        if (opts.linkUrl && link) {
            link.href = opts.linkUrl;
            if (opts.linkAriaLabel) link.setAttribute('aria-label', opts.linkAriaLabel);
            link.classList.remove('hidden');
        }

        container.appendChild(toast);

        setTimeout(() => {
            toast.style.opacity = '0';
            toast.style.transform = 'translateY(8px)';
            setTimeout(() => toast.remove(), 200);
        }, duration);
    },
};
