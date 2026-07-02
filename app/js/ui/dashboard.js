import { getHandle } from '../wasm-facade.js';
import { App, Toast, Utils } from './core.js';
import { Templates } from './templates.js';
import { OpHistory } from './op-history.js';

function poolLabelById(poolContractId) {
    const pool = App.state.pools.find(item => item.poolContractId === poolContractId);
    return Utils.poolLabel(pool);
}

function el(tag, className, text) {
    const node = document.createElement(tag);
    if (className) node.className = className;
    if (text != null) node.textContent = text;
    return node;
}

function shortCounterparty(cp) {
    if (!cp) return '';
    return cp.length > 18 ? `${cp.slice(0, 8)}…${cp.slice(-6)}` : cp;
}

export const Dashboard = {
    _timer: null,

    init() {
        App.events.addEventListener('wallet:ready', () => {
            this.start();
        });
        App.events.addEventListener('wallet:disconnected', () => {
            this.stop();
            this.clear();
        });
        document.getElementById('pool-history-close')?.addEventListener('click', () => this.closeHistory());
        document.getElementById('pool-history-modal')?.addEventListener('click', (e) => {
            if (e.target === e.currentTarget) this.closeHistory();
        });
        document.getElementById('move-funds-history')?.addEventListener('click', () => this.openHistory(App.state.selectedPoolId));
    },

    start() {
        this.stop();
        this.refresh().catch(() => {});
        this._timer = setInterval(() => this.refresh().catch(() => {}), 10_000);
    },

    stop() {
        if (this._timer) {
            clearInterval(this._timer);
            this._timer = null;
        }
    },

    clear() {
        document.getElementById('dashboard-balance-grid')?.replaceChildren();
        document.getElementById('dashboard-feed')?.replaceChildren();
    },

    async refresh() {
        if (!App.state.wallet.address) return;
        const address = App.state.wallet.address;
        const [balancesRes, feedRes, lookupRes] = await Promise.allSettled([
            getHandle().webClient.getPortfolioBalances(address),
            getHandle().webClient.getOperationalFeed(5),
            getHandle().webClient.lookupRegisteredPublicKey(address),
        ]);

        if (balancesRes.status === 'fulfilled') {
            App.state.balances = Array.isArray(balancesRes.value) ? balancesRes.value : [];
            this.renderBalances();
            App.events.dispatchEvent(new CustomEvent('balances:updated'));
        } else {
            console.warn('[Dashboard] balances refresh failed:', balancesRes.reason);
        }

        if (feedRes.status === 'fulfilled') {
            App.state.feed = Array.isArray(feedRes.value) ? feedRes.value : [];
            this.renderFeed();
        } else {
            console.warn('[Dashboard] feed refresh failed:', feedRes.reason);
        }

        if (lookupRes.status === 'fulfilled') {
            App.state.profile.registryLookup = lookupRes.value || null;
            App.state.profile.registered = !!lookupRes.value?.entry;
        } else {
            console.warn('[Dashboard] registry lookup failed:', lookupRes.reason);
        }
        App.events.dispatchEvent(new CustomEvent('profile:updated'));

        if (balancesRes.status === 'rejected' && feedRes.status === 'rejected' && lookupRes.status === 'rejected') {
            Toast.show('Failed to refresh dashboard data', 'info');
        }
    },

    renderBalances() {
        const container = document.getElementById('dashboard-balance-grid');
        if (!container) return;
        container.replaceChildren();
        App.state.balances.forEach(balance => container.appendChild(Templates.createBalanceCard(balance)));
        container.querySelectorAll('[data-quick-flow]').forEach(btn => {
            btn.addEventListener('click', () => {
                const flow = btn.dataset.quickFlow;
                const poolId = btn.dataset.poolId;
                App.events.dispatchEvent(new CustomEvent('dashboard:quick-flow', {
                    detail: { flow, poolId },
                }));
            });
        });
        container.querySelectorAll('[data-view-notes]').forEach(btn => {
            btn.addEventListener('click', () => {
                App.events.dispatchEvent(new CustomEvent('dashboard:view-notes', {
                    detail: { poolId: btn.dataset.poolId },
                }));
            });
        });
        container.querySelectorAll('[data-view-history]').forEach(btn => {
            btn.addEventListener('click', () => this.openHistory(btn.dataset.poolId));
        });
    },

    async openHistory(poolId) {
        const label = poolLabelById(poolId);
        const titleEl = document.getElementById('pool-history-title');
        const listEl = document.getElementById('pool-history-list');
        const emptyEl = document.getElementById('pool-history-empty');
        const modal = document.getElementById('pool-history-modal');
        if (!listEl || !modal) return;
        if (titleEl) titleEl.textContent = `${label} operations`;

        listEl.replaceChildren();
        emptyEl?.classList.add('hidden');
        modal.classList.remove('hidden');
        modal.classList.add('flex');

        const ops = await OpHistory.list(App.state.wallet.address, poolId, 10);
        emptyEl?.classList.toggle('hidden', ops.length > 0);

        ops.forEach(op => {
            const row = el('div', 'rounded-2xl border border-white/8 bg-white/[0.03] p-3');
            const top = el('div', 'flex items-center justify-between gap-3');
            top.appendChild(el('span', 'text-sm font-medium text-white', op.opType));
            const sign = op.direction === 'out' ? '−' : op.direction === 'in' ? '+' : '';
            const amountText = op.amount != null ? `${sign}${Utils.formatTokenAmount(op.amount, label)}` : '';
            top.appendChild(el('span', `font-mono text-sm ${op.direction === 'out' ? 'text-rose-200' : 'text-cyan-100'}`, amountText));
            row.appendChild(top);

            const meta = el('div', 'mt-1 flex items-center justify-between gap-3 text-[11px] text-slate-500');
            if (op.counterparty) {
                const cp = el('button', 'break-all text-left text-slate-400 transition hover:text-cyan-100', `→ ${shortCounterparty(op.counterparty)}`);
                cp.type = 'button';
                cp.title = `Copy ${op.counterparty}`;
                cp.addEventListener('click', () => Utils.copyToClipboard(op.counterparty));
                meta.appendChild(cp);
            } else {
                meta.appendChild(el('span'));
            }
            meta.appendChild(el('span', 'shrink-0', op.createdAt ? new Date(op.createdAt * 1000).toLocaleString() : ''));
            row.appendChild(meta);

            if (op.txHash) {
                const a = el('a', 'mt-2 inline-block text-[11px] font-medium text-cyan-100 underline underline-offset-4', 'Open in explorer');
                a.href = Utils.explorerTxUrl(op.txHash);
                a.target = '_blank';
                a.rel = 'noreferrer noopener';
                row.appendChild(a);
            }
            listEl.appendChild(row);
        });
    },

    closeHistory() {
        const modal = document.getElementById('pool-history-modal');
        modal?.classList.add('hidden');
        modal?.classList.remove('flex');
    },

    renderFeed() {
        const container = document.getElementById('dashboard-feed');
        if (!container) return;
        container.replaceChildren();
        // Only pass a token label for pool items; registry/ASP items have no pool
        // (poolContractId is null) and shouldn't show the "Token" fallback.
        App.state.feed.forEach(item => container.appendChild(
            Templates.createFeedCard(item, item.poolContractId ? poolLabelById(item.poolContractId) : null),
        ));
    },
};
