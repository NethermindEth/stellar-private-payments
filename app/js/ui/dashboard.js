import { getHandle } from '../wasm-facade.js';
import { App, Toast, Utils } from './core.js';
import { Templates } from './templates.js';

function poolLabelById(poolContractId) {
    const pool = App.state.pools.find(item => item.poolContractId === poolContractId);
    return Utils.poolLabel(pool);
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
        App.events.addEventListener('profile:updated', () => this.renderProfile());
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
        document.getElementById('dashboard-profile-address').textContent = 'Not connected';
        document.getElementById('dashboard-profile-registration').textContent = '—';
    },

    async refresh() {
        if (!App.state.wallet.address) return;
        try {
            const [balances, feed, selfLookup] = await Promise.all([
                getHandle().webClient.getPortfolioBalances(App.state.wallet.address),
                getHandle().webClient.getOperationalFeed(8),
                getHandle().webClient.lookupRegisteredPublicKey(App.state.wallet.address),
            ]);
            App.state.balances = Array.isArray(balances) ? balances : [];
            App.state.feed = Array.isArray(feed) ? feed : [];
            App.state.profile.registryLookup = selfLookup || null;
            App.state.profile.registered = !!selfLookup?.entry;
            this.renderBalances();
            this.renderFeed();
            this.renderProfile();
            App.events.dispatchEvent(new CustomEvent('profile:updated'));
        } catch (error) {
            console.warn('[Dashboard] refresh failed:', error);
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
    },

    renderFeed() {
        const container = document.getElementById('dashboard-feed');
        if (!container) return;
        container.replaceChildren();
        App.state.feed.forEach(item => container.appendChild(Templates.createFeedCard(item, poolLabelById(item.poolContractId))));
    },

    renderProfile() {
        const address = App.state.wallet.address;
        document.getElementById('dashboard-profile-address').textContent = address ? Utils.shortAddress(address, 8, 6) : 'Not connected';
        document.getElementById('dashboard-profile-registration').textContent = App.state.profile.registered ? 'Registered' : 'Not registered';
        document.getElementById('dashboard-profile-sync').textContent = App.state.profile.registryLookup?.registryFullySynced ? 'Registry synced' : 'Registry syncing';
    },
};
