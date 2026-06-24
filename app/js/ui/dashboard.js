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
        const address = App.state.wallet.address;
        const [balancesRes, feedRes, lookupRes] = await Promise.allSettled([
            getHandle().webClient.getPortfolioBalances(address),
            getHandle().webClient.getOperationalFeed(8),
            getHandle().webClient.lookupRegisteredPublicKey(address),
        ]);

        if (balancesRes.status === 'fulfilled') {
            App.state.balances = Array.isArray(balancesRes.value) ? balancesRes.value : [];
            this.renderBalances();
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
        this.renderProfile();
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
