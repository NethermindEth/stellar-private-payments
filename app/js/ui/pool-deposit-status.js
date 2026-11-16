import { App, Utils } from './core.js';

// Live chain status is scoped to the current session, separately from the
// manifest-derived permission and privacy controls.
const statuses = new Map();
const pending = new Map();
let generation = 0;

const DETAIL = {
    loading: 'Checking deposit status…',
    accepting: '',
    paused: 'Deposits are paused. Transfers and withdrawals still work.',
    unavailable: 'Deposit status is unavailable. It will be checked again on the next refresh.',
};

function changed(poolId) {
    App.events.dispatchEvent(new CustomEvent('pool:deposit-status', { detail: { poolId } }));
}

function isConfigured(poolId) {
    return App.state.pools.some(pool => pool.poolContractId === poolId);
}

export const PoolDepositStatus = {
    get(poolId) {
        if (!isConfigured(poolId)) return 'unavailable';
        return statuses.get(poolId) ?? 'loading';
    },

    isPaused(poolId) {
        return this.get(poolId) === 'paused';
    },

    // Show the status sentence only while deposits are paused.
    renderDetail(node, poolId, idleClass) {
        const detail = DETAIL[this.get(poolId)];
        const paused = this.isPaused(poolId);
        node.hidden = !paused;
        if (node.textContent !== detail) node.textContent = detail;
        node.classList.toggle('text-amber-200', paused);
        node.classList.toggle(idleClass, !paused);
    },

    async refresh(sdk) {
        const ids = new Set(App.state.pools.map(pool => pool.poolContractId));
        for (const id of statuses.keys()) if (!ids.has(id)) statuses.delete(id);
        const currentGeneration = generation;
        await Promise.allSettled([...ids].map(poolId => {
            if (pending.has(poolId)) return pending.get(poolId);
            const request = (async () => {
                let state;
                try {
                    const data = await sdk.poolContractsData(poolId);
                    const info = data.pools.find(pool => pool.contractId === poolId);
                    if (typeof info?.depositsPaused !== 'boolean') throw new Error('Deposit status missing');
                    state = info.depositsPaused ? 'paused' : 'accepting';
                } catch {
                    state = 'unavailable';
                }
                // Late responses from a disconnected wallet (clear() bumps the
                // generation) or a removed pool must not repopulate the
                // current session's status.
                if (generation !== currentGeneration || !isConfigured(poolId)) return;
                const previous = statuses.get(poolId);
                statuses.set(poolId, state);
                if (previous !== state) changed(poolId);
            })();
            pending.set(poolId, request);
            return request.finally(() => {
                if (pending.get(poolId) === request) pending.delete(poolId);
            });
        }));
    },

    clear() {
        generation++;
        pending.clear();
        statuses.clear();
        changed();
    },

    renderCard(card) {
        const poolId = card.dataset.poolId;
        const paused = this.isPaused(poolId);
        const status = card.querySelector('[data-pool-deposit-status]');
        status.id = `pool-deposit-status-${poolId}`;
        status.hidden = !paused;
        card.querySelector('[data-pool-paused-indicator]').hidden = !paused;
        const deposit = card.querySelector('[data-quick-flow="deposit"]');
        deposit.disabled = paused;
        if (paused) deposit.setAttribute('aria-describedby', status.id);
        else deposit.removeAttribute('aria-describedby');
    },

    renderMoveFunds() {
        const poolId = Utils.selectedPool()?.poolContractId;
        const status = document.getElementById('move-pool-deposit-status');
        if (status) {
            status.hidden = !poolId;
            if (poolId) this.renderDetail(status, poolId, 'text-slate-400');
        }
        const button = document.getElementById('btn-deposit');
        if (button) button.disabled = button.dataset.status === 'submitting' || this.isPaused(poolId);
    },
};
