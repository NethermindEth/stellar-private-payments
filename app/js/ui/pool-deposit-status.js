import { App, Utils } from './core.js';

// Live chain status is scoped to the current session, separately from the
// manifest-derived permission and privacy controls.
const statuses = new Map();
// Tree room and notes total per pool, absent while unknown.
const figures = new Map();
const pending = new Map();
let generation = 0;

const DETAIL = {
    loading: 'Checking deposit status…',
    accepting: '',
    paused: 'Deposits are paused. Transfers and withdrawals still work.',
    unavailable: 'Deposit status is unavailable. It will be checked again on the next refresh.',
};

// Every transaction adds two leaves to the pool tree, one per output note.
const LEAVES_PER_TRANSACTION = 2n;
// A pool is nearly full once less than 1/20 (5%) of its tree is left.
const NEAR_FULL_SHARE = 20n;

const CAPACITY_TAG = {
    nearFull: 'Pool nearly full',
    full: 'Pool full',
};

const transactions = count => `${count.toLocaleString('en-US')} more transaction${count === 1n ? '' : 's'}`;

// Reads the tree room and the notes total out of a pool's chain state, or
// null when the tree figures are missing or malformed.
function poolFigures(info) {
    try {
        const capacity = BigInt(info.merkleCapacity);
        const used = BigInt(info.merkleNextIndex);
        if (capacity <= 0n || used < 0n || used > capacity) return null;
        const left = capacity - used;
        let level = null;
        if (left < LEAVES_PER_TRANSACTION) level = 'full';
        else if (left * NEAR_FULL_SHARE < capacity) level = 'nearFull';
        return {
            transactionsLeft: left / LEAVES_PER_TRANSACTION,
            level,
            notesTotal: info.notesTotal == null ? null : BigInt(info.notesTotal),
        };
    } catch {
        return null;
    }
}

const figuresKey = value => value ? `${value.transactionsLeft}:${value.level}:${value.notesTotal}` : '';

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

    // 'full', 'nearFull', or null while the pool has room or is unknown.
    capacityLevel(poolId) {
        return isConfigured(poolId) ? figures.get(poolId)?.level ?? null : null;
    },

    // The warning for a full or nearly full pool, or '' otherwise. A full
    // tree refuses every transaction, withdrawals included.
    capacityWarning(poolId) {
        const level = this.capacityLevel(poolId);
        if (level === 'full') return 'This pool is full. No deposit, transfer or withdrawal can go through, so funds still in it cannot be withdrawn.';
        if (level === 'nearFull') return `This pool is nearly full, with room for about ${transactions(figures.get(poolId).transactionsLeft)}. Once it is full, no deposit, transfer or withdrawal can go through, so withdraw any funds you want out before then.`;
        return '';
    },

    // The tree room and the value held in notes, or '' while unknown.
    figuresText(poolId) {
        const value = isConfigured(poolId) ? figures.get(poolId) : null;
        if (!value) return '';
        const parts = [`Room for about ${transactions(value.transactionsLeft)}`];
        if (value.notesTotal != null) parts.push(`${Utils.formatPoolAmount(value.notesTotal, poolId)} held in notes`);
        return parts.join(' · ');
    },

    // Show the status sentence only while deposits are paused or the pool is
    // full or nearly full. A full pool takes no transfers or withdrawals
    // either, so its warning replaces the pause sentence.
    renderDetail(node, poolId, idleClass) {
        const paused = this.isPaused(poolId);
        const warning = this.capacityWarning(poolId);
        const pausedLine = paused && this.capacityLevel(poolId) !== 'full' ? DETAIL.paused : '';
        const detail = warning
            ? [pausedLine, warning].filter(Boolean).join(' ')
            : DETAIL[this.get(poolId)];
        const shown = paused || Boolean(warning);
        node.hidden = !shown;
        if (node.textContent !== detail) node.textContent = detail;
        node.classList.toggle('text-amber-200', shown);
        node.classList.toggle(idleClass, !shown);
    },

    // Quiet line with the tree room and the notes total, hidden while unknown.
    renderFigures(node, poolId) {
        const text = this.figuresText(poolId);
        node.hidden = !text;
        if (node.textContent !== text) node.textContent = text;
    },

    async refresh(sdk) {
        const ids = new Set(App.state.pools.map(pool => pool.poolContractId));
        for (const id of statuses.keys()) if (!ids.has(id)) statuses.delete(id);
        for (const id of figures.keys()) if (!ids.has(id)) figures.delete(id);
        const currentGeneration = generation;
        await Promise.allSettled([...ids].map(poolId => {
            if (pending.has(poolId)) return pending.get(poolId);
            const request = (async () => {
                let state;
                let value = null;
                try {
                    const data = await sdk.poolContractsData(poolId);
                    const info = data.pools.find(pool => pool.contractId === poolId);
                    if (typeof info?.depositsPaused !== 'boolean') throw new Error('Deposit status missing');
                    state = info.depositsPaused ? 'paused' : 'accepting';
                    value = poolFigures(info);
                } catch {
                    state = 'unavailable';
                }
                // Late responses from a disconnected wallet (clear() bumps the
                // generation) or a removed pool must not repopulate the
                // current session's status.
                if (generation !== currentGeneration || !isConfigured(poolId)) return;
                const previous = statuses.get(poolId);
                const previousFigures = figuresKey(figures.get(poolId));
                statuses.set(poolId, state);
                if (value) figures.set(poolId, value);
                else figures.delete(poolId);
                if (previous !== state || previousFigures !== figuresKey(value)) changed(poolId);
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
        figures.clear();
        changed();
    },

    renderCard(card) {
        const poolId = card.dataset.poolId;
        const paused = this.isPaused(poolId);
        const status = card.querySelector('[data-pool-deposit-status]');
        status.id = `pool-deposit-status-${poolId}`;
        status.hidden = !paused;
        const level = this.capacityLevel(poolId);
        const capacity = card.querySelector('[data-pool-capacity-status]');
        if (capacity) {
            capacity.hidden = !level;
            capacity.textContent = level ? CAPACITY_TAG[level] : '';
            capacity.title = level ? this.capacityWarning(poolId) : '';
        }
        card.querySelector('[data-pool-paused-indicator]').hidden = !paused && !level;
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
