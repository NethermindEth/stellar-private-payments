/**
 * Recent pool activity sidebar (WASM-first).
 *
 * Reads aggregated activity from local SQLite via `webClient.getRecentPoolActivity()`.
 *
 * @module ui/pool-events
 */

import { getHandle } from '../wasm-facade.js';
import { App } from './core.js';

function setStatus(status, text = '') {
    const el = document.getElementById('recent-tx-status');
    if (!el) return;

    if (status === 'success') {
        el.textContent = text || 'Updated';
        el.className = 'text-[10px] text-emerald-500';
    } else if (status === 'error') {
        el.textContent = text || 'Error';
        el.className = 'text-[10px] text-red-500';
    } else {
        el.textContent = '—';
        el.className = 'text-[10px] text-dark-500';
    }
}

function showLoading() {
    document.getElementById('recent-tx')?.replaceChildren();
    document.getElementById('recent-tx-empty')?.classList.add('hidden');
    document.getElementById('recent-tx-loading')?.classList.remove('hidden');
}

function showEmpty() {
    document.getElementById('recent-tx')?.replaceChildren();
    document.getElementById('recent-tx-loading')?.classList.add('hidden');
    document.getElementById('recent-tx-empty')?.classList.remove('hidden');
}

function hideLoading() {
    document.getElementById('recent-tx-loading')?.classList.add('hidden');
}

function inferType(row) {
    const c = Number(row.commitments || 0);
    const n = Number(row.nullifiers || 0);
    if (n === 0 && c > 0) return { label: 'Deposit', color: 'text-emerald-400' };
    if (n > 0 && c === 0) return { label: 'Withdraw', color: 'text-orange-400' };
    if (n > 0 && c > 0) return { label: 'Transfer', color: 'text-brand-400' };
    return { label: 'Pool Activity', color: 'text-dark-300' };
}

function iconSvg(type) {
    if (type === 'Deposit') {
        return '<svg class="w-3.5 h-3.5 text-emerald-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 4v16m0 0l-4-4m4 4l4-4"/></svg>';
    }
    if (type === 'Withdraw') {
        return '<svg class="w-3.5 h-3.5 text-orange-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 20V4m0 0l-4 4m4-4l4 4"/></svg>';
    }
    if (type === 'Transfer') {
        return '<svg class="w-3.5 h-3.5 text-brand-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 7h12m-12 6h12m-12 6h12M4 7h.01M4 13h.01M4 19h.01"/></svg>';
    }
    return '<svg class="w-3.5 h-3.5 text-dark-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><circle cx="12" cy="12" r="9"/><path d="M12 7v6"/><path d="M12 17h.01"/></svg>';
}

function ledgerLink(ledger) {
    return `https://stellar.expert/explorer/testnet/ledger/${ledger}`;
}

export const PoolEvents = {
    _timer: null,
    _loading: false,

    init() {
        App.events.addEventListener('wallet:ready', () => this.start());
        App.events.addEventListener('wallet:disconnected', () => this.stop());
    },

    start() {
        this.stop();
        this.refresh().catch(() => {});
        this._timer = setInterval(() => {
            this.refresh().catch(() => {});
        }, 30_000);
    },

    stop() {
        if (this._timer) {
            clearInterval(this._timer);
            this._timer = null;
        }
        setStatus('idle');
        showEmpty();
    },

    async refresh() {
        if (this._loading) return;
        if (!App.state.wallet.connected) return;
        this._loading = true;

        showLoading();
        try {
            const rows = await getHandle().webClient.getRecentPoolActivity(3);
            const list = Array.isArray(rows) ? rows : [];

            hideLoading();
            if (list.length === 0) {
                showEmpty();
                setStatus('success', 'No events');
                return;
            }

            document.getElementById('recent-tx-empty')?.classList.add('hidden');
            const container = document.getElementById('recent-tx');
            container?.replaceChildren();

            for (const row of list) {
                const ledger = Number(row.ledger || 0);
                const commitments = Number(row.commitments || 0);
                const nullifiers = Number(row.nullifiers || 0);
                const info = inferType(row);

                const li = document.createElement('li');
                li.className = 'flex justify-between items-center p-2 bg-dark-800 rounded text-xs hover:bg-dark-700 transition-colors';

                const left = document.createElement('div');
                left.className = 'flex items-center gap-2';
                left.innerHTML = iconSvg(info.label);

                const txt = document.createElement('div');
                txt.className = 'flex flex-col';

                const title = document.createElement('span');
                title.className = `text-dark-200 font-medium ${info.color}`;
                title.textContent = info.label;

                const detail = document.createElement('span');
                detail.className = 'text-[10px] text-dark-500';
                detail.textContent = `${commitments} commit${commitments === 1 ? '' : 's'}, ${nullifiers} nullifier${nullifiers === 1 ? '' : 's'}`;

                txt.appendChild(title);
                txt.appendChild(detail);
                left.appendChild(txt);

                const a = document.createElement('a');
                a.href = ledgerLink(ledger);
                a.target = '_blank';
                a.rel = 'noopener noreferrer';
                a.className = 'text-dark-400 hover:text-brand-400 transition-colors flex items-center gap-1';
                a.innerHTML = `L${ledger} <svg class="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10 6H6a2 2 0 00-2 2v10a2 2 0 002 2h10a2 2 0 002-2v-4M14 4h6m0 0v6m0-6L10 14"/></svg>`;

                li.appendChild(left);
                li.appendChild(a);
                container?.appendChild(li);
            }

            setStatus('success');
        } catch (e) {
            console.error('[PoolEvents] refresh failed:', e);
            showEmpty();
            setStatus('error');
        } finally {
            this._loading = false;
        }
    },
};

