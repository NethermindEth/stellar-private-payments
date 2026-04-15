/**
 * On-chain state panel wiring (WASM-first).
 *
 * Populates the "On-Chain State" and basic Stats fields using `webClient.allContractsData()`.
 * Keeps HTML/CSS intact; this module only updates existing DOM IDs.
 *
 * @module ui/onchain-state
 */

import { getHandle } from '../wasm-facade.js';
import { App, Toast, Utils } from './core.js';

function setText(id, value) {
    const el = document.getElementById(id);
    if (!el) return;
    el.textContent = value ?? '—';
}

function setMonoText(id, value) {
    const el = document.getElementById(id);
    if (!el) return;
    el.textContent = value ?? '—';
    el.title = value ?? '';
}

function setIndicator(indicatorId, ok) {
    const el = document.getElementById(indicatorId);
    if (!el) return;
    el.classList.remove('bg-dark-500', 'bg-emerald-500', 'bg-red-500');
    if (ok === true) el.classList.add('bg-emerald-500');
    else if (ok === false) el.classList.add('bg-red-500');
    else el.classList.add('bg-dark-500');
}

function setStatus(id, ok, ledger) {
    const el = document.getElementById(id);
    if (!el) return;
    if (ok === true) {
        el.textContent = ledger ? `L${ledger}` : 'OK';
        el.className = 'text-[10px] text-emerald-500';
    } else if (ok === false) {
        el.textContent = 'Error';
        el.className = 'text-[10px] text-red-500';
    } else {
        el.textContent = '—';
        el.className = 'text-[10px] text-dark-500';
    }
}

function setLastUpdated() {
    const el = document.getElementById('state-last-updated');
    if (!el) return;
    const now = new Date();
    const hh = String(now.getHours()).padStart(2, '0');
    const mm = String(now.getMinutes()).padStart(2, '0');
    const ss = String(now.getSeconds()).padStart(2, '0');
    el.textContent = `Last updated: ${hh}:${mm}:${ss}`;
}

function showError(message) {
    const display = document.getElementById('contract-error-display');
    const text = document.getElementById('contract-error-text');
    if (text) text.textContent = message || 'Error loading contract state';
    display?.classList.remove('hidden');
}

function hideError() {
    document.getElementById('contract-error-display')?.classList.add('hidden');
}

export const OnchainState = {
    _timer: null,
    _refreshing: false,

    init() {
        document.getElementById('btn-refresh-state')?.addEventListener('click', () => {
            this.refreshAll().catch(() => {});
        });
        document.getElementById('btn-scan-notes')?.addEventListener('click', () => {
            Toast.show('Not supported in MVP yet', 'info');
        });
        document.getElementById('btn-force-resync')?.addEventListener('click', () => {
            Toast.show('Not supported in MVP yet', 'info');
        });

        App.events.addEventListener('wallet:ready', () => {
            this.start();
        });
        App.events.addEventListener('wallet:disconnected', () => {
            this.stop();
            this.clear();
        });
    },

    start() {
        this.stop();
        this.refreshAll().catch(() => {});
        this._timer = setInterval(() => {
            this.refreshAll().catch(() => {});
        }, 30_000);
    },

    stop() {
        if (this._timer) {
            clearInterval(this._timer);
            this._timer = null;
        }
    },

    clear() {
        hideError();

        setText('chain-network-badge', '—');

        setIndicator('pool-indicator', null);
        setStatus('pool-status', null);
        setMonoText('pool-address', '—');
        setMonoText('pool-root', '—');
        setText('pool-commitments', '—');
        setText('pool-levels', '—');

        setIndicator('membership-indicator', null);
        setStatus('membership-status', null);
        setMonoText('membership-address', '—');
        setMonoText('membership-root', '—');
        setText('membership-count', '—');

        setIndicator('nonmembership-indicator', null);
        setStatus('nonmembership-status', null);
        setMonoText('nonmembership-address', '—');
        setMonoText('nonmembership-root', '—');
        setText('nonmembership-tree-status', '—');

        setText('pool-total-value', '—');

        setText('state-last-updated', 'Last updated: —');
    },

    async refreshAll() {
        if (this._refreshing) return;
        if (!App.state.wallet.connected) return;

        this._refreshing = true;
        try {
            hideError();
            const data = await getHandle().webClient.allContractsData();

            // Network badge
            setText('chain-network-badge', data?.network || '—');

            // Pool
            setIndicator('pool-indicator', !!data?.pool?.success);
            setStatus('pool-status', data?.pool?.success, data?.pool?.ledger);
            setMonoText('pool-address', data?.pool?.contractId ? Utils.truncateHex(data.pool.contractId, 6, 6) : '—');
            document.getElementById('pool-address')?.setAttribute('title', data?.pool?.contractId || '');

            const poolRoot = data?.pool?.merkleRoot ?? null;
            setMonoText('pool-root', poolRoot ? Utils.truncateHex(poolRoot, 10, 8) : '—');
            document.getElementById('pool-root')?.setAttribute('title', poolRoot || '');

            setText('pool-commitments', data?.pool?.totalCommitments ?? '—');
            setText('pool-levels', data?.pool?.merkleLevels ?? '—');

            // ASP Membership
            setIndicator('membership-indicator', !!data?.aspMembership?.success);
            setStatus('membership-status', data?.aspMembership?.success, data?.aspMembership?.ledger);
            setMonoText('membership-address', data?.aspMembership?.contractId ? Utils.truncateHex(data.aspMembership.contractId, 6, 6) : '—');
            document.getElementById('membership-address')?.setAttribute('title', data?.aspMembership?.contractId || '');

            const memRoot = data?.aspMembership?.root ?? null;
            setMonoText('membership-root', memRoot ? Utils.truncateHex(memRoot, 10, 8) : '—');
            document.getElementById('membership-root')?.setAttribute('title', memRoot || '');

            setText('membership-count', data?.aspMembership?.nextIndex ?? '—');

            // ASP Non-Membership
            setIndicator('nonmembership-indicator', !!data?.aspNonMembership?.success);
            setStatus('nonmembership-status', data?.aspNonMembership?.success, data?.aspNonMembership?.ledger);
            setMonoText('nonmembership-address', data?.aspNonMembership?.contractId ? Utils.truncateHex(data.aspNonMembership.contractId, 6, 6) : '—');
            document.getElementById('nonmembership-address')?.setAttribute('title', data?.aspNonMembership?.contractId || '');

            const nonRoot = data?.aspNonMembership?.root ?? null;
            setMonoText('nonmembership-root', nonRoot ? Utils.truncateHex(nonRoot, 10, 8) : '—');
            document.getElementById('nonmembership-root')?.setAttribute('title', nonRoot || '');

            const isEmpty = data?.aspNonMembership?.isEmpty;
            setText('nonmembership-tree-status', isEmpty === true ? 'Empty' : isEmpty === false ? 'Non-empty' : '—');

            // Stats (minimal MVP)
            setText('pool-total-value', data?.pool?.totalCommitments ?? '—');

            setLastUpdated();
        } catch (e) {
            console.error('[OnchainState] refresh failed:', e);
            showError(e?.message || 'Failed to load contract state');
        } finally {
            this._refreshing = false;
        }
    },
};

