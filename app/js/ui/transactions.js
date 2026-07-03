/**
 * Transactions UI — deposit, transfer, withdraw, and advanced transact.
 *
 * DOM matches `app/index.html`. Pool ops run on the SDK `PrivatePool` handle.
 *
 * @module ui/transactions
 */

import { client } from '../wasm-facade.js';
import { App, Toast, Utils } from './core.js';
import { ensureAppPool } from './pool.js';
import { Templates } from './templates.js';
import { OpHistory } from './op-history.js';

const DECIMALS = 7;
const N_OUTPUTS = 2;
const TX_PROGRESS_EVENT = 'stellar-private-payments:tx-progress';

function selectedPool() {
    return Utils.selectedPool();
}

function parseAmount(value, { allowNegative = false } = {}) {
    const raw = String(value ?? '').trim();
    if (!raw) return { ok: true, value: 0n };
    const match = /^([+-])?(\d*)(?:\.(\d*))?$/.exec(raw);
    if (!match) return { ok: false, error: 'Invalid amount' };
    const sign = match[1] || '';
    const intPart = match[2] || '0';
    const frac = (match[3] || '').padEnd(DECIMALS, '0');
    if ((match[3] || '').length > DECIMALS) return { ok: false, error: 'Too many decimal places' };
    const valueInt = (BigInt(intPart) * (10n ** BigInt(DECIMALS))) + BigInt(frac || '0');
    if (sign === '-' && !allowNegative && valueInt !== 0n) {
        return { ok: false, error: 'Amount must be non-negative' };
    }
    return { ok: true, value: sign === '-' ? -valueInt : valueInt };
}

function requireWallet() {
    if (!App.state.wallet.address || !App.state.wallet.networkPassphrase) {
        throw new Error('Connect your wallet first');
    }
}

function setLoading(button, loading, label = 'Submitting…') {
    if (!button) return;
    button.disabled = loading;
    button.querySelector('.btn-text')?.classList.toggle('hidden', loading);
    const loadingEl = button.querySelector('.btn-loading');
    if (loadingEl) {
        loadingEl.classList.toggle('hidden', !loading);
        loadingEl.textContent = loading ? label : '';
    }
}

// SDK prover emits `stellar-private-payments:tx-progress` with { flow, stage, message };
// surface `message` on the button loading label during pool ops.
function bindTxProgress(button, flow) {
    const handler = (event) => {
        const detail = event.detail;
        if (!button || detail?.flow !== flow || !detail?.message) return;
        const loadingEl = button.querySelector('.btn-loading');
        if (!loadingEl) return;
        loadingEl.classList.remove('hidden');
        loadingEl.textContent = detail.message;
    };
    window.addEventListener(TX_PROGRESS_EVENT, handler);
    return () => window.removeEventListener(TX_PROGRESS_EVENT, handler);
}

async function runPoolOp(flow, button, fn) {
    const unbind = button ? bindTxProgress(button, flow) : () => {};
    try {
        return await fn();
    } finally {
        unbind();
    }
}

function txResultsToHashes(results) {
    if (results == null) return null;
    const list = Array.isArray(results) ? results : [results];
    return list.map((r) => (typeof r === 'string' ? r : r?.txHash)).filter(Boolean);
}

function normalizeHexKey(value) {
    if (value == null) return '';
    if (typeof value === 'string') return value.trim();
    return String(value).trim();
}

function updatePoolLabels() {
    const pool = selectedPool();
    const label = Utils.poolLabel(pool);
    document.querySelectorAll('[data-current-token]').forEach(el => {
        el.textContent = label;
    });
}

// Show the balance of the currently selected token in Move Funds.
function updateMoveFundsBalance() {
    const el = document.getElementById('move-funds-balance');
    if (!el) return;
    const balance = (App.state.balances || []).find(b => b.poolContractId === App.state.selectedPoolId);
    el.textContent = balance ? Utils.formatTokenAmount(balance.amount, balance.tokenLabel) : '—';
}

async function lookupRecipient(address, refs) {
    refs.warning.textContent = '';
    refs.status.textContent = '';
    refs.manual.classList.add('hidden');
    if (!address) {
        refs.noteKey.value = '';
        refs.encKey.value = '';
        return null;
    }

    const lookup = await client().lookupRegisteredPublicKey(address);
    if (lookup?.entry) {
        refs.noteKey.value = normalizeHexKey(lookup.entry.noteKey);
        refs.encKey.value = normalizeHexKey(lookup.entry.encryptionKey);
        refs.status.textContent = 'Found local registration';
        return lookup;
    }

    refs.manual.classList.remove('hidden');
    refs.status.textContent = 'No local registration found';
    if (!lookup?.registryFullySynced) {
        refs.warning.textContent =
            'Local registry is still syncing. This address may be registered on-chain but not yet available locally.';
    }
    return lookup;
}

function collectInputNotes(rootId) {
    return Array.from(document.querySelectorAll(`#${rootId} .note-input`))
        .map(input => input.value.trim())
        .filter(Boolean);
}

function collectAdvancedOutputs() {
    const rows = Array.from(document.querySelectorAll('#advanced-outputs .advanced-output-row'));
    const amounts = [];
    const noteKeys = [];
    const encKeys = [];
    for (const row of rows) {
        const amount = parseAmount(row.querySelector('.output-amount')?.value, { allowNegative: false });
        if (!amount.ok) throw new Error(amount.error);
        amounts.push(amount.value);
        noteKeys.push(row.querySelector('.output-note-key')?.value?.trim() || null);
        encKeys.push(row.querySelector('.output-enc-key')?.value?.trim() || null);
    }
    while (amounts.length < N_OUTPUTS) amounts.push(0n);
    while (noteKeys.length < N_OUTPUTS) noteKeys.push(null);
    while (encKeys.length < N_OUTPUTS) encKeys.push(null);
    return {
        amounts: amounts.slice(0, N_OUTPUTS),
        noteKeys: noteKeys.slice(0, N_OUTPUTS),
        encKeys: encKeys.slice(0, N_OUTPUTS),
    };
}

function fillNextAdvancedInput(noteId) {
    const inputs = Array.from(document.querySelectorAll('#advanced-inputs .note-input'));
    const target = inputs.find(input => !input.value.trim()) || inputs[0];
    if (!target) return;
    target.value = noteId;
    target.dispatchEvent(new Event('input', { bubbles: true }));
}

// Show the amount of the note referenced by an input row (looked up from the
// loaded notes), so the operator can see what each selected input is worth.
function updateInputAmount(row) {
    const amountEl = row.querySelector('.note-input-amount');
    if (!amountEl) return;
    const id = row.querySelector('.note-input')?.value.trim();
    const note = id ? App.state.notes.find(n => n.id === id) : null;
    if (note) {
        const pool = App.state.pools.find(p => p.poolContractId === note.poolContractId);
        amountEl.textContent = `Amount: ${Utils.formatTokenAmount(note.amount, Utils.poolLabel(pool))}`;
    } else {
        amountEl.textContent = '';
    }
}

function wireAdvancedInputRow(row) {
    row.querySelector('.note-input')?.addEventListener('input', () => updateInputAmount(row));
}

function wireAdvancedOutputRow(row) {
    const addressInput = row.querySelector('.output-address');
    const refs = {
        status: row.querySelector('.lookup-status'),
        warning: row.querySelector('.lookup-warning'),
        manual: row.querySelector('.manual-fields'),
        noteKey: row.querySelector('.output-note-key'),
        encKey: row.querySelector('.output-enc-key'),
    };
    // Auto-search the registry once a full Stellar address (56 chars) is entered;
    // reset the lookup state for any shorter/partial input.
    addressInput?.addEventListener('input', async () => {
        const value = addressInput.value.trim();
        if (value.length === 56) {
            try {
                await lookupRecipient(value, refs);
            } catch (error) {
                refs.warning.textContent = error?.message || 'Lookup failed';
            }
        } else {
            lookupRecipient('', refs);
        }
    });
}

export const Transactions = {
    init() {
        this.buildAdvancedComposer();
        this.bindSharedEvents();
        this.bindMoveFunds();
        this.bindAdvancedTransact();
        updatePoolLabels();
        updateMoveFundsBalance();

        App.events.addEventListener('wallet:ready', (event) => {
            const address = event?.detail?.address || App.state.wallet.address;
            if (!address) return;
            const withdrawRecipient = document.getElementById('withdraw-recipient');
            const advancedRecipient = document.getElementById('advanced-public-recipient');
            if (withdrawRecipient) withdrawRecipient.value = address;
            if (advancedRecipient) advancedRecipient.value = address;
        });
    },

    buildAdvancedComposer() {
        const inputs = document.getElementById('advanced-inputs');
        const outputs = document.getElementById('advanced-outputs');
        inputs?.replaceChildren();
        outputs?.replaceChildren();
        for (let i = 0; i < 2; i += 1) {
            const inputRow = Templates.createNoteInputRow(i);
            inputs?.appendChild(inputRow);
            wireAdvancedInputRow(inputRow);
            const row = Templates.createOutputRow(i);
            outputs?.appendChild(row);
            wireAdvancedOutputRow(row);
        }
    },

    bindSharedEvents() {
        App.events.addEventListener('pool:config', updatePoolLabels);
        App.events.addEventListener('pool:selected', updatePoolLabels);
        App.events.addEventListener('pool:config', updateMoveFundsBalance);
        App.events.addEventListener('pool:selected', updateMoveFundsBalance);
        App.events.addEventListener('balances:updated', updateMoveFundsBalance);
        App.events.addEventListener('advanced:use-note', (event) => {
            fillNextAdvancedInput(event.detail.id);
            Toast.show('Note added to advanced transact', 'success');
        });
    },

    bindMoveFunds() {
        document.getElementById('btn-deposit')?.addEventListener('click', async (event) => {
            const button = event.currentTarget;
            try {
                requireWallet();
                const amount = parseAmount(document.getElementById('deposit-amount')?.value, { allowNegative: false });
                if (!amount.ok || amount.value <= 0n) throw new Error(amount.error || 'Enter a deposit amount');
                setLoading(button, true, 'Preparing deposit…');
                const pool = selectedPool();
                const session = await ensureAppPool();
                const result = await runPoolOp('deposit', button, () => session.deposit(amount.value));
                if (this.showExecuteResult(result, 'Deposit')) {
                    const hashes = result?.hashes ?? txResultsToHashes(result);
                    OpHistory.record(App.state.wallet.address, pool.poolContractId, {
                        type: 'Deposit',
                        amount: amount.value,
                        direction: 'in',
                        hashes,
                    });
                    document.getElementById('deposit-amount').value = '';
                }
            } catch (error) {
                Toast.show(error?.message || 'Deposit failed', 'error');
            } finally {
                setLoading(button, false);
            }
        });

        const transferRefs = {
            status: document.getElementById('transfer-lookup-status'),
            warning: document.getElementById('transfer-lookup-warning'),
            manual: document.getElementById('transfer-manual-fields'),
            noteKey: document.getElementById('transfer-note-key'),
            encKey: document.getElementById('transfer-enc-key'),
        };
        const transferAddress = document.getElementById('transfer-address');
        // Auto-search the registry once a full Stellar address (56 chars) is entered;
        // reset the lookup state for any shorter/partial input.
        transferAddress?.addEventListener('input', async () => {
            const value = transferAddress.value.trim();
            if (value.length === 56) {
                try {
                    await lookupRecipient(value, transferRefs);
                } catch (error) {
                    transferRefs.warning.textContent = error?.message || 'Lookup failed';
                }
            } else {
                lookupRecipient('', transferRefs);
            }
        });

        document.getElementById('btn-transfer')?.addEventListener('click', async (event) => {
            const button = event.currentTarget;
            try {
                requireWallet();
                const amount = parseAmount(document.getElementById('transfer-amount')?.value, { allowNegative: false });
                if (!amount.ok || amount.value <= 0n) throw new Error(amount.error || 'Enter a transfer amount');
                const noteKey = transferRefs.noteKey.value.trim();
                const encKey = transferRefs.encKey.value.trim();
                if (!noteKey || !encKey) throw new Error('Recipient note key and encryption key are required');
                setLoading(button, true, 'Preparing transfer…');
                const pool = selectedPool();
                const session = await ensureAppPool();
                const result = await runPoolOp('transfer', button, () =>
                    session.transferToKeys(noteKey, encKey, amount.value),
                );
                if (this.showExecuteResult(result, 'Transfer')) {
                    const hashes = result?.hashes ?? txResultsToHashes(result);
                    OpHistory.record(App.state.wallet.address, pool.poolContractId, {
                        type: 'Sent',
                        amount: amount.value,
                        direction: 'out',
                        counterparty: transferAddress.value.trim() || noteKey,
                        hashes,
                    });
                    document.getElementById('transfer-amount').value = '';
                    transferAddress.value = '';
                    transferRefs.noteKey.value = '';
                    transferRefs.encKey.value = '';
                    transferRefs.status.textContent = '';
                    transferRefs.warning.textContent = '';
                    transferRefs.manual.classList.add('hidden');
                }
            } catch (error) {
                Toast.show(error?.message || 'Transfer failed', 'error');
            } finally {
                setLoading(button, false);
            }
        });

        document.getElementById('btn-withdraw')?.addEventListener('click', async (event) => {
            const button = event.currentTarget;
            try {
                requireWallet();
                const amount = parseAmount(document.getElementById('withdraw-amount')?.value, { allowNegative: false });
                if (!amount.ok || amount.value <= 0n) throw new Error(amount.error || 'Enter a withdrawal amount');
                const recipient = document.getElementById('withdraw-recipient')?.value?.trim() || App.state.wallet.address;
                setLoading(button, true, 'Preparing withdrawal…');
                const pool = selectedPool();
                const session = await ensureAppPool();
                const result = await runPoolOp('withdraw', button, () =>
                    session.withdraw(amount.value, recipient),
                );
                if (this.showExecuteResult(result, 'Withdrawal')) {
                    const hashes = result?.hashes ?? txResultsToHashes(result);
                    OpHistory.record(App.state.wallet.address, pool.poolContractId, {
                        type: 'Withdraw',
                        amount: amount.value,
                        direction: 'out',
                        counterparty: recipient,
                        hashes,
                    });
                    document.getElementById('withdraw-amount').value = '';
                    document.getElementById('withdraw-recipient').value = '';
                }
            } catch (error) {
                Toast.show(error?.message || 'Withdraw failed', 'error');
            } finally {
                setLoading(button, false);
            }
        });
    },

    bindAdvancedTransact() {
        document.getElementById('btn-advanced-transact')?.addEventListener('click', async (event) => {
            const button = event.currentTarget;
            try {
                requireWallet();
                const deposit = parseAmount(
                    document.getElementById('advanced-public-deposit')?.value,
                    { allowNegative: false },
                );
                if (!deposit.ok) throw new Error(`Public deposit: ${deposit.error}`);
                const withdraw = parseAmount(
                    document.getElementById('advanced-public-withdraw')?.value,
                    { allowNegative: false },
                );
                if (!withdraw.ok) throw new Error(`Public withdraw: ${withdraw.error}`);
                // Public deposit is value entering the transaction (input, positive);
                // public withdraw is value leaving it (output, negative). The contract
                // takes a single signed ext amount.
                const publicAmount = deposit.value - withdraw.value;
                const inputNoteIds = collectInputNotes('advanced-inputs');
                const { amounts, noteKeys, encKeys } = collectAdvancedOutputs();
                const pool = selectedPool();
                const recipient = document.getElementById('advanced-public-recipient')?.value?.trim()
                    || App.state.wallet.address;

                setLoading(button, true, 'Preparing advanced transaction…');
                const session = await ensureAppPool();
                const result = await runPoolOp('transact', button, () => session.transact({
                    extRecipient: recipient,
                    extAmount: publicAmount,
                    inputNoteIds,
                    outputAmounts: amounts,
                    outRecipientNoteKeysHex: noteKeys,
                    outRecipientEncKeysHex: encKeys,
                }));
                if (this.showExecuteResult(result, 'Advanced transaction')) {
                    const hashes = result?.hashes ?? txResultsToHashes(result);
                    const absAmount = publicAmount < 0n ? -publicAmount : publicAmount;
                    const direction = publicAmount > 0n ? 'in' : publicAmount < 0n ? 'out' : 'none';
                    OpHistory.record(App.state.wallet.address, pool.poolContractId, {
                        type: 'Advanced',
                        amount: absAmount,
                        direction,
                        counterparty: direction === 'out' ? recipient : null,
                        hashes,
                    });
                    this.buildAdvancedComposer();
                    document.getElementById('advanced-public-deposit').value = '';
                    document.getElementById('advanced-public-withdraw').value = '';
                    document.getElementById('advanced-public-recipient').value = '';
                }
            } catch (error) {
                Toast.show(error?.message || 'Advanced transaction failed', 'error');
            } finally {
                setLoading(button, false);
            }
        });
    },

    // Returns true when a real submission happened, so callers can clear their form only on success.
    showExecuteResult(result, label = 'Transaction') {
        if (result?.status === 'aspNotReady') {
            Toast.show(
                'Your account is not registered with the ASP yet. Share your note public key and ASP secret with the ASP provider, then try again.',
                'error',
                8000,
            );
            return false;
        }
        if (result?.status === 'failed') {
            if (Array.isArray(result.hashes) && result.hashes.length) {
                this.showSubmittedToasts(result.hashes, label);
            }
            Toast.show(result.message || `${label} failed`, 'error', 7000);
            return false;
        }
        if (result?.status === 'ok') {
            return this.showSubmittedToasts(result.hashes, label);
        }
        const hashes = txResultsToHashes(result);
        if (hashes?.length) {
            return this.showSubmittedToasts(hashes, label);
        }
        Toast.show(`${label} failed`, 'error');
        return false;
    },

    showSubmittedToasts(hashes, label = 'Transaction') {
        if (!Array.isArray(hashes) || !hashes.length) return false;
        const lastHash = hashes[hashes.length - 1];
        const message = hashes.length === 1
            ? `${label} submitted: ${Utils.truncateHex(lastHash, 10, 8)}`
            : `${label}: ${hashes.length} transactions submitted. Last: ${Utils.truncateHex(lastHash, 10, 8)}`;
        Toast.show(message, 'success', 7000, {
            linkUrl: Utils.explorerTxUrl(lastHash),
            linkAriaLabel: 'Open transaction in explorer',
        });
        for (const txHash of hashes) {
            App.events.dispatchEvent(new CustomEvent('tx:submitted', { detail: { txHash } }));
        }
        return true;
    },
};
