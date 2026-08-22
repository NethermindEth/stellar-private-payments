/**
 * Transactions UI — deposit, transfer, withdraw, and advanced transact.
 *
 * DOM matches `app/index.html`. Pool ops run on the SDK `PrivatePool` handle.
 *
 * @module ui/transactions
 */

import { client, isRuntimeReady } from '../wasm-facade.js';
import { friendlyErrorMessage } from '../facade-errors.js';
import { StrKey } from '@stellar/stellar-sdk';
import { App, Toast, Utils } from './core.js';
import { ensureAppPool } from './pool.js';
import { Templates } from './templates.js';
import { OpHistory } from './op-history.js';
import { getTransactionErrorMessage } from './errors.js';
import { confirmAction } from './confirm.js';
import { onEnter } from './keys.js';

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
    if (!isRuntimeReady()) {
        throw new Error('Still connecting to your wallet. Please wait a moment and try again.');
    }
}

function setLoading(button, loading, label = 'Submitting…') {
    if (!button) return;
    button.disabled = loading;
    button.dataset.status = loading ? 'submitting' : 'idle';
    if (!loading) delete button.dataset.progress;
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
        button.dataset.status = 'submitting';
        button.dataset.progress = detail.message;
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

// Enter in a field bypasses the button's disabled state, so guard the in-flight
// case explicitly — otherwise Enter can fire a second op while one is running.
function onEnterUnlessBusy(input, button, handler) {
    onEnter(input, () => {
        if (button?.disabled) return;
        handler();
    });
}

// Builds a confirmation-dialog row with the number of transactions the action
// requires. Best-effort only: a failed estimate must not block the action.
async function txCountRow(amountValue) {
    try {
        const session = await ensureAppPool();
        const estimate = await session.estimate(amountValue);
        const txCount = estimate?.txCount;
        if (!txCount) return null;
        return {
            label: 'Transactions',
            value: `${txCount} transaction${txCount === 1 ? '' : 's'}`,
        };
    } catch {
        return null;
    }
}

async function submitDeposit(button, amountValue, pool) {
    setLoading(button, true, 'Preparing deposit…');
    const session = await ensureAppPool();
    const result = await runPoolOp('deposit', button, () => session.deposit(amountValue));
    if (Transactions.showExecuteResult(result, 'Deposit')) {
        const hashes = result?.hashes ?? txResultsToHashes(result);
        OpHistory.record(App.state.wallet.address, pool.poolContractId, {
            type: 'Deposit',
            amount: amountValue,
            direction: 'in',
            hashes,
        });
        document.getElementById('deposit-amount').value = '';
    }
}

async function submitTransfer(button, amountValue, pool, transferRefs, transferAddress) {
    const noteKey = transferRefs.noteKey.value.trim();
    const encKey = transferRefs.encKey.value.trim();
    setLoading(button, true, 'Preparing transfer…');
    const session = await ensureAppPool();
    const result = await runPoolOp('transfer', button, () =>
        session.transferToKeys(noteKey, encKey, amountValue),
    );
    if (Transactions.showExecuteResult(result, 'Transfer')) {
        const hashes = result?.hashes ?? txResultsToHashes(result);
        OpHistory.record(App.state.wallet.address, pool.poolContractId, {
            type: 'Sent',
            amount: amountValue,
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
}

async function submitWithdraw(button, amountValue, pool, recipient) {
    setLoading(button, true, 'Preparing withdrawal…');
    const session = await ensureAppPool();
    const result = await runPoolOp('withdraw', button, () =>
        session.withdraw(amountValue, recipient),
    );
    if (Transactions.showExecuteResult(result, 'Withdrawal')) {
        const hashes = result?.hashes ?? txResultsToHashes(result);
        OpHistory.record(App.state.wallet.address, pool.poolContractId, {
            type: 'Withdraw',
            amount: amountValue,
            direction: 'out',
            counterparty: recipient,
            hashes,
        });
        document.getElementById('withdraw-amount').value = '';
        document.getElementById('withdraw-recipient').value = '';
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

    const lookup = await client().recipientLookup(address);
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
                refs.warning.textContent = friendlyErrorMessage(error?.message) || 'Lookup failed';
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
            Toast.show('Note added to advanced transact', 'success', 4000, { origin: 'advanced' });
        });
    },

    bindMoveFunds() {
        const depositButton = document.getElementById('btn-deposit');
        const depositAmountInput = document.getElementById('deposit-amount');

        async function runDeposit(button) {
            try {
                requireWallet();
                const amount = parseAmount(depositAmountInput?.value, { allowNegative: false });
                if (!amount.ok || amount.value <= 0n) throw new Error(amount.error || 'Enter a deposit amount');
                const pool = selectedPool();
                const rows = [
                    { label: 'Amount', value: Utils.formatTokenAmount(amount.value, Utils.poolLabel(pool)) },
                ];
                const countRow = await txCountRow(amount.value);
                if (countRow) rows.push(countRow);
                const confirmed = await confirmAction({
                    title: 'Confirm deposit',
                    rows,
                    confirmLabel: 'Deposit',
                });
                if (!confirmed) return;
                await submitDeposit(button, amount.value, pool);
            } catch (error) {
                Toast.show(getTransactionErrorMessage(error, 'Deposit'), 'error', 7000, { origin: 'deposit' });
            } finally {
                setLoading(button, false);
            }
        }

        depositButton?.addEventListener('click', (event) => runDeposit(event.currentTarget));
        onEnterUnlessBusy(depositAmountInput, depositButton, () => runDeposit(depositButton));

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
                    transferRefs.warning.textContent = friendlyErrorMessage(error?.message) || 'Lookup failed';
                }
            } else {
                lookupRecipient('', transferRefs);
            }
        });

        const transferAmountInput = document.getElementById('transfer-amount');
        const transferButton = document.getElementById('btn-transfer');

        async function runTransfer(button) {
            try {
                requireWallet();
                const amount = parseAmount(transferAmountInput?.value, { allowNegative: false });
                if (!amount.ok || amount.value <= 0n) throw new Error(amount.error || 'Enter a transfer amount');
                const noteKey = transferRefs.noteKey.value.trim();
                const encKey = transferRefs.encKey.value.trim();
                if (!noteKey || !encKey) throw new Error('Recipient note key and encryption key are required');
                const  pool = selectedPool();
                const recipientLabel = transferAddress.value.trim()
                    ? Utils.shortAddress(transferAddress.value.trim())
                    : Utils.shortAddress(noteKey);
                const rows = [
                    { label: 'Recipient', value: recipientLabel },
                    { label: 'Amount', value: Utils.formatTokenAmount(amount.value, Utils.poolLabel(pool)) },
                ];
                const countRow = await txCountRow(amount.value);
                if (countRow) rows.push(countRow);
                const confirmed = await confirmAction({
                    title: 'Confirm transfer',
                    rows,
                    confirmLabel: 'Transfer',
                });
                if (!confirmed) return;
                await submitTransfer(button, amount.value, pool, transferRefs, transferAddress);
            } catch (error) {
                Toast.show(getTransactionErrorMessage(error, 'Transfer'), 'error', 7000, { origin: 'transfer' });
            } finally {
                setLoading(button, false);
            }
        }

        onEnter(transferAddress, async () => {
            const value = transferAddress.value.trim();
            if (!value) return;
            if (!StrKey.isValidEd25519PublicKey(value)) {
                Toast.show('Invalid Stellar address', 'error', 4000, { origin: 'transfer' });
                return;
            }
            // The `input` handler above already looked this address up at 56 chars;
            // only re-query when that left the keys empty.
            if (!transferRefs.noteKey.value.trim()) {
                try {
                    await lookupRecipient(value, transferRefs);
                } catch (error) {
                    transferRefs.warning.textContent = friendlyErrorMessage(error?.message) || 'Lookup failed';
                    return; // keep focus here so the user can retry the address
                }
            }
            // No registration found: the manual key fields are now visible and empty,
            // so send focus there rather than past them to the amount.
            if (!transferRefs.noteKey.value.trim() && !transferRefs.manual.classList.contains('hidden')) {
                transferRefs.noteKey.focus();
                return;
            }
            transferAmountInput?.focus();
        });
        transferButton?.addEventListener('click', (event) => runTransfer(event.currentTarget));
        onEnterUnlessBusy(transferAmountInput, transferButton, () => runTransfer(transferButton));

        const withdrawRecipientInput = document.getElementById('withdraw-recipient');
        const withdrawAmountInput = document.getElementById('withdraw-amount');
        const withdrawButton = document.getElementById('btn-withdraw');

        async function runWithdraw(button) {
            try {
                requireWallet();
                const amount = parseAmount(withdrawAmountInput?.value, { allowNegative: false });
                if (!amount.ok || amount.value <= 0n) throw new Error(amount.error || 'Enter a withdrawal amount');
                const recipient = withdrawRecipientInput?.value?.trim() || App.state.wallet.address;
                if (recipient !== App.state.wallet.address && !StrKey.isValidEd25519PublicKey(recipient)) {
                    throw new Error('Invalid Stellar address');
                }
                const pool = selectedPool();
                const rows = [
                    { label: 'Recipient', value: Utils.shortAddress(recipient) },
                    { label: 'Amount', value: Utils.formatTokenAmount(amount.value, Utils.poolLabel(pool)) },
                ];
                const countRow = await txCountRow(amount.value);
                if (countRow) rows.push(countRow);
                const confirmed = await confirmAction({
                    title: 'Confirm withdrawal',
                    rows,
                    confirmLabel: 'Withdraw',
                });
                if (!confirmed) return;
                await submitWithdraw(button, amount.value, pool, recipient);
            } catch (error) {
                Toast.show(getTransactionErrorMessage(error, 'Withdraw'), 'error', 7000, { origin: 'withdraw' });
            } finally {
                setLoading(button, false);
            }
        }

        onEnter(withdrawRecipientInput, () => {
            const value = withdrawRecipientInput.value.trim();
            if (value && !StrKey.isValidEd25519PublicKey(value)) {
                Toast.show('Invalid Stellar address', 'error', 4000, { origin: 'withdraw' });
                return;
            }
            withdrawAmountInput?.focus();
        });
        withdrawButton?.addEventListener('click', (event) => runWithdraw(event.currentTarget));
        onEnterUnlessBusy(withdrawAmountInput, withdrawButton, () => runWithdraw(withdrawButton));
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

                const rows = [
                    { label: 'Recipient', value: Utils.shortAddress(recipient) },
                    { label: 'Input notes', value: `${inputNoteIds.length}` },
                    { label: 'Outputs', value: `${amounts.length}` },
                ];
                if (deposit.value > 0n) {
                    rows.push({ label: 'Public deposit', value: Utils.formatTokenAmount(deposit.value, Utils.poolLabel(pool)) });
                }
                if (withdraw.value > 0n) {
                    rows.push({ label: 'Public withdraw', value: Utils.formatTokenAmount(withdraw.value, Utils.poolLabel(pool)) });
                }
                // Advanced transact always executes as a single transaction.
                rows.push({ label: 'Transactions', value: '1 transaction' });
                const confirmed = await confirmAction({
                    title: 'Confirm advanced transaction',
                    rows,
                    confirmLabel: 'Transact',
                });
                if (!confirmed) return;

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
                Toast.show(getTransactionErrorMessage(error, 'Advanced transaction'), 'error', 7000, { origin: 'advanced' });
            } finally {
                setLoading(button, false);
            }
        });
    },

    // Returns true when a real submission happened, so callers can clear their form only on success.
    showExecuteResult(result, label = 'Transaction') {
        const origin = { Deposit: 'deposit', Transfer: 'transfer', Withdrawal: 'withdraw', 'Advanced transaction': 'advanced' }[label] || 'transaction';
        if (result?.status === 'aspNotReady') {
            Toast.show(
                'Your account is not registered with the ASP yet. Share your note public key and ASP secret with the ASP provider, then try again.',
                'error',
                8000,
                { origin },
            );
            return false;
        }
        if (result?.status === 'failed') {
            if (Array.isArray(result.hashes) && result.hashes.length) {
                this.showSubmittedToasts(result.hashes, label, origin);
            }
            Toast.show(getTransactionErrorMessage({ message: result.message, code: result.code }, label) || `${label} failed`, 'error', 7000, { origin });
            return false;
        }
        if (result?.status === 'ok') {
            return this.showSubmittedToasts(result.hashes, label, origin);
        }
        const hashes = txResultsToHashes(result);
        if (hashes?.length) {
            return this.showSubmittedToasts(hashes, label, origin);
        }
        Toast.show(`${label} failed`, 'error', 4000, { origin });
        return false;
    },

    showSubmittedToasts(hashes, label = 'Transaction', origin = 'transaction') {
        if (!Array.isArray(hashes) || !hashes.length) return false;
        const lastHash = hashes[hashes.length - 1];
        const message = hashes.length === 1
            ? `${label} submitted: ${Utils.truncateHex(lastHash, 10, 8)}`
            : `${label}: ${hashes.length} transactions submitted. Last: ${Utils.truncateHex(lastHash, 10, 8)}`;
        Toast.show(message, 'success', 7000, {
            linkUrl: Utils.explorerTxUrl(lastHash),
            linkAriaLabel: 'Open transaction in explorer',
            origin,
            transactionHash: lastHash,
        });
        for (const txHash of hashes) {
            App.events.dispatchEvent(new CustomEvent('tx:submitted', { detail: { txHash } }));
        }
        return true;
    },
};
