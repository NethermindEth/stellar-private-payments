/**
 * Transactions UI - Deposit / Withdraw / Transfer / Transact.
 *
 * WASM-first: all proving + tx preparation happens in WebClient.
 * JS is responsible only for UI interactions and signing/submitting prepared XDR.
 *
 * @module ui/transactions
 */

import { getHandle } from '../wasm-facade.js';
import { submitProvedPoolTransact } from '../stellar.js';
import { App, Toast, Utils } from './core.js';
import { Templates } from './templates.js';

const N_OUTPUTS = 2;
let cachedContractConfig = null;

async function getContractConfig() {
    if (cachedContractConfig) return cachedContractConfig;
    cachedContractConfig = await getHandle().webClient.contractConfig();
    return cachedContractConfig;
}

function noteAmountToStroopsBigInt(amount) {
    if (amount == null) return 0n;
    if (typeof amount === 'bigint') return amount;
    if (typeof amount === 'number') {
        if (!Number.isFinite(amount)) return 0n;
        return BigInt(Math.trunc(amount));
    }
    if (typeof amount === 'string') {
        const s = amount.trim();
        if (!s) return 0n;
        try {
            return BigInt(s);
        } catch {
            return 0n;
        }
    }
    return 0n;
}

const STROOPS_PER_XLM = 10_000_000n;

function tryParseXlmToStroopsBigInt(xlmText, { allowNegative = false } = {}) {
    const raw = xlmText == null ? '' : String(xlmText);
    const s = raw.trim();
    if (!s) return { ok: true, value: 0n };

    // Decimal-only (no scientific notation). Accepts: [-+]?\d*(\.\d*)?
    const m = /^([+-])?(\d*)(?:\.(\d*))?$/.exec(s);
    if (!m) {
        return { ok: false, error: 'Invalid amount (use a decimal number, no scientific notation).' };
    }

    const signChar = m[1] || '';
    const intPart = m[2] || '';
    const fracPart = m[3] || '';
    const hasAnyDigits = /[0-9]/.test(intPart) || /[0-9]/.test(fracPart);
    if (!hasAnyDigits) {
        return { ok: false, error: 'Invalid amount.' };
    }

    if (fracPart.length > 7) {
        return { ok: false, error: 'Too many decimal places (max 7).' };
    }

    let intVal = 0n;
    let fracVal = 0n;
    try {
        intVal = intPart ? BigInt(intPart) : 0n;
        fracVal = fracPart ? BigInt(fracPart.padEnd(7, '0')) : 0n;
    } catch {
        return { ok: false, error: 'Invalid amount.' };
    }

    const abs = intVal * STROOPS_PER_XLM + fracVal;
    const isNegative = signChar === '-';
    if (isNegative && !allowNegative && abs !== 0n) {
        return { ok: false, error: 'Amount must be non-negative.' };
    }

    return { ok: true, value: isNegative ? -abs : abs };
}

function xlmToStroopsBigInt(xlm, opts) {
    const res = tryParseXlmToStroopsBigInt(xlm, opts);
    if (!res.ok) throw new Error(res.error);
    return res.value;
}

function stroopsBigIntToXlmText(stroops) {
    let v = typeof stroops === 'bigint' ? stroops : 0n;
    const isNeg = v < 0n;
    if (isNeg) v = -v;

    const absStr = v.toString().padStart(8, '0');
    const intPart = absStr.slice(0, -7);
    const fracRaw = absStr.slice(-7);
    const frac = fracRaw.replace(/0+$/, '');
    const out = frac ? `${intPart}.${frac}` : intPart;
    return isNeg ? `-${out}` : out;
}

function parseMembershipBlinding(inputId) {
    const raw = document.getElementById(inputId)?.value?.trim() || '0';
    try {
        return BigInt(raw);
    } catch {
        throw new Error(`Invalid membership blinding: ${raw}`);
    }
}

function setLoading(btn, loadingText) {
    const btnText = btn.querySelector('.btn-text');
    const btnLoading = btn.querySelector('.btn-loading');
    btn.disabled = true;
    btnText?.classList.add('hidden');
    if (btnLoading) {
        btnLoading.classList.remove('hidden');
        btnLoading.innerHTML = `<span class="inline-block w-4 h-4 border-2 border-dark-950/30 border-t-dark-950 rounded-full animate-spin"></span><span class="btn-loading-text ml-2"></span>`;
        const text = btnLoading.querySelector('.btn-loading-text');
        if (text) text.textContent = loadingText;
    }
}

function setLoadingText(btn, text) {
    const btnLoading = btn.querySelector('.btn-loading');
    const el = btnLoading?.querySelector('.btn-loading-text');
    if (el) el.textContent = text;
}

function clearLoading(btn) {
    const btnText = btn.querySelector('.btn-text');
    const btnLoading = btn.querySelector('.btn-loading');
    btn.disabled = false;
    btnText?.classList.remove('hidden');
    btnLoading?.classList.add('hidden');
    if (btnLoading) btnLoading.textContent = '';
}

function requireWalletReady() {
    if (!App.state.wallet.connected || !App.state.wallet.address) {
        throw new Error('Please connect your wallet first');
    }
    if (!App.state.wallet.sorobanRpcUrl || !App.state.wallet.networkPassphrase) {
        throw new Error('Wallet network details unavailable');
    }
}

function collectNoteIds(containerId) {
    const noteIds = [];
    document.querySelectorAll(`#${containerId} .note-input`).forEach(input => {
        const id = input.value.trim();
        if (id) noteIds.push(id);
    });
    return noteIds;
}

function collectOutputAmounts(containerId) {
    const out = [];
    document.querySelectorAll(`#${containerId} .output-amount`).forEach(input => {
        out.push(xlmToStroopsBigInt(input.value, { allowNegative: false }));
    });
    while (out.length < N_OUTPUTS) out.push(0n);
    return out.slice(0, N_OUTPUTS);
}

function collectAdvancedRecipients(containerId) {
    const noteKeys = [];
    const encKeys = [];
    document.querySelectorAll(`#${containerId} .advanced-output-row`).forEach(row => {
        const nk = row.querySelector('.output-note-key')?.value?.trim();
        const ek = row.querySelector('.output-enc-key')?.value?.trim();
        noteKeys.push(nk ? nk : null);
        encKeys.push(ek ? ek : null);
    });
    while (noteKeys.length < N_OUTPUTS) noteKeys.push(null);
    while (encKeys.length < N_OUTPUTS) encKeys.push(null);
    return { noteKeys: noteKeys.slice(0, N_OUTPUTS), encKeys: encKeys.slice(0, N_OUTPUTS) };
}

function txLink(hash) {
    return `https://stellar.expert/explorer/testnet/tx/${hash}`;
}

function sumInputNotesStroops(containerId) {
    const ids = collectNoteIds(containerId);
    let total = 0n;
    for (const id of ids) {
        const note = App.state.notes.find(n => n.id === id && !n.spent);
        if (!note) continue;
        total += noteAmountToStroopsBigInt(note.amount);
    }
    return total;
}

function setEqValidity(eq, isValid, shouldShow) {
    const validIcon = eq?.querySelector('[data-icon="valid"]');
    const invalidIcon = eq?.querySelector('[data-icon="invalid"]');
    if (!eq || !validIcon || !invalidIcon) return;

    if (!shouldShow) {
        validIcon.classList.add('hidden');
        invalidIcon.classList.add('hidden');
        eq.classList.remove('border-red-500/50', 'bg-red-500/5', 'border-emerald-500/50', 'bg-emerald-500/5');
        return;
    }

    validIcon.classList.toggle('hidden', !isValid);
    invalidIcon.classList.toggle('hidden', isValid);
    if (isValid) {
        eq.classList.remove('border-red-500/50', 'bg-red-500/5');
        eq.classList.add('border-emerald-500/50', 'bg-emerald-500/5');
    } else {
        eq.classList.add('border-red-500/50', 'bg-red-500/5');
        eq.classList.remove('border-emerald-500/50', 'bg-emerald-500/5');
    }
}

function updateWithdrawTotal() {
    const totalEl = document.getElementById('withdraw-total');
    const inputs = document.getElementById('withdraw-inputs');
    if (!totalEl || !inputs) return;
    const totalStroops = sumInputNotesStroops('withdraw-inputs');
    totalEl.textContent = `${stroopsBigIntToXlmText(totalStroops)} XLM`;
}

function updateTransferBalance() {
    const eq = document.getElementById('transfer-balance');
    const inputsEl = document.getElementById('transfer-inputs');
    const outputsEl = document.getElementById('transfer-outputs');
    if (!eq || !inputsEl || !outputsEl) return;

    const inputsTotalStroops = sumInputNotesStroops('transfer-inputs');
    let outputsTotalStroops = 0n;
    let outputsValid = true;
    let outputsAnyNonEmpty = false;
    document.querySelectorAll('#transfer-outputs .output-amount').forEach(input => {
        const raw = input.value;
        if (raw && raw.trim()) outputsAnyNonEmpty = true;
        const r = tryParseXlmToStroopsBigInt(raw, { allowNegative: false });
        if (!r.ok) {
            outputsValid = false;
            return;
        }
        outputsTotalStroops += r.value;
    });

    eq.querySelector('[data-eq="inputs"]').textContent = `Inputs: ${stroopsBigIntToXlmText(inputsTotalStroops)}`;
    eq.querySelector('[data-eq="outputs"]').textContent = `Outputs: ${stroopsBigIntToXlmText(outputsTotalStroops)}`;

    const shouldShow = inputsTotalStroops !== 0n || outputsTotalStroops !== 0n || outputsAnyNonEmpty;
    const isBalanced =
        outputsValid && inputsTotalStroops !== 0n && inputsTotalStroops === outputsTotalStroops && shouldShow;
    setEqValidity(eq, isBalanced, shouldShow);
}

function updateTransactBalance() {
    const eq = document.getElementById('transact-balance');
    const inputsEl = document.getElementById('transact-inputs');
    const outputsEl = document.getElementById('transact-outputs');
    const amountEl = document.getElementById('transact-amount');
    if (!eq || !inputsEl || !outputsEl || !amountEl) return;

    const inputsTotalStroops = sumInputNotesStroops('transact-inputs');
    const publicRes = tryParseXlmToStroopsBigInt(amountEl.value, { allowNegative: true });
    const publicValid = publicRes.ok;
    const publicStroops = publicRes.ok ? publicRes.value : 0n;
    let outputsTotalStroops = 0n;
    let outputsValid = true;
    let outputsAnyNonEmpty = false;
    document.querySelectorAll('#transact-outputs .output-amount').forEach(input => {
        const raw = input.value;
        if (raw && raw.trim()) outputsAnyNonEmpty = true;
        const r = tryParseXlmToStroopsBigInt(raw, { allowNegative: false });
        if (!r.ok) {
            outputsValid = false;
            return;
        }
        outputsTotalStroops += r.value;
    });

    const publicText = publicValid
        ? `${publicStroops >= 0n ? '+' : ''}${stroopsBigIntToXlmText(publicStroops)}`
        : 'Invalid';
    eq.querySelector('[data-eq="inputs"]').textContent = `Inputs: ${stroopsBigIntToXlmText(inputsTotalStroops)}`;
    eq.querySelector('[data-eq="public"]').textContent = `Public: ${publicText}`;
    eq.querySelector('[data-eq="outputs"]').textContent = `Outputs: ${stroopsBigIntToXlmText(outputsTotalStroops)}`;

    const publicAnyNonEmpty = !!(amountEl.value && amountEl.value.trim());
    const shouldShow =
        inputsTotalStroops !== 0n || publicStroops !== 0n || outputsTotalStroops !== 0n || outputsAnyNonEmpty || publicAnyNonEmpty;
    const isBalanced =
        publicValid &&
        outputsValid &&
        inputsTotalStroops + publicStroops === outputsTotalStroops &&
        shouldShow;
    setEqValidity(eq, isBalanced, shouldShow);
}

export const Transactions = {
    init() {
        // Deposit
        const depositOutputs = document.getElementById('deposit-outputs');
        depositOutputs?.replaceChildren();
        depositOutputs?.appendChild(Templates.createOutputRow(0, 10));
        depositOutputs?.appendChild(Templates.createOutputRow(1, 0));
        this._wireDeposit();

        // Withdraw
        const withdrawInputs = document.getElementById('withdraw-inputs');
        withdrawInputs?.replaceChildren();
        withdrawInputs?.appendChild(Templates.createInputRow(0));
        withdrawInputs?.appendChild(Templates.createInputRow(1));
        this._wireWithdraw();

        // Transfer
        const transferInputs = document.getElementById('transfer-inputs');
        const transferOutputs = document.getElementById('transfer-outputs');
        transferInputs?.replaceChildren();
        transferOutputs?.replaceChildren();
        transferInputs?.appendChild(Templates.createInputRow(0));
        transferInputs?.appendChild(Templates.createInputRow(1));
        transferOutputs?.appendChild(Templates.createOutputRow(0, 0));
        transferOutputs?.appendChild(Templates.createOutputRow(1, 0));
        this._wireTransfer();

        // Transact
        const transactInputs = document.getElementById('transact-inputs');
        const transactOutputs = document.getElementById('transact-outputs');
        transactInputs?.replaceChildren();
        transactOutputs?.replaceChildren();
        transactInputs?.appendChild(Templates.createInputRow(0));
        transactInputs?.appendChild(Templates.createInputRow(1));
        transactOutputs?.appendChild(Templates.createAdvancedOutputRow(0, 0));
        transactOutputs?.appendChild(Templates.createAdvancedOutputRow(1, 0));
        this._wireTransact();

        // Prefill withdraw recipient on connect
        App.events.addEventListener('wallet:ready', () => {
            const w = App.state.wallet.address;
            const withdrawRecipient = document.getElementById('withdraw-recipient');
            const transactRecipient = document.getElementById('transact-recipient');
            if (withdrawRecipient && !withdrawRecipient.value.trim()) withdrawRecipient.value = w;
            if (transactRecipient && !transactRecipient.value.trim()) transactRecipient.value = w;
        });

        App.events.addEventListener('notes:updated', () => {
            document.querySelectorAll('.note-input').forEach(input => {
                input.dispatchEvent(new Event('input', { bubbles: true }));
            });
            updateWithdrawTotal();
            updateTransferBalance();
            updateTransactBalance();
        });

        updateWithdrawTotal();
        updateTransferBalance();
        updateTransactBalance();
    },

    _wireDeposit() {
        const slider = document.getElementById('deposit-slider');
        const amount = document.getElementById('deposit-amount');
        const outputs = document.getElementById('deposit-outputs');
        const btn = document.getElementById('btn-deposit');

        const updateBalance = () => {
            const eq = document.getElementById('deposit-balance');
            if (!eq) return false;

            const depositRaw = amount?.value ?? '';
            const depositRes = tryParseXlmToStroopsBigInt(depositRaw, { allowNegative: false });
            const depositAnyNonEmpty = !!(depositRaw && String(depositRaw).trim());

            let outputsTotalStroops = 0n;
            let outputsValid = true;
            let outputsAnyNonEmpty = false;
            document.querySelectorAll('#deposit-outputs .output-amount').forEach(input => {
                const raw = input.value;
                if (raw && raw.trim()) outputsAnyNonEmpty = true;
                const r = tryParseXlmToStroopsBigInt(raw, { allowNegative: false });
                if (!r.ok) {
                    outputsValid = false;
                    return;
                }
                outputsTotalStroops += r.value;
            });

            eq.querySelector('[data-eq="input"]').textContent = `Deposit: ${
                depositRes.ok ? stroopsBigIntToXlmText(depositRes.value) : 'Invalid'
            }`;
            eq.querySelector('[data-eq="outputs"]').textContent = `Outputs: ${
                outputsValid ? stroopsBigIntToXlmText(outputsTotalStroops) : 'Invalid'
            }`;

            const shouldShow = depositAnyNonEmpty || outputsAnyNonEmpty;
            const isBalanced =
                shouldShow &&
                depositRes.ok &&
                outputsValid &&
                depositRes.value > 0n &&
                depositRes.value === outputsTotalStroops;
            const status = eq.querySelector('[data-eq="status"]');
            if (shouldShow) {
                if (isBalanced) {
                    status.innerHTML = '<svg class="w-5 h-5 text-emerald-500" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg>';
                    eq.classList.remove('border-red-500/50', 'bg-red-500/5');
                    eq.classList.add('border-emerald-500/50', 'bg-emerald-500/5');
                } else {
                    status.innerHTML = '<svg class="w-5 h-5 text-red-500" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="15" y1="9" x2="9" y2="15"/><line x1="9" y1="9" x2="15" y2="15"/></svg>';
                    eq.classList.add('border-red-500/50', 'bg-red-500/5');
                    eq.classList.remove('border-emerald-500/50', 'bg-emerald-500/5');
                }
            } else {
                status.innerHTML = '';
                eq.classList.remove('border-red-500/50', 'bg-red-500/5', 'border-emerald-500/50', 'bg-emerald-500/5');
            }
            return isBalanced;
        };

        slider?.addEventListener('input', () => {
            if (amount) amount.value = slider.value;
            updateBalance();
        });
        amount?.addEventListener('input', () => {
            if (slider) slider.value = String(Math.min(Math.max(0, Number(amount.value || 0)), 1000));
            updateBalance();
        });
        outputs?.addEventListener('input', updateBalance);

        document.querySelectorAll('[data-target="deposit-amount"]').forEach(spinnerBtn => {
            spinnerBtn.addEventListener('click', () => {
                const input = document.getElementById('deposit-amount');
                const val = parseFloat(input.value) || 0;
                input.value = spinnerBtn.classList.contains('spinner-up') ? String(val + 1) : String(Math.max(0, val - 1));
                input.dispatchEvent(new Event('input', { bubbles: true }));
            });
        });

        btn?.addEventListener('click', async () => {
            try {
                requireWalletReady();
                if (!updateBalance()) throw new Error('Deposit amount must equal sum of outputs');

                const userAddress = App.state.wallet.address;
                const membershipBlinding = parseMembershipBlinding('deposit-membership-blinding');
                const amountStroops = xlmToStroopsBigInt(amount.value, { allowNegative: false });
                const outputAmounts = collectOutputAmounts('deposit-outputs');

                setLoading(btn, 'Validating…');
                const onStatus = p => p?.message && setLoadingText(btn, p.message);
	                setLoadingText(btn, 'Proving…');
	                const proved = await getHandle().webClient.proveDeposit(
	                    userAddress,
	                    membershipBlinding,
	                    amountStroops,
	                    outputAmounts,
	                    onStatus,
	                );

	                if (proved == null) {
	                    Toast.show('Cannot prepare deposit yet (ASP registration required or membership blinding is incorrect).', 'error', 7000);
	                    return;
	                }

	                const config = await getContractConfig();
	                setLoadingText(btn, 'Ready to sign…');
	                const txHash = await submitProvedPoolTransact(proved, {
	                    address: userAddress,
	                    rpcUrl: App.state.wallet.sorobanRpcUrl,
	                    networkPassphrase: App.state.wallet.networkPassphrase,
	                    poolContractId: config?.pool,
	                }, { onStatus });
                Toast.show(
                    `Submitted: ${Utils.truncateHex(txHash, 10, 8)}`,
                    'success',
                    7000,
                    { linkUrl: txLink(txHash), linkAriaLabel: 'Open in Stellar Expert' }
                );
                App.events.dispatchEvent(new CustomEvent('tx:submitted', { detail: { txHash } }));
            } catch (e) {
                Toast.show(e?.message || 'Deposit failed', 'error', 7000);
            } finally {
                clearLoading(btn);
            }
        });

        updateBalance();
    },

    _wireWithdraw() {
        const inputs = document.getElementById('withdraw-inputs');
        const btn = document.getElementById('btn-withdraw');
        inputs?.addEventListener('input', updateWithdrawTotal);
        updateWithdrawTotal();

        btn?.addEventListener('click', async () => {
            try {
                requireWalletReady();
                const userAddress = App.state.wallet.address;
                const membershipBlinding = parseMembershipBlinding('withdraw-membership-blinding');
                const recipient = document.getElementById('withdraw-recipient')?.value?.trim() || userAddress;
                const inputNoteIds = collectNoteIds('withdraw-inputs');
                if (inputNoteIds.length === 0) throw new Error('Provide at least 1 input note');
                if (inputNoteIds.length > 2) throw new Error('At most 2 input notes are supported');

                setLoading(btn, 'Validating…');
                const onStatus = p => p?.message && setLoadingText(btn, p.message);
	                setLoadingText(btn, 'Proving…');
	                const proved = await getHandle().webClient.proveWithdraw(
	                    userAddress,
	                    membershipBlinding,
	                    recipient,
	                    inputNoteIds,
	                    onStatus,
	                );
	                if (proved == null) {
	                    Toast.show('Cannot prepare withdraw yet (ASP registration required or membership blinding is incorrect).', 'error', 7000);
	                    return;
	                }

	                const config = await getContractConfig();
	                setLoadingText(btn, 'Ready to sign…');
	                const txHash = await submitProvedPoolTransact(proved, {
	                    address: userAddress,
	                    rpcUrl: App.state.wallet.sorobanRpcUrl,
	                    networkPassphrase: App.state.wallet.networkPassphrase,
	                    poolContractId: config?.pool,
	                }, { onStatus });
                Toast.show(
                    `Submitted: ${Utils.truncateHex(txHash, 10, 8)}`,
                    'success',
                    7000,
                    { linkUrl: txLink(txHash), linkAriaLabel: 'Open in Stellar Expert' }
                );
                App.events.dispatchEvent(new CustomEvent('tx:submitted', { detail: { txHash } }));
            } catch (e) {
                Toast.show(e?.message || 'Withdraw failed', 'error', 7000);
            } finally {
                clearLoading(btn);
            }
        });
    },

    _wireTransfer() {
        const btn = document.getElementById('btn-transfer');
        const inputs = document.getElementById('transfer-inputs');
        const outputs = document.getElementById('transfer-outputs');
        const addressbookBtn = document.getElementById('transfer-addressbook-btn');
        addressbookBtn?.addEventListener('click', () => {
            App.state.addressBookFillTarget = { kind: 'transfer' };
            document.getElementById('section-tab-addressbook')?.click();
            document.getElementById('section-panel-addressbook')?.scrollIntoView({ behavior: 'smooth', block: 'start' });
        });

        inputs?.addEventListener('input', updateTransferBalance);
        outputs?.addEventListener('input', updateTransferBalance);
        updateTransferBalance();

        btn?.addEventListener('click', async () => {
            try {
                requireWalletReady();
                const userAddress = App.state.wallet.address;
                const membershipBlinding = parseMembershipBlinding('transfer-membership-blinding');
                const recipientNoteKey = document.getElementById('transfer-recipient-key')?.value?.trim();
                const recipientEncKey = document.getElementById('transfer-recipient-enc-key')?.value?.trim();
                if (!recipientNoteKey || !recipientEncKey) throw new Error('Recipient note key + encryption key are required');
                const inputNoteIds = collectNoteIds('transfer-inputs');
                if (inputNoteIds.length === 0) throw new Error('Provide at least 1 input note');
                if (inputNoteIds.length > 2) throw new Error('At most 2 input notes are supported');
                const outputAmounts = collectOutputAmounts('transfer-outputs');

                setLoading(btn, 'Validating…');
                const onStatus = p => p?.message && setLoadingText(btn, p.message);
	                setLoadingText(btn, 'Proving…');
	                const proved = await getHandle().webClient.proveTransfer(
	                    userAddress,
	                    membershipBlinding,
	                    recipientNoteKey,
	                    recipientEncKey,
	                    inputNoteIds,
	                    outputAmounts,
	                    onStatus,
	                );
	                if (proved == null) {
	                    Toast.show('Cannot prepare transfer yet (ASP registration required or membership blinding is incorrect).', 'error', 7000);
	                    return;
	                }

	                const config = await getContractConfig();
	                setLoadingText(btn, 'Ready to sign…');
	                const txHash = await submitProvedPoolTransact(proved, {
	                    address: userAddress,
	                    rpcUrl: App.state.wallet.sorobanRpcUrl,
	                    networkPassphrase: App.state.wallet.networkPassphrase,
	                    poolContractId: config?.pool,
	                }, { onStatus });
                Toast.show(
                    `Submitted: ${Utils.truncateHex(txHash, 10, 8)}`,
                    'success',
                    7000,
                    { linkUrl: txLink(txHash), linkAriaLabel: 'Open in Stellar Expert' }
                );
                App.events.dispatchEvent(new CustomEvent('tx:submitted', { detail: { txHash } }));
            } catch (e) {
                Toast.show(e?.message || 'Transfer failed', 'error', 7000);
            } finally {
                clearLoading(btn);
            }
        });
    },

    _wireTransact() {
        const slider = document.getElementById('transact-slider');
        const amount = document.getElementById('transact-amount');
        const inputs = document.getElementById('transact-inputs');
        const outputs = document.getElementById('transact-outputs');
        const btn = document.getElementById('btn-transact');

        slider?.addEventListener('input', () => {
            if (amount) amount.value = slider.value;
            updateTransactBalance();
        });
        amount?.addEventListener('input', () => {
            if (slider) slider.value = String(Math.min(Math.max(-500, Number(amount.value || 0)), 500));
            updateTransactBalance();
        });
        inputs?.addEventListener('input', updateTransactBalance);
        outputs?.addEventListener('input', updateTransactBalance);

        document.querySelectorAll('[data-target="transact-amount"]').forEach(spinnerBtn => {
            spinnerBtn.addEventListener('click', () => {
                const input = document.getElementById('transact-amount');
                const val = parseFloat(input.value) || 0;
                input.value = spinnerBtn.classList.contains('spinner-up') ? String(val + 1) : String(val - 1);
                input.dispatchEvent(new Event('input', { bubbles: true }));
            });
        });

        btn?.addEventListener('click', async () => {
            try {
                requireWalletReady();
                const userAddress = App.state.wallet.address;
                const membershipBlinding = parseMembershipBlinding('transact-membership-blinding');
                const extAmountStroops = xlmToStroopsBigInt(amount.value, { allowNegative: true });
                const extRecipient = document.getElementById('transact-recipient')?.value?.trim() || userAddress;
                if (extAmountStroops < 0n && !extRecipient) {
                    throw new Error('Withdrawal recipient is required when public amount is negative');
                }

                const inputNoteIds = collectNoteIds('transact-inputs');
                if (inputNoteIds.length > 2) throw new Error('At most 2 input notes are supported');
                const outputAmounts = collectOutputAmounts('transact-outputs');
                const { noteKeys, encKeys } = collectAdvancedRecipients('transact-outputs');

                setLoading(btn, 'Validating…');
                const onStatus = p => p?.message && setLoadingText(btn, p.message);
	                setLoadingText(btn, 'Proving…');
	                const proved = await getHandle().webClient.proveTransact(
	                    userAddress,
	                    membershipBlinding,
	                    extRecipient,
	                    extAmountStroops,
	                    inputNoteIds,
	                    outputAmounts,
	                    noteKeys,
	                    encKeys,
	                    onStatus,
	                );
	                if (proved == null) {
	                    Toast.show('Cannot prepare transaction yet (ASP registration required or membership blinding is incorrect).', 'error', 7000);
	                    return;
	                }

	                const config = await getContractConfig();
	                setLoadingText(btn, 'Ready to sign…');
	                const txHash = await submitProvedPoolTransact(proved, {
	                    address: userAddress,
	                    rpcUrl: App.state.wallet.sorobanRpcUrl,
	                    networkPassphrase: App.state.wallet.networkPassphrase,
	                    poolContractId: config?.pool,
	                }, { onStatus });
                Toast.show(
                    `Submitted: ${Utils.truncateHex(txHash, 10, 8)}`,
                    'success',
                    7000,
                    { linkUrl: txLink(txHash), linkAriaLabel: 'Open in Stellar Expert' }
                );
                App.events.dispatchEvent(new CustomEvent('tx:submitted', { detail: { txHash } }));
            } catch (e) {
                Toast.show(e?.message || 'Transact failed', 'error', 7000);
            } finally {
                clearLoading(btn);
            }
        });

        updateTransactBalance();
    },
};
