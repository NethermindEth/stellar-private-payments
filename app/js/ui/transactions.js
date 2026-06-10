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

function getActivePoolContractId(config) {
    const pools = Array.isArray(config?.pools) ? config.pools : [];
    const selected = pools.find(p => p?.enabled) || pools[0];
    const poolContractId = selected?.poolContractId;
    if (!poolContractId) throw new Error("Pool contract ID not available");
    return poolContractId;
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

let TOKEN_DECIMALS = 7;
let TOKEN_SYMBOL = "XLM";

function baseUnitsPerToken() {
    return 10n ** BigInt(TOKEN_DECIMALS);
}

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
        fracVal = fracPart ? BigInt(fracPart.padEnd(TOKEN_DECIMALS, '0')) : 0n;
    } catch {
        return { ok: false, error: 'Invalid amount.' };
    }

    const abs = intVal * baseUnitsPerToken() + fracVal;
    const isNegative = signChar === '-';
    if (isNegative && !allowNegative && abs !== 0n) {
        return { ok: false, error: 'Amount must be non-negative.' };
    }

    return { ok: true, value: isNegative ? -abs : abs };
}

function decimalToBaseUnitsBigInt(amount, opts) {
    const res = tryParseXlmToStroopsBigInt(amount, opts);
    if (!res.ok) throw new Error(res.error);
    return res.value;
}

function baseUnitsBigIntToDecimalText(baseUnits) {
    let v = typeof baseUnits === 'bigint' ? baseUnits : 0n;
    const isNeg = v < 0n;
    if (isNeg) v = -v;

    const absStr = v.toString().padStart(TOKEN_DECIMALS + 1, '0');
    const intPart = absStr.slice(0, -TOKEN_DECIMALS);
    const fracRaw = absStr.slice(-TOKEN_DECIMALS);
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
        out.push(decimalToBaseUnitsBigInt(input.value, { allowNegative: false }));
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

function isAdvancedMode(checkboxId) {
    return document.getElementById(checkboxId)?.checked ?? false;
}

function wireSpendAdvancedToggle(checkboxId, advancedSectionId, amountSectionId = null) {
    const cb = document.getElementById(checkboxId);
    const advancedSection = document.getElementById(advancedSectionId);
    const amountSection = amountSectionId ? document.getElementById(amountSectionId) : null;
    const update = () => {
        const advanced = !!cb?.checked;
        advancedSection?.classList.toggle('hidden', !advanced);
        if (amountSection) {
            amountSection.classList.toggle('hidden', advanced);
        }
    };
    cb?.addEventListener('change', update);
    update();
}

function makePoolSubmitFn(poolContractId, userAddress, onStatus) {
    return proved => submitProvedPoolTransact(proved, {
        address: userAddress,
        rpcUrl: App.state.wallet.sorobanRpcUrl,
        networkPassphrase: App.state.wallet.networkPassphrase,
        poolContractId,
    }, { onStatus });
}

function showSubmittedToasts(hashes) {
    if (!Array.isArray(hashes) || hashes.length === 0) return;
    const lastHash = hashes[hashes.length - 1];
    const message = hashes.length === 1
        ? `Submitted: ${Utils.truncateHex(lastHash, 10, 8)}`
        : `Submitted ${hashes.length} transactions. Last: ${Utils.truncateHex(lastHash, 10, 8)}`;
    Toast.show(
        message,
        'success',
        7000,
        { linkUrl: txLink(lastHash), linkAriaLabel: 'Open in Stellar Expert' },
    );
    for (const txHash of hashes) {
        App.events.dispatchEvent(new CustomEvent('tx:submitted', { detail: { txHash } }));
    }
}

const ASP_NOT_READY_MSG = 'Cannot prepare transaction yet (ASP registration required or membership blinding is incorrect).';

function spendPlanStepCount(plan) {
    const n = plan?.stepCount ?? plan?.step_count;
    if (typeof n === 'number' && Number.isFinite(n)) return Math.trunc(n);
    if (typeof n === 'bigint') return Number(n);
    return null;
}

function spendPlanHintText(stepCount) {
    if (stepCount === 1) return 'Requires 1 on-chain transaction.';
    return `Requires ${stepCount} on-chain transactions.`;
}

async function fetchSpendPlanStepCount(userAddress, poolContractId, amountStroops) {
    const plan = await getHandle().webClient.planSpend(userAddress, poolContractId, amountStroops);
    const stepCount = spendPlanStepCount(plan);
    if (stepCount == null || stepCount < 1) {
        throw new Error('Could not plan spend');
    }
    return stepCount;
}

async function requireSpendPlanApproval(userAddress, poolContractId, amountStroops) {
    const stepCount = await fetchSpendPlanStepCount(userAddress, poolContractId, amountStroops);
    if (stepCount > 1) {
        const ok = window.confirm(
            `This spend requires ${stepCount} on-chain transactions (${stepCount} wallet approvals). Continue?`,
        );
        if (!ok) return null;
    }
    return stepCount;
}

async function submitProvedAdvanced(ctx, proved) {
    if (proved == null) {
        Toast.show(ASP_NOT_READY_MSG, 'error', 7000);
        return;
    }
    ctx.setLoadingText(ctx.btn, 'Ready to sign…');
    const txHash = await submitProvedPoolTransact(proved, {
        address: ctx.userAddress,
        rpcUrl: App.state.wallet.sorobanRpcUrl,
        networkPassphrase: App.state.wallet.networkPassphrase,
        poolContractId: ctx.poolContractId,
    }, { onStatus: ctx.onStatus });
    showSubmittedToasts([txHash]);
}

function callProveTransact(ctx, {
    extRecipient,
    extAmount,
    inputNoteIds,
    outputAmounts,
    noteKeys,
    encKeys,
}) {
    return getHandle().webClient.proveTransact(
        ctx.poolContractId,
        ctx.userAddress,
        ctx.membershipBlinding,
        extRecipient,
        extAmount,
        inputNoteIds,
        outputAmounts,
        noteKeys,
        encKeys,
        ctx.onStatus,
    );
}

async function runSpendFlow({
    btn,
    advancedCheckboxId,
    amountInputId,
    membershipBlindingId,
    proveAdvanced,
    executeSimple,
}) {
    requireWalletReady();
    const userAddress = App.state.wallet.address;
    const membershipBlinding = parseMembershipBlinding(membershipBlindingId);
    const advanced = isAdvancedMode(advancedCheckboxId);

    setLoading(btn, 'Validating…');
    const onStatus = p => p?.message && setLoadingText(btn, p.message);
    const setLoadingTextForBtn = text => setLoadingText(btn, text);
    const config = await getContractConfig();
    const poolContractId = getActivePoolContractId(config);
    const ctx = {
        btn,
        userAddress,
        membershipBlinding,
        poolContractId,
        onStatus,
        setLoadingText: setLoadingTextForBtn,
    };

    if (advanced) {
        await proveAdvanced(ctx);
        return;
    }

    const amountRes = tryParseXlmToStroopsBigInt(
        document.getElementById(amountInputId)?.value,
        { allowNegative: false },
    );
    if (!amountRes.ok) throw new Error(amountRes.error);
    if (amountRes.value <= 0n) throw new Error('Amount must be greater than zero');

    const stepCount = await requireSpendPlanApproval(userAddress, poolContractId, amountRes.value);
    if (stepCount == null) return;

    setLoadingText(btn, stepCount === 1 ? 'Proving…' : `Proving (1/${stepCount})…`);
    const submitFn = makePoolSubmitFn(poolContractId, userAddress, onStatus);
    const hashes = await executeSimple(ctx, amountRes.value, submitFn);
    if (hashes == null) {
        Toast.show(ASP_NOT_READY_MSG, 'error', 7000);
        return;
    }
    showSubmittedToasts(hashes);
}

function wireSpendPlanHint(amountInputId, hintId, advancedCheckboxId) {
    const input = document.getElementById(amountInputId);
    const hint = document.getElementById(hintId);
    let timer;

    const hide = () => {
        if (!hint) return;
        hint.textContent = '';
        hint.classList.add('hidden');
    };

    const update = async () => {
        if (isAdvancedMode(advancedCheckboxId)) {
            hide();
            return;
        }
        if (!App.state.wallet.connected || !App.state.wallet.address) {
            hide();
            return;
        }
        const res = tryParseXlmToStroopsBigInt(input?.value, { allowNegative: false });
        if (!res.ok || res.value <= 0n) {
            hide();
            return;
        }
        try {
            const config = await getContractConfig();
            const poolContractId = getActivePoolContractId(config);
            const stepCount = await fetchSpendPlanStepCount(
                App.state.wallet.address,
                poolContractId,
                res.value,
            );
            if (hint) {
                hint.textContent = spendPlanHintText(stepCount);
                hint.classList.remove('hidden');
            }
        } catch {
            hide();
        }
    };

    input?.addEventListener('input', () => {
        clearTimeout(timer);
        timer = setTimeout(update, 400);
    });
    document.getElementById(advancedCheckboxId)?.addEventListener('change', update);
    App.events.addEventListener('wallet:ready', update);
    App.events.addEventListener('notes:updated', update);
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
    totalEl.textContent = `${baseUnitsBigIntToDecimalText(totalStroops)} ${TOKEN_SYMBOL}`;
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

    eq.querySelector('[data-eq="inputs"]').textContent = `Inputs: ${baseUnitsBigIntToDecimalText(inputsTotalStroops)}`;
    eq.querySelector('[data-eq="outputs"]').textContent = `Outputs: ${baseUnitsBigIntToDecimalText(outputsTotalStroops)}`;

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
        ? `${publicStroops >= 0n ? '+' : ''}${baseUnitsBigIntToDecimalText(publicStroops)}`
        : 'Invalid';
    eq.querySelector('[data-eq="inputs"]').textContent = `Inputs: ${baseUnitsBigIntToDecimalText(inputsTotalStroops)}`;
    eq.querySelector('[data-eq="public"]').textContent = `Public: ${publicText}`;
    eq.querySelector('[data-eq="outputs"]').textContent = `Outputs: ${baseUnitsBigIntToDecimalText(outputsTotalStroops)}`;

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

        // Prefill withdraw recipient on connect + account change (always overwrite)
        App.events.addEventListener('wallet:ready', (e) => {
            const nextAddress = e?.detail?.address || App.state.wallet.address;
            if (!nextAddress) return;

            const withdrawRecipient = document.getElementById('withdraw-recipient');
            const transactRecipient = document.getElementById('transact-recipient');
            if (withdrawRecipient) withdrawRecipient.value = nextAddress;
            if (transactRecipient) transactRecipient.value = nextAddress;
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
        const amount = document.getElementById('deposit-amount');
        const outputs = document.getElementById('deposit-outputs');
        const btn = document.getElementById('btn-deposit');
        wireSpendAdvancedToggle('deposit-advanced-mode', 'deposit-advanced-section');

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
                depositRes.ok ? baseUnitsBigIntToDecimalText(depositRes.value) : 'Invalid'
            }`;
            eq.querySelector('[data-eq="outputs"]').textContent = `Outputs: ${
                outputsValid ? baseUnitsBigIntToDecimalText(outputsTotalStroops) : 'Invalid'
            }`;

            const shouldShow = depositAnyNonEmpty || outputsAnyNonEmpty;
            const isBalanced =
                shouldShow &&
                depositRes.ok &&
                outputsValid &&
                depositRes.value > 0n &&
                depositRes.value === outputsTotalStroops;
            setEqValidity(eq, isBalanced, shouldShow);
            return isBalanced;
        };

        amount?.addEventListener('input', updateBalance);
        outputs?.addEventListener('input', updateBalance);

        btn?.addEventListener('click', async () => {
            try {
                requireWalletReady();
                const advanced = isAdvancedMode('deposit-advanced-mode');
                const userAddress = App.state.wallet.address;
                const membershipBlinding = parseMembershipBlinding('deposit-membership-blinding');

                let amountStroops;
                let outputAmounts;
                if (advanced) {
                    if (!updateBalance()) throw new Error('Deposit amount must equal sum of outputs');
                    amountStroops = decimalToBaseUnitsBigInt(amount.value, { allowNegative: false });
                    outputAmounts = collectOutputAmounts('deposit-outputs');
                } else {
                    const amountRes = tryParseXlmToStroopsBigInt(amount?.value, { allowNegative: false });
                    if (!amountRes.ok) throw new Error(amountRes.error);
                    if (amountRes.value <= 0n) throw new Error('Amount must be greater than zero');
                    amountStroops = amountRes.value;
                    outputAmounts = [amountStroops, 0n];
                }

                setLoading(btn, 'Validating…');
                const onStatus = p => p?.message && setLoadingText(btn, p.message);
                const config = await getContractConfig();
                const poolContractId = getActivePoolContractId(config);
                setLoadingText(btn, 'Proving…');
                const proved = await getHandle().webClient.proveDeposit(
                    poolContractId,
                    userAddress,
                    membershipBlinding,
                    amountStroops,
                    outputAmounts,
                    onStatus,
                );

                if (proved == null) {
                    Toast.show(ASP_NOT_READY_MSG, 'error', 7000);
                    return;
                }

                setLoadingText(btn, 'Ready to sign…');
                const txHash = await submitProvedPoolTransact(proved, {
                    address: userAddress,
                    rpcUrl: App.state.wallet.sorobanRpcUrl,
                    networkPassphrase: App.state.wallet.networkPassphrase,
                    poolContractId,
                }, { onStatus });
                showSubmittedToasts([txHash]);
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
        wireSpendAdvancedToggle('withdraw-advanced-mode', 'withdraw-advanced-section', 'withdraw-amount-section');
        wireSpendPlanHint('withdraw-amount', 'withdraw-plan-hint', 'withdraw-advanced-mode');
        updateWithdrawTotal();

        btn?.addEventListener('click', async () => {
            try {
                await runSpendFlow({
                    btn,
                    advancedCheckboxId: 'withdraw-advanced-mode',
                    amountInputId: 'withdraw-amount',
                    membershipBlindingId: 'withdraw-membership-blinding',
                    proveAdvanced: async (ctx) => {
                        const recipient = document.getElementById('withdraw-recipient')?.value?.trim()
                            || ctx.userAddress;
                        const inputNoteIds = collectNoteIds('withdraw-inputs');
                        if (inputNoteIds.length === 0) throw new Error('Provide at least 1 input note');
                        if (inputNoteIds.length > 2) throw new Error('At most 2 input notes are supported');

                        const total = sumInputNotesStroops('withdraw-inputs');
                        if (total <= 0n) {
                            throw new Error('Selected notes must have a positive total');
                        }

                        ctx.setLoadingText(ctx.btn, 'Proving…');
                        const proved = await callProveTransact(ctx, {
                            extRecipient: recipient,
                            extAmount: -total,
                            inputNoteIds,
                            outputAmounts: [0n, 0n],
                            noteKeys: [null, null],
                            encKeys: [null, null],
                        });
                        await submitProvedAdvanced(ctx, proved);
                    },
                    executeSimple: async (ctx, amountStroops, submitFn) => {
                        const recipient = document.getElementById('withdraw-recipient')?.value?.trim()
                            || ctx.userAddress;
                        return getHandle().webClient.executeWithdraw(
                            ctx.poolContractId,
                            ctx.userAddress,
                            ctx.membershipBlinding,
                            recipient,
                            amountStroops,
                            submitFn,
                            ctx.onStatus,
                        );
                    },
                });
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
        wireSpendAdvancedToggle('transfer-advanced-mode', 'transfer-advanced-section', 'transfer-amount-section');
        wireSpendPlanHint('transfer-amount', 'transfer-plan-hint', 'transfer-advanced-mode');
        updateTransferBalance();

        btn?.addEventListener('click', async () => {
            try {
                const recipientNoteKey = document.getElementById('transfer-recipient-key')?.value?.trim();
                const recipientEncKey = document.getElementById('transfer-recipient-enc-key')?.value?.trim();
                if (!recipientNoteKey || !recipientEncKey) {
                    throw new Error('Recipient note key + encryption key are required');
                }

                await runSpendFlow({
                    btn,
                    advancedCheckboxId: 'transfer-advanced-mode',
                    amountInputId: 'transfer-amount',
                    membershipBlindingId: 'transfer-membership-blinding',
                    proveAdvanced: async (ctx) => {
                        const inputNoteIds = collectNoteIds('transfer-inputs');
                        if (inputNoteIds.length === 0) throw new Error('Provide at least 1 input note');
                        if (inputNoteIds.length > 2) throw new Error('At most 2 input notes are supported');
                        if (!updateTransferBalance()) throw new Error('Input notes must equal output amounts');

                        const outputAmounts = collectOutputAmounts('transfer-outputs');

                        ctx.setLoadingText(ctx.btn, 'Proving…');
                        const proved = await callProveTransact(ctx, {
                            extRecipient: ctx.poolContractId,
                            extAmount: 0n,
                            inputNoteIds,
                            outputAmounts,
                            noteKeys: [recipientNoteKey, recipientNoteKey],
                            encKeys: [recipientEncKey, recipientEncKey],
                        });
                        await submitProvedAdvanced(ctx, proved);
                    },
                    executeSimple: async (ctx, amountStroops, submitFn) => getHandle().webClient.executeTransfer(
                        ctx.poolContractId,
                        ctx.userAddress,
                        ctx.membershipBlinding,
                        amountStroops,
                        recipientNoteKey,
                        recipientEncKey,
                        submitFn,
                        ctx.onStatus,
                    ),
                });
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
                const extAmountStroops = decimalToBaseUnitsBigInt(amount.value, { allowNegative: true });
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
	                const config = await getContractConfig();
                const poolContractId = getActivePoolContractId(config);
	                setLoadingText(btn, 'Proving…');
	                const proved = await callProveTransact(
	                    {
	                        userAddress,
	                        membershipBlinding,
	                        poolContractId,
	                        onStatus,
	                    },
	                    {
	                        extRecipient,
	                        extAmount: extAmountStroops,
	                        inputNoteIds,
	                        outputAmounts,
	                        noteKeys,
	                        encKeys,
	                    },
	                );
	                if (proved == null) {
	                    Toast.show('Cannot prepare transaction yet (ASP registration required or membership blinding is incorrect).', 'error', 7000);
	                    return;
	                }

	                setLoadingText(btn, 'Ready to sign…');
	                const txHash = await submitProvedPoolTransact(proved, {
	                    address: userAddress,
	                    rpcUrl: App.state.wallet.sorobanRpcUrl,
	                    networkPassphrase: App.state.wallet.networkPassphrase,
	                    poolContractId: poolContractId,
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
