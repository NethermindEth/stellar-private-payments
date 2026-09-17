/**
 * The "Sign and pay with" pickers: which account signs and pays for an
 * on-chain transaction, while the connected account keeps owning the notes.
 *
 * Freighter does not list the accounts it holds, so beyond the owner the
 * choices are accounts the user pasted, remembered per owner across sessions.
 * Freighter signs as a requested account it holds whichever account is active;
 * one it does not hold fails at signing, which is where the user finds out.
 *
 * Each picker is a `[data-signing-account]` element. Pasted accounts are shared
 * by all pickers; each keeps its own selection. The settings drawer lists them
 * for removal.
 *
 * @module ui/signing-account
 */

import { StrKey, rpc } from '@stellar/stellar-sdk';
import { getCurrentRpcUrl } from '../wasm-facade.js';
import { addSigner, chosenSigner, rememberSigners, removeSigner } from '../signing-account.js';
import { App, Utils } from './core.js';
import { onEnter } from './keys.js';

const OTHER = '__other__';

function pickers() {
    return [...document.querySelectorAll('[data-signing-account]')].map((root) => ({
        scope: root.dataset.signingAccount,
        select: root.querySelector('[data-signing-select]'),
        other: root.querySelector('[data-signing-other]'),
        input: root.querySelector('[data-signing-input]'),
        use: root.querySelector('[data-signing-use]'),
        error: root.querySelector('[data-signing-error]'),
    }));
}

function picker(scope) {
    return pickers().find((p) => p.scope === scope) ?? null;
}

function render(p, selected = null) {
    const { select, other, input, error } = p;
    if (!select) return;
    const { address: owner, signers = [] } = App.state.wallet;

    const options = [];
    if (owner) options.push(new Option(`Connected wallet · ${Utils.shortAddress(owner)}`, owner));
    for (const signer of signers) options.push(new Option(Utils.shortAddress(signer), signer));
    options.push(new Option('Use another account…', OTHER));
    select.replaceChildren(...options);
    select.disabled = !owner;
    select.value = chosenSigner({ selected, owner, signers }) ?? OTHER;

    other?.classList.add('hidden');
    if (input) input.value = '';
    if (error) error.textContent = '';
}

function renderAll() {
    for (const p of pickers()) render(p);
    renderSettings();
}

// Re-render every picker after the shared list changed, keeping each picker's
// selection unless `overrides` names another for its scope. A selection no
// longer in the list falls back to the owner.
function renderKeepingSelections(overrides = {}) {
    for (const each of pickers()) {
        render(each, overrides[each.scope] ?? each.select?.value);
    }
    renderSettings();
}

function setSigners(signers) {
    const owner = App.state.wallet.address;
    App.state.wallet.signers = signers;
    rememberSigners(owner, signers);
}

function renderSettings() {
    const list = document.getElementById('settings-signing-accounts');
    const empty = document.getElementById('settings-signing-accounts-empty');
    if (!list) return;
    const { address: owner, signers = [] } = App.state.wallet;

    list.replaceChildren(...signers.map((signer) => {
        const item = document.createElement('li');
        item.setAttribute('data-testid', 'settings-signing-account');
        item.className = 'flex items-center justify-between gap-3 rounded-2xl border border-white/8 bg-ink-950 px-4 py-3';

        const address = document.createElement('span');
        address.className = 'min-w-0 break-all font-mono text-xs text-slate-100';
        address.textContent = signer;

        const remove = document.createElement('button');
        remove.type = 'button';
        remove.setAttribute('data-testid', 'settings-signing-account-remove');
        remove.setAttribute('aria-label', `Remove ${Utils.shortAddress(signer)}`);
        remove.className = 'shrink-0 rounded-full border border-rose-400/25 px-3 py-1.5 text-xs font-medium text-rose-100 transition hover:border-rose-400/40 hover:bg-rose-400/10';
        remove.textContent = 'Remove';
        remove.addEventListener('click', () => {
            setSigners(removeSigner(App.state.wallet.signers, signer));
            renderKeepingSelections();
        });

        item.append(address, remove);
        return item;
    }));

    if (empty) {
        empty.textContent = owner
            ? 'No accounts added. Add one under "Sign and pay with" in Move Funds or Advanced.'
            : 'Connect a wallet to see the accounts added to sign for it.';
        empty.classList.toggle('hidden', signers.length > 0);
    }
}

function useOtherAccount(p) {
    const address = p.input?.value.trim() ?? '';
    if (!StrKey.isValidEd25519PublicKey(address)) {
        if (p.error) p.error.textContent = 'Enter a valid Stellar address (G…).';
        return;
    }
    setSigners(addSigner(App.state.wallet.signers, address, App.state.wallet.address));
    // The new account joins every picker; only this one switches to it.
    renderKeepingSelections({ [p.scope]: address });
}

// The signer is the transaction's source account, so it has to exist on the
// network. The SDK reports a missing one only after proving, and without
// naming it, so look first. Only a definite "not found" stops the transaction;
// an RPC hiccup here leaves the SDK to decide.
async function ensureFunded(address) {
    const rpcUrl = getCurrentRpcUrl();
    if (!rpcUrl) return;
    try {
        await new rpc.Server(rpcUrl, { allowHttp: rpcUrl.startsWith('http://') }).getAccount(address);
    } catch (error) {
        if (/not found/i.test(error?.message ?? '')) {
            throw new Error(`${Utils.shortAddress(address)} isn't funded on this network. Fund it or pick another account to sign and pay with.`);
        }
    }
}

export const SigningAccount = {
    init() {
        for (const p of pickers()) {
            p.select?.addEventListener('change', () => {
                const choosingOther = p.select.value === OTHER;
                p.other?.classList.toggle('hidden', !choosingOther);
                if (choosingOther) p.input?.focus();
            });
            p.use?.addEventListener('click', () => useOtherAccount(p));
            onEnter(p.input, () => useOtherAccount(p));
        }

        App.events.addEventListener('wallet:ready', renderAll);
        App.events.addEventListener('wallet:disconnected', renderAll);
        renderAll();
    },

    /**
     * The account chosen in the `scope` picker, made the session's signer.
     *
     * @param {string} scope - The picker's `data-signing-account` value.
     * @returns {Promise<string>} The signing account; the owner unless another is picked.
     */
    async forTransaction(scope) {
        const select = picker(scope)?.select;
        // Falling back to the owner here would sign as the account the user
        // just moved away from, without the confirmation naming it.
        if (select?.value === OTHER) {
            throw new Error('Enter the account to sign and pay with, or pick one from the list.');
        }
        const { address: owner, signers } = App.state.wallet;
        const signer = chosenSigner({ selected: select?.value ?? null, owner, signers });
        if (signer !== owner) await ensureFunded(signer);
        App.state.wallet.signingAddress = signer;
        return signer;
    },
};
