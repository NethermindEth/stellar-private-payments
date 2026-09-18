/**
 * The "Sign and pay with" pickers: which account signs and pays for an
 * on-chain transaction, while the connected account keeps owning the notes.
 *
 * Freighter does not list the accounts it holds, only the active one, and that
 * only once the user allowed it for this site. So beyond the owner the choices
 * are the accounts added before, remembered per owner across sessions, and
 * Freighter's active account, offered until it signs a transaction and so
 * joins them. When Freighter keeps its active account from the app, a picker
 * option asks for it. Any account can also be pasted.
 *
 * Freighter signs as a requested account it holds whichever account is active;
 * one it does not hold fails at signing, which is where the user finds out.
 *
 * Each picker is a `[data-signing-account]` element. Added accounts are shared
 * by all pickers; each keeps its own selection. The settings drawer lists them
 * for removal.
 *
 * @module ui/signing-account
 */

import { StrKey, rpc } from '@stellar/stellar-sdk';
import { getCurrentRpcUrl } from '../wasm-facade.js';
import { connectWallet } from '../wallet.js';
import {
    activeSuggestion,
    addSigner,
    chosenSigner,
    rememberSigners,
    removeSigner,
    signingPrivacyWarning,
} from '../signing-account.js';
import { App, Toast, Utils } from './core.js';
import { onEnter } from './keys.js';

const OTHER = '__other__';
const REQUEST_ACTIVE = '__request_active__';

function pickers() {
    return [...document.querySelectorAll('[data-signing-account]')].map((root) => ({
        scope: root.dataset.signingAccount,
        select: root.querySelector('[data-signing-select]'),
        other: root.querySelector('[data-signing-other]'),
        input: root.querySelector('[data-signing-input]'),
        use: root.querySelector('[data-signing-use]'),
        error: root.querySelector('[data-signing-error]'),
        warning: root.querySelector('[data-signing-warning]'),
    }));
}

function picker(scope) {
    return pickers().find((p) => p.scope === scope) ?? null;
}

function updateWarning(p) {
    if (!p.warning) return;
    const warning = signingPrivacyWarning({ owner: App.state.wallet.address, signer: p.select?.value });
    p.warning.textContent = warning;
    p.warning.classList.toggle('hidden', !warning);
}

function render(p, selected = null) {
    const { select, other, input, error } = p;
    if (!select) return;
    const { address: owner, signers = [], activeAddress: active = null } = App.state.wallet;
    const suggestion = activeSuggestion({ active, owner, signers });

    const prompt = new Option('Choose an account to sign and pay…', '');
    prompt.disabled = true;
    prompt.hidden = true;
    const options = [prompt];
    if (owner) {
        const depositOption = new Option(`Deposit account · ${Utils.shortAddress(owner)}`, owner);
        depositOption.dataset.privacyWarning = 'true';
        options.push(depositOption);
    }
    for (const signer of signers) options.push(new Option(Utils.shortAddress(signer), signer));
    if (suggestion) {
        options.push(new Option(Utils.shortAddress(suggestion), suggestion));
    }
    // An empty active address is Freighter keeping its account from this site.
    if (owner && active === '') {
        options.push(new Option('Use the account active in Freighter…', REQUEST_ACTIVE));
    }
    options.push(new Option('Enter another address…', OTHER));
    select.replaceChildren(...options);
    select.disabled = !owner;

    // A picker in the middle of pasting an account stays there.
    if (owner && selected === OTHER) {
        select.value = OTHER;
        updateWarning(p);
        return;
    }
    select.value = chosenSigner({ selected, owner, signers, active }) ?? '';
    updateWarning(p);

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
// longer in the list requires a new choice.
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
    App.events.dispatchEvent(new Event('wallet:signers-changed'));
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

// Ask Freighter to share its active account, and offer it in `p`.
async function requestActiveAccount(p) {
    try {
        const address = await connectWallet();
        App.state.wallet.activeAddress = address;
        renderKeepingSelections({ [p.scope]: address });
    } catch (error) {
        renderKeepingSelections({ [p.scope]: '' });
        Toast.show(error?.message || 'Freighter did not share its active account', 'error');
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
                updateWarning(p);
                if (p.select.value === REQUEST_ACTIVE) {
                    requestActiveAccount(p);
                    return;
                }
                const choosingOther = p.select.value === OTHER;
                p.other?.classList.toggle('hidden', !choosingOther);
                if (choosingOther) p.input?.focus();
            });
            p.use?.addEventListener('click', () => useOtherAccount(p));
            onEnter(p.input, () => useOtherAccount(p));
        }

        App.events.addEventListener('wallet:ready', renderAll);
        App.events.addEventListener('wallet:disconnected', renderAll);
        App.events.addEventListener('wallet:active-changed', () => renderKeepingSelections());
        renderAll();
    },

    /**
     * The account chosen in the `scope` picker, made the session's signer.
     *
     * @param {string} scope - The picker's `data-signing-account` value.
     * @param {{ ownerOnly?: boolean }} options - Deposits must be signed by the owner.
     * @returns {Promise<string>} The explicitly chosen account, or the owner for deposits.
     */
    async forTransaction(scope, { ownerOnly = false } = {}) {
        if (ownerOnly) {
            App.state.wallet.signingAddress = App.state.wallet.address;
            return App.state.wallet.address;
        }
        const select = picker(scope)?.select;
        // Falling back to the owner here would sign as the account the user
        // just moved away from, without the confirmation naming it.
        if (select?.value === OTHER || select?.value === REQUEST_ACTIVE) {
            throw new Error('Enter the account to sign and pay with, or pick one from the list.');
        }
        const { address: owner, signers, activeAddress: active } = App.state.wallet;
        const signer = chosenSigner({ selected: select?.value ?? null, owner, signers, active });
        if (!signer) throw new Error('Choose an account to sign and pay with.');
        if (signer !== owner) await ensureFunded(signer);
        App.state.wallet.signingAddress = signer;
        return signer;
    },

    /**
     * Remember `signer` for the owner once the user confirmed a transaction
     * with it. This is how Freighter's active account, offered in the picker,
     * joins the added accounts; one already added, or the owner, is left as
     * it is.
     *
     * @param {string | null} signer - As returned by {@link forTransaction}.
     */
    keep(signer) {
        const { address: owner, signers = [] } = App.state.wallet;
        const added = addSigner(signers, signer, owner);
        if (added.length === signers.length) return;
        setSigners(added);
        renderKeepingSelections();
    },
};
