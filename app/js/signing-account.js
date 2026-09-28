/**
 * Rules for signing with an account other than the note owner.
 *
 * Kept in its own module, free of any import, so it is reachable from Node for
 * unit testing — the same reason as `account-session.js`.
 */

/**
 * Add an account chosen to sign, keeping the list free of duplicates and of
 * the owner, who is always available and never needs remembering.
 *
 * @param {string[]} signers - Accounts already chosen this session.
 * @param {string} address - The account just chosen.
 * @param {string | null} owner - The note owner.
 * @returns {string[]} A new list.
 */
export function addSigner(signers = [], address, owner) {
    if (!address || address === owner || signers.includes(address)) return [...signers];
    return [...signers, address];
}

/**
 * Remove an account from those chosen to sign.
 *
 * @param {string[]} signers - Accounts chosen so far.
 * @param {string} address - The account to remove.
 * @returns {string[]} A new list.
 */
export function removeSigner(signers = [], address) {
    return signers.filter((signer) => signer !== address);
}

/**
 * Freighter's active account, when it is worth offering as a signer: shared
 * with the app, and neither the owner nor an account already added.
 *
 * @param {{ active: string | null, owner: string | null, signers?: string[] }} accounts
 * @returns {string | null}
 */
export function activeSuggestion({ active, owner, signers = [] }) {
    return active && owner && active !== owner && !signers.includes(active) ? active : null;
}

/**
 * The account that signs the next transaction.
 *
 * The explicitly selected owner, added account, or Freighter account on offer.
 * Missing or stale selections require a new choice instead of using the owner.
 *
 * @param {{
 *   selected: string | null,
 *   owner: string | null,
 *   signers?: string[],
 *   active?: string | null,
 * }} choice
 * @returns {string | null}
 */
export function chosenSigner({ selected, owner, signers = [], active = null }) {
    if (!owner || !selected) return null;
    if (selected === owner) return owner;
    if (signers.includes(selected)) return selected;
    return selected === activeSuggestion({ active, owner, signers }) ? selected : null;
}

/**
 * Whether a withdrawal to the owner needs a privacy warning.
 *
 * A withdrawal names its recipient on-chain and is sent by the signing account,
 * so paying the owner from another account puts both addresses in one
 * transaction. When the owner also signs, reusing the same account for deposits
 * and withdrawals can link its activity on-chain.
 *
 * @param {{ owner: string | null, signer: string | null, recipient: string | null }} withdrawal
 * @returns {boolean}
 */
export function withdrawalLinksAccounts({ owner, signer, recipient }) {
    return Boolean(owner && signer && recipient === owner);
}

/** Privacy guidance when the deposit account signs a non-deposit transaction. */
export function signingPrivacyWarning({ owner, signer }) {
    return owner && signer === owner
        ? 'Signing with your deposit account can link this transaction to your deposits. Use an unrelated signing account for better privacy.'
        : '';
}

const SIGNERS_KEY_PREFIX = 'poolstellar_signers:';

/**
 * The accounts the user added to sign for `owner`, kept across sessions.
 *
 * Kept per owner, since an account added to sign for one owner may be the
 * owner itself under another.
 *
 * @param {string | null} owner - The note owner.
 * @param {Storage | undefined} [storage] - Defaults to `localStorage`.
 * @returns {string[]}
 */
export function rememberedSigners(owner, storage = globalThis.localStorage) {
    if (!owner) return [];
    try {
        const stored = JSON.parse(storage?.getItem(SIGNERS_KEY_PREFIX + owner) ?? '[]');
        if (!Array.isArray(stored)) return [];
        return stored.reduce((signers, address) => (
            typeof address === 'string' ? addSigner(signers, address, owner) : signers
        ), []);
    } catch {
        return [];
    }
}

/**
 * Remember the accounts added to sign for `owner`.
 *
 * @param {string | null} owner - The note owner.
 * @param {string[]} signers
 * @param {Storage | undefined} [storage] - Defaults to `localStorage`.
 */
export function rememberSigners(owner, signers, storage = globalThis.localStorage) {
    if (!owner) return;
    try {
        storage?.setItem(SIGNERS_KEY_PREFIX + owner, JSON.stringify(signers));
    } catch (e) {
        console.error('[SigningAccount] rememberSigners failed:', e);
    }
}
