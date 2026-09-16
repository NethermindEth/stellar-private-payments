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
 * The account that signs the next transaction.
 *
 * The picker's value when it is an account chosen this session; otherwise,
 * including before a wallet has connected the picker, the owner.
 *
 * @param {{ selected: string | null, owner: string | null, signers?: string[] }} choice
 * @returns {string | null}
 */
export function chosenSigner({ selected, owner, signers = [] }) {
    return selected && signers.includes(selected) ? selected : owner;
}

/**
 * Whether a withdrawal would publicly link the signing account to the owner.
 *
 * A withdrawal names its recipient on-chain and is sent by the signing account,
 * so paying the owner from another account puts both addresses in one
 * transaction.
 *
 * @param {{ owner: string | null, signer: string | null, recipient: string | null }} withdrawal
 * @returns {boolean}
 */
export function withdrawalLinksAccounts({ owner, signer, recipient }) {
    return Boolean(owner && signer && signer !== owner && recipient === owner);
}
