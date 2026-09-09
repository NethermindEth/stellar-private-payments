/**
 * The rule that a wallet must sign with the account it was asked to sign with.
 *
 * Kept in its own module, free of any import, so it is reachable from Node for
 * unit testing: `wallet.js` pulls in `@stellar/freighter-api`, whose package
 * exports cannot be resolved outside the browser bundle.
 */

/**
 * Refuse a signature the wallet produced with an account other than the one
 * requested.
 *
 * Freighter returns success with `signerAddress` set to the *active* account
 * when it does not hold the requested one: no error, no rejection, and nothing
 * in the approval prompt naming the address that was asked for. Comparing the
 * two is what catches the substitution.
 *
 * Skipped when the caller pinned no address (nothing to compare) or the wallet
 * reported none. The wording deliberately avoids "rejected"/"denied"/
 * "cancelled": normalizeWalletError's classifier substring-matches those, and a
 * substitution is not a user cancellation.
 *
 * @param {string} method - Wallet method name, for the message.
 * @param {string | undefined} requested - Address the caller asked to sign with.
 * @param {string | undefined} reported - Address the wallet says signed.
 * @throws {Error} with `code = 'SIGNER_ADDRESS_MISMATCH'` when the two differ.
 */
export function verifySignerAddress(method, requested, reported) {
    if (!requested || !reported || requested === reported) {
        return;
    }
    const err = new Error(
        `${method}: the wallet signed with a different account than the one requested.`,
    );
    err.code = 'SIGNER_ADDRESS_MISMATCH';
    throw err;
}
