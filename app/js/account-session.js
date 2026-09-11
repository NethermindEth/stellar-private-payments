/**
 * The wallet session a note account is opened with.
 *
 * Kept in its own module, free of any import, so it is reachable from Node for
 * unit testing: `ui/core.js`, where the session state itself lives, pulls in
 * `@stellar/stellar-sdk`, whose package exports cannot be resolved outside the
 * browser bundle.
 */

/**
 * Derive the `openAccount` arguments from the connected wallet session.
 *
 * Every layer below the app keeps the note owner and the account that signs for
 * it apart, so name both here instead of passing the owner alone and letting
 * the facade default the signer back to it out of sight. Until something can
 * choose a signing account, there is none and the owner signs for itself.
 *
 * @param {{
 *   networkPassphrase?: string | null,
 *   address?: string | null,
 *   signingAddress?: string | null,
 * }} wallet - `App.state.wallet`.
 * @returns {{ networkPassphrase: string|null, userAddress: string|null, signerAddress: string|null }}
 */
export function accountSession(wallet = {}) {
    const userAddress = wallet.address ?? null;
    return {
        networkPassphrase: wallet.networkPassphrase ?? null,
        userAddress,
        signerAddress: wallet.signingAddress ?? userAddress,
    };
}
