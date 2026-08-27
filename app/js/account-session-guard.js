// Guards for the account-session cache in wasm-facade.js, which imports the
// wasm package and so cannot be loaded by plain `node --test`. These have no
// imports and are unit-tested directly.

/**
 * Reject a session request that does not name the note owner.
 *
 * Otherwise the SDK resolves the owner from `signer.getPublicKey()` — whichever
 * account the wallet has active at that instant.
 *
 * @param {string|null|undefined} userAddress
 * @returns {string}
 */
export function requireNoteOwner(userAddress) {
    if (typeof userAddress === 'string' && userAddress.length > 0) return userAddress;
    throw new Error(
        'openAccount requires userAddress: refusing to open a session for whichever account the wallet has active',
    );
}

/**
 * Whether a cached session may be reused. Both identities must match, and
 * absent values never match — including against each other, so an entry stored
 * under a null key can never be handed back.
 *
 * @param {{userAddress: string|null|undefined, signerAddress: string|null|undefined}} cached
 * @param {{userAddress: string|null|undefined, signerAddress: string|null|undefined}} requested
 * @returns {boolean}
 */
export function sessionMatchesCache(cached, requested) {
    return (
        isUsableAddress(cached.userAddress) &&
        isUsableAddress(cached.signerAddress) &&
        cached.userAddress === requested.userAddress &&
        cached.signerAddress === requested.signerAddress
    );
}

function isUsableAddress(value) {
    return typeof value === 'string' && value.length > 0;
}

/**
 * Supersession tokens for in-flight session opens.
 *
 * `openAccount` awaits the SDK and its caller can be abandoned meanwhile, so
 * without a token checked at the cache write the abandoned call can resolve
 * last and overwrite the newer session. A counter rather than a flag, because
 * two opens for the same address can be in flight at once.
 */
export function createSessionGeneration() {
    let current = 0;
    return {
        begin() {
            current += 1;
            return current;
        },
        invalidate() {
            current += 1;
        },
        isCurrent(token) {
            return token === current;
        },
    };
}
