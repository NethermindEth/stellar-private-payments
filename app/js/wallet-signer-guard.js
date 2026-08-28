// Signature guards. No imports, so these can be unit-tested without a bundler
// (@stellar/freighter-api's minified CJS build does not resolve under plain
// `node --test`, so anything importing wallet.js is untestable there).

/**
 * Throw if the wallet signed with an account other than the one requested.
 *
 * Skips when either address is absent — an unaddressed call, or a wallet that
 * omits `signerAddress`. The error code is deliberately not USER_REJECTED: a
 * wrong signer is not a decline and must not be reported as one.
 *
 * @param {string} label - Call site label for the error message.
 * @param {string|undefined} requestedAddress
 * @param {string|undefined} signerAddress
 */
export function verifySignerAddress(label, requestedAddress, signerAddress) {
    if (!requestedAddress || !signerAddress || !signerAddress.trim() || requestedAddress === signerAddress) return;
    const err = new Error(
        `${label}: wallet signed with ${signerAddress}, but ${requestedAddress} was requested`,
    );
    err.code = 'SIGNER_ADDRESS_MISMATCH';
    throw err;
}

/**
 * Throw if the wallet returned no signed value.
 *
 * Older Freighter versions return a falsy signature instead of an error
 * payload when the user declines, so treat it as a rejection rather than
 * letting an undefined XDR propagate as if signing had succeeded.
 *
 * @param {string} message
 * @param {string|null|undefined} value
 */
export function assertSignedValue(message, value) {
    if (value) return;
    const err = new Error(message);
    err.code = 'USER_REJECTED';
    throw err;
}

/**
 * Bind a signing adapter to one account and network.
 *
 * The pinned values are spread last so a caller cannot override them.
 * `address` is what verifySignerAddress compares the wallet's response
 * against, so letting contract.Client supply it would make the check validate
 * the wrong pair.
 *
 * Returned as arrow-function properties rather than methods: contract.Client
 * invokes these options unbound, so anything relying on `this` throws.
 *
 * @param {{signMessage: Function, signTransaction: Function, signAuthEntry: Function}} adapter
 * @param {{address: string, networkPassphrase: string}} identity
 * @returns {{signMessage: Function, signTransaction: Function, signAuthEntry: Function}}
 */
export function createPinnedSigner(adapter, identity) {
    const { address, networkPassphrase } = identity || {};
    // A partial identity would make verifySignerAddress skip silently.
    if (!address || !networkPassphrase) {
        throw new Error('createPinnedSigner requires both address and networkPassphrase');
    }
    const pin = (opts) => ({ ...opts, networkPassphrase, address });
    return {
        signMessage: (message, opts = {}) => adapter.signMessage(message, pin(opts)),
        signTransaction: (xdr, opts = {}) => adapter.signTransaction(xdr, pin(opts)),
        signAuthEntry: (xdr, opts = {}) => adapter.signAuthEntry(xdr, pin(opts)),
    };
}
