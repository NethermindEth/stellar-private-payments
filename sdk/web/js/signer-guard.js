/**
 * Confirm Freighter actually signed with the account it was asked to.
 *
 * This is a second, independent check of the same guarantee
 * sdk/web/src/signer.rs's WalletSigner::call() already enforces on every
 * caller that reaches Freighter through the wasm boundary — added here too
 * so the guarantee holds for FreighterSigner on its own terms, not only for
 * whichever wrapper a caller happens to route through. Skips silently when
 * there is no requested address to compare against.
 *
 * The thrown error's `code` is deliberately not `-4` (SEP-0043 user
 * rejection) and its message avoids the reject/denied/cancelled wording
 * freighter.js's `throwFreighterError` fallback-message contract warns
 * against — a wrong signer is not a decline, and must not be reported as
 * one.
 *
 * Kept in its own module, with no imports, so it can be unit-tested
 * directly: `@stellar/freighter-api` is deliberately not a dependency of
 * this package (consumers such as app/ supply it, bundled in at build time
 * via esbuild's `--alias`), so freighter.js itself cannot be loaded by a
 * plain Node unit test outside that bundling step.
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
 * Confirm the wallet actually returned a signed value.
 *
 * Older Freighter versions return a falsy signature instead of an error
 * payload when the user declines. Coded `-4` (SEP-0043's own user-rejection
 * code) rather than left uncoded, matching FreighterSigner's own convention
 * for real wallet-reported rejections (see `throwFreighterError` in
 * freighter.js) and the wasm boundary's (see sdk/web/src/signer.rs and
 * sdk/web/src/client/mod.rs's `pool_err`) — an uncoded error here was
 * previously unclassifiable as a decline anywhere downstream (app/js/ui/
 * errors.js's isUserCancelledError checks for `-4` or the string
 * `'USER_REJECTED'`; app/js/wallet.js uses the string convention instead —
 * see that file's own assertSignedValue for why the two files don't share
 * one literal code value).
 *
 * @param {string} message - Error message to raise when `value` is falsy.
 * @param {string|null|undefined} value - The signed value the wallet returned.
 */
export function assertSignedValue(message, value) {
  if (value) return;
  const err = new Error(message);
  err.code = -4;
  throw err;
}

export function createPinnedSigner(adapter, identity) {
  const { address, networkPassphrase } = identity || {};
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
