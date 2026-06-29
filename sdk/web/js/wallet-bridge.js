const BRIDGE_KEY = '__walletSignBridge';

/**
 * Install the global wallet bridge consumed by the Rust WASM signer.
 * @param {import('./freighter.js').FreighterSigner} signer
 * @param {string} networkPassphrase
 */
export function installWalletBridge(signer, networkPassphrase) {
  if (typeof globalThis.window === 'undefined') {
    throw new Error('Wallet bridge requires a browser environment');
  }

  globalThis.window[BRIDGE_KEY] = {
    async signAuthEntry(preimageXdr, opts = {}) {
      const { signedAuthEntry } = await signer.signAuthEntry(preimageXdr, {
        networkPassphrase,
        ...opts,
      });
      return signedAuthEntry;
    },

    async signTransaction(txXdr, opts = {}) {
      const { signedTxXdr } = await signer.signTransaction(txXdr, {
        networkPassphrase,
        ...opts,
      });
      return signedTxXdr;
    },

    async signMessage(message, opts = {}) {
      const { signedMessage } = await signer.signMessage(message, {
        networkPassphrase,
        ...opts,
      });
      return signedMessage;
    },
  };
}
