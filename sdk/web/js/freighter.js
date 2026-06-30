import {
  isAllowed,
  isConnected,
  requestAccess,
  setAllowed,
  signAuthEntry,
  signMessage,
  signTransaction,
} from '@stellar/freighter-api';

/**
 * Freighter wallet adapter for {@link Client.connect}.
 *
 * Pass an instance as the second argument: `Client.connect(options, signer)`.
 */
export class FreighterSigner {
  async ensureReady() {
    const conn = await isConnected();
    if (conn?.error || !conn?.isConnected) {
      throw new Error('Freighter not detected. Install from https://www.freighter.app/');
    }
    const allowed = await isAllowed();
    if (!allowed?.isAllowed) {
      const set = await setAllowed();
      if (set?.error) throw new Error(`Freighter access rejected: ${set.error}`);
    }
  }

  async getPublicKey() {
    await this.ensureReady();
    const access = await requestAccess();
    if (access?.error || !access?.address) {
      throw new Error('Failed to get public key from Freighter');
    }
    return access.address;
  }

  async signTransaction(xdr, opts = {}) {
    await this.ensureReady();
    const { signedTxXdr, signerAddress, error } = await signTransaction(xdr, opts);
    if (error) throw new Error(`Transaction signing failed: ${error}`);
    if (!signedTxXdr) throw new Error('No signed transaction returned');
    return { signedTxXdr, signerAddress };
  }

  async signAuthEntry(xdr, opts = {}) {
    await this.ensureReady();
    const { signedAuthEntry, signerAddress, error } = await signAuthEntry(xdr, opts);
    if (error) throw new Error(`Auth entry signing failed: ${error}`);
    if (!signedAuthEntry) throw new Error('No signed auth entry returned');
    return { signedAuthEntry, signerAddress };
  }

  async signMessage(message, opts = {}) {
    await this.ensureReady();
    const { signedMessage, signerAddress, error } = await signMessage(message, opts ?? {});
    if (error) throw new Error(`Message signing failed: ${error}`);
    if (!signedMessage) throw new Error('No signature returned');
    return { signedMessage: String(signedMessage), signerAddress };
  }
}
