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
 * Freighter wallet adapter for {@link DeploymentClient.account}.
 *
 * SEP-0043 v1.2.1 standardizes getAddress, signTransaction, signAuthEntry,
 * signMessage, and getNetwork. The permission/connection methods used below
 * (isConnected, isAllowed, requestAccess, setAllowed) are Freighter-only
 * because SEP-0043 is still Draft and defines no connect/permission-gating
 * API. Pass an instance as the second argument: `client.account(options, signer)`.
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
      if (set?.error) throwFreighterError(set.error, 'Freighter access rejected');
    }
  }

  async getPublicKey() {
    await this.ensureReady();
    const access = await requestAccess();
    if (access?.error) throwFreighterError(access.error, 'Failed to get public key from Freighter');
    if (!access?.address) {
      throw new Error('No public key returned');
    }
    return access.address;
  }

  async signTransaction(xdr, opts = {}) {
    await this.ensureReady();
    const { signedTxXdr, signerAddress, error } = await signTransaction(xdr, opts);
    if (error) throwFreighterError(error, 'Transaction signing failed');
    if (!signedTxXdr) throw new Error('No signed transaction returned');
    return { signedTxXdr, signerAddress };
  }

  async signAuthEntry(xdr, opts = {}) {
    await this.ensureReady();
    const { signedAuthEntry, signerAddress, error } = await signAuthEntry(xdr, opts);
    if (error) throwFreighterError(error, 'Auth entry signing failed');
    if (!signedAuthEntry) throw new Error('No signed auth entry returned');
    return { signedAuthEntry, signerAddress };
  }

  async signMessage(message, opts = {}) {
    await this.ensureReady();
    const { signedMessage, signerAddress, error } = await signMessage(message, opts ?? {});
    if (error) throwFreighterError(error, 'Message signing failed');
    if (!signedMessage) throw new Error('No signature returned');
    return { signedMessage: String(signedMessage), signerAddress };
  }
}

/**
 * Throw a proper Error for a Freighter error payload.
 *
 * Uses error.message so the thrown error is readable (instead of the raw
 * "[object Object]" string), preserves the original error as `cause`, and
 * carries the SEP-0043 user-rejection code (-4) so callers and the SDK's
 * wasm signer wrapper can detect it.
 */
function throwFreighterError(error, fallbackMessage) {
  const message = error?.message || fallbackMessage;
  const err = new Error(message);
  if (error?.code === -4) {
    err.code = -4;
  }
  err.cause = error;
  throw err;
}
