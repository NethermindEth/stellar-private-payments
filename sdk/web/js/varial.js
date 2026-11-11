import {
    isAllowed,
    isConnected,
    requestAccess,
    setAllowed,
    signAuthEntry,
    signMessage,
    signTransaction,
} from "@stellar/varial-sdk";

/**
 * Varial wallet adapter for {@link Client.account}.
 *
 * SEP-0043 v1.2.1 standardizes getAddress, signTransaction, signAuthEntry,
 * signMessage, and getNetwork. The permission/connection methods used below
 * (isConnected, isAllowed, requestAccess, setAllowed) are Varial-only
 * because SEP-0043 is still Draft and defines no connect/permission-gating
 * API. Pass an instance as the second argument: `client.account(options, signer)`.
 */
export class VarialSigner {
    async ensureReady() {
        const conn = await isConnected();
        if (conn?.error || !conn?.isConnected) {
            throw new Error(
                "Varial not detected. Install from https://www.varial.app/",
            );
        }
        const allowed = await isAllowed();
        if (!allowed?.isAllowed) {
            const set = await setAllowed();
            if (set?.error)
                throwVarialError(
                    set.error,
                    "Varial access could not be granted",
                );
        }
    }

    async getPublicKey() {
        await this.ensureReady();
        const access = await requestAccess();
        if (access?.error)
            throwVarialError(
                access.error,
                "Failed to get public key from Varial",
            );
        if (!access?.address) {
            throw new Error("No public key returned");
        }
        return access.address;
    }

    async signTransaction(xdr, opts = {}) {
        await this.ensureReady();
        const { signedTxXdr, signerAddress, error } = await signTransaction(
            xdr,
            opts,
        );
        if (error) throwVarialError(error, "Transaction signing failed");
        if (!signedTxXdr) throw new Error("No signed transaction returned");
        return { signedTxXdr, signerAddress };
    }

    async signAuthEntry(xdr, opts = {}) {
        await this.ensureReady();
        const { signedAuthEntry, signerAddress, error } = await signAuthEntry(
            xdr,
            opts,
        );
        if (error) throwVarialError(error, "Auth entry signing failed");
        if (!signedAuthEntry) throw new Error("No signed auth entry returned");
        return { signedAuthEntry, signerAddress };
    }

    async signMessage(message, opts = {}) {
        await this.ensureReady();
        const { signedMessage, signerAddress, error } = await signMessage(
            message,
            opts ?? {},
        );
        if (error) throwVarialError(error, "Message signing failed");
        if (!signedMessage) throw new Error("No signature returned");
        return { signedMessage: String(signedMessage), signerAddress };
    }
}

/**
 * Throw a proper Error for a Varial error payload.
 *
 * Uses error.message so the thrown error is readable (instead of the raw
 * "[object Object]" string), preserves the original error as `cause`, and
 * carries the SEP-0043 user-rejection code (-4) so callers and the SDK's
 * wasm signer wrapper can detect it.
 *
 * `fallbackMessage` must not contain rejection wording ("rejected", "denied",
 * "cancelled"): app-side classifiers fall back to substring matching when a
 * wallet does not set code -4, so such wording would make an arbitrary wallet
 * failure self-classify as a user cancellation.
 */
function throwVarialError(error, fallbackMessage) {
    const message = error?.message || fallbackMessage;
    const err = new Error(message);
    if (error?.code === -4) {
        err.code = -4;
    }
    err.cause = error;
    throw err;
}
