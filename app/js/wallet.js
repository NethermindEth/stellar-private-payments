import {
    WatchWalletChanges,
    getAddress,
    getNetworkDetails,
    isAllowed,
    isConnected,
    requestAccess,
    setAllowed,
    signAuthEntry,
    signTransaction,
    signMessage
} from '@stellar/freighter-api';
/**
 * Request wallet access and return the active public key.
 *
 * Throws when the extension is missing or unavailable.
 *
 * @returns {Promise<void>}
 */
async function assertFreighterInstalled() {
    const conn = await isConnected();
    if (conn?.error) {
        throw normalizeWalletError(conn.error, "Failed to check Freighter connection");
    }
    if (!conn?.isConnected) {
        throw new Error("Freighter not detected. Install from https://www.freighter.app/");
    }
}

/**
 * Ensure Freighter is installed, connected, and allowed for this site.
 *
 * Optionally requests wallet access and returns the active public key.
 *
 * @param {Object} [opts] - Optional configuration.
 * @param {boolean} [opts.requestAddress=false] - Whether to request and return the active address.
 * @returns {Promise<string|void>} - Connected Stellar public key when requested.
 */
async function ensureFreighterReady(opts = {}) {
    const { requestAddress = false } = opts;

    await assertFreighterInstalled();

    const allowed = await isAllowed();
    if (allowed?.error) {
        throw normalizeWalletError(allowed.error, "Failed to check Freighter allow-list");
    }

    if (!allowed?.isAllowed) {
        const set = await setAllowed();
        if (set?.error) {
            throw normalizeWalletError(set.error, "Freighter access rejected");
        }
    }

    if (requestAddress) {
        const access = await requestAccess();
        if (access?.error) {
            throw normalizeWalletError(access.error, "Freighter access request failed");
        }
        if (!access?.address) {
            throw new Error("No public key returned");
        }
        return access.address;
    }
}

/**
 * Request wallet access and return the active public key.
 *
 * Validates Freighter availability, prompts for access if needed,
 * and returns the connected Stellar address.
 *
 * @returns {Promise<string>} - Connected Stellar public key (G...).
 */
export async function connectWallet() {
    return await ensureFreighterReady({requestAddress: true});
}

/**
 * Return the active address only if Freighter is already connected AND allowed
 * for this origin, without prompting. Returns null otherwise. Lets a page
 * restore a session already established elsewhere in the app (same origin)
 * without showing a connection popup.
 * @returns {Promise<string|null>}
 */
export async function getConnectedAddress() {
    try {
        const conn = await isConnected();
        if (!conn?.isConnected) return null;
        const allowed = await isAllowed();
        if (!allowed?.isAllowed) return null;
        const res = await getAddress();
        if (res?.error || !res?.address) return null;
        return res.address;
    } catch {
        return null;
    }
}

/**
 * Fetch the currently active public key from Freighter without prompting.
 * @returns {Promise<string>}
 */
export async function getWalletAddress() {
    await ensureFreighterReady();
    const res = await getAddress();
    if (res?.error) {
        throw normalizeWalletError(res.error, "Failed to get active Freighter address");
    }
    if (!res?.address) {
        throw new Error("No public key returned");
    }
    return res.address;
}

/**
 * Watch Freighter for wallet address/network changes.
 * @param {{intervalMs?: number, onChange: function}} opts
 * @returns {function} stop watcher
 */
export function startWalletWatcher(opts) {
    const { intervalMs = 3000, onChange } = opts || {};
    const watcher = new WatchWalletChanges(intervalMs);
    const res = watcher.watch((info) => {
        try {
            onChange?.(info);
        } catch (e) {
            console.warn('[Wallet] watch callback failed:', e);
        }
    });
    if (res?.error) {
        throw normalizeWalletError(res.error, 'Failed to start wallet watcher');
    }
    return () => watcher.stop();
}

/**
 * Fetch current network details from Freighter.
 *
 * Useful for displaying network name and ensuring app/network alignment.
 *
 * @returns {Promise<{network: string, networkUrl: string, networkPassphrase: string, sorobanRpcUrl?: string}>}
 */
export async function getWalletNetwork() {
    const details = await getNetworkDetails();
    if (details?.error) {
        throw normalizeWalletError(details.error, "Failed to get Freighter network details");
    }

    const { network, networkUrl, networkPassphrase, sorobanRpcUrl } = details;
    return { network, networkUrl, networkPassphrase, sorobanRpcUrl };
}

/**
 * Normalize Freighter errors to a consistent shape.
 *
 * Marks common rejection phrases as USER_REJECTED for UI handling.
 *
 * @param {Object} error - Raw Freighter error payload.
 * @param {string} fallbackMessage - Default message when none provided.
 * @returns {Error} - Error with `code` set to USER_REJECTED or WALLET_ERROR.
 */
function normalizeWalletError(error, fallbackMessage = "Wallet error") {
    const message = error?.message || fallbackMessage;
    const lower = String(message).toLowerCase();
    const err = new Error(message);
    err.code = /reject|declin|denied|cancel/.test(lower) ? 'USER_REJECTED' : 'WALLET_ERROR';
    err.cause = error;
    return err;
}

/**
 * Request the user to sign a transaction XDR via Freighter.
 *
 * Ensures wallet access, then returns the signed XDR and signer address.
 *
 * @param {string} transactionXdr - Unsigned transaction XDR (base64).
 * @param {Object} opts - Optional signing context.
 * @param {string} [opts.networkPassphrase] - Network passphrase for signing.
 * @param {string} [opts.address] - Specific account to sign with.
 * @returns {Promise<{signedTxXdr: string, signerAddress: string}>}
 */
export async function signWalletTransaction(transactionXdr, opts = {}) {
    await ensureFreighterReady();

    const { signedTxXdr, signerAddress, error } = await signTransaction(transactionXdr, opts);
    if (error) {
        throw normalizeWalletError(error, 'Transaction signature failed');
    }

    return { signedTxXdr, signerAddress };
}

/**
 * Request the user to sign a Soroban auth preimage via Freighter.
 *
 * Takes HashIdPreimage XDR (base64); returns raw signature bytes for authorizeEntry.
 *
 * @param {string} entryXdr - Authorization preimage XDR (base64).
 * @param {Object} opts - Optional signing context.
 * @param {string} [opts.networkPassphrase] - Network passphrase for signing.
 * @param {string} [opts.address] - Specific account to sign with.
 * @returns {Promise<{signedAuthEntry: string | null, signerAddress: string}>}
 */
export async function signWalletAuthEntry(entryXdr, opts = {}) {
    await ensureFreighterReady();

    const { signedAuthEntry, signerAddress, error } = await signAuthEntry(entryXdr, opts);
    if (error) {
        throw normalizeWalletError(error, 'Auth entry signature failed');
    }

    return { signedAuthEntry, signerAddress };
}

/**
 * Request the user to sign an arbitrary message via Freighter.
 *
 * Used for deriving encryption keys deterministically.
 *
 * @param {string} message - Message to sign.
 * @param {Object} [opts] - Optional signing context.
 * @param {string} [opts.address] - Specific account to sign with.
 * @param {string} [opts.networkPassphrase] - Network passphrase for signing context.
 * @returns {Promise<{signedMessage: string | null, signerAddress: string}>}
 */
export async function signWalletMessage(message, opts = {}) {
    const { skipEnsureReady = false, ...freighterOpts } = opts || {};
    if (!skipEnsureReady) {
        await ensureFreighterReady();
    }

    console.log('[Wallet] Requesting message signature for:', message.substring(0, 30) + '...');
    const result = await signMessage(message, freighterOpts);
    console.log('[Wallet] signMessage result:', {
        hasSignedMessage: !!result?.signedMessage,
        hasError: !!result?.error,
        error: result?.error,
    });

    const { signedMessage, signerAddress, error } = result || {};
    if (error) {
        throw normalizeWalletError(error, 'Message signature failed');
    }
    // If SignMessage returns null
    if (!signedMessage) {
        throw new Error('No signature returned. User may have rejected the request.');
    }

    return { signedMessage, signerAddress };
}
