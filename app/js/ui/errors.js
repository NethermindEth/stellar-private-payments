/**
 * Error handling utilities for user-friendly transaction error messages.
 *
 * Classifies an error by its structured code, its contract error code, or a
 * fixed message the SDK or browser is known to produce. Anything else gets a
 * generic message, with the raw text kept as copyable details. Pure: no DOM.
 * @module ui/errors
 */

import { friendlyErrorMessage } from '../facade-errors.js';

/**
 * Contract error code mappings.
 * These map to the Error enums defined in the Soroban contracts.
 */
export const CONTRACT_ERRORS = {
    // Pool contract errors
    pool: {
        7: 'Proof verification failed. The ZK proof is invalid.',
        8: 'Invalid merkle root. The pool state may have changed.',
        9: 'This note has already been spent.',
        18: 'Deposits into this pool are paused. Withdrawals and transfers still work.',
        20: 'No admin transfer is pending.',
        21: 'The contract does not run the code this pool accepts.',
        22: 'The pool holds less than this would pay out, so it refused. Tell the pool operator.',
        // Only a fee claim, sent from admin.html, can fail with this.
        23: 'The claim asks for more than the fees collected, most likely because another claim went through first. The Pools tab\'s Fees column now shows what is left to claim.',
        24: 'The pool does not pay itself or its token contract. Choose another recipient.',
    },
    // Groth16 verifier errors
    verifier: {
        0: 'Proof verification failed.',
    },
    // ASP Non-Membership errors
    aspNonMembership: {
        2: 'Key not found in ASP tree.',
        3: 'A key is already on the blocklist.',
        4: 'ASP non-membership proof verification failed.',
        7: 'No admin transfer is pending.',
    },
    // ASP Membership errors
    aspMembership: {
        6: 'No admin transfer is pending.',
    },
    // Public key registry errors
    registry: {
        1: 'The keys to register are malformed.',
        2: 'Only an account address can register keys.',
        3: 'The note key is not in its canonical form.',
        4: 'The encryption key is not in its canonical form.',
        5: 'This address is already registered with different keys, and a registration can\'t be changed.',
        6: 'The registry rejected the proof that you hold your note key.',
    },
};

/** Code of a {@link UserFacingError}. */
export const USER_FACING = 'USER_FACING';

/**
 * An error whose message is already written for the user: an input to fix or a
 * state to wait out. Shown as is, never as "… failed".
 */
export class UserFacingError extends Error {
    constructor(message) {
        super(message);
        this.name = 'UserFacingError';
        this.code = USER_FACING;
    }
}

const PROOF_FAILED = 'Proof verification failed. This can happen if the pool state changed during proof generation. Please ensure your membership in the proper ASP tree is synced and try again.';
const NETWORK_ERROR = 'Network error. Please check your connection and try again.';

/**
 * What a transaction refused with `Error(Contract, #N)` tells the user. The
 * code alone does not name the contract; a spend's codes are the pool's.
 */
const CONTRACT_MESSAGES = {
    0: PROOF_FAILED, // Groth16 verifier InvalidProof
    7: PROOF_FAILED,
    8: 'Pool state has changed. Please wait for sync to complete and try again.',
    9: 'This note has already been spent. Please refresh your notes and try with different inputs.',
    18: CONTRACT_ERRORS.pool[18],
    21: CONTRACT_ERRORS.pool[21],
    22: CONTRACT_ERRORS.pool[22],
    24: CONTRACT_ERRORS.pool[24],
};

/**
 * Fixed messages the browser and the SDK give when a request cannot reach the
 * network. Kept to those exact texts: a word like "fetch" or "timeout" also
 * appears in errors that have nothing to do with the connection.
 */
const NETWORK_MESSAGES = [
    /\bnetwork error: /i, // SDK rpc::Error::Reqwest
    /\bRPC request timed out\b/, // SDK rpc::Error::Timeout
    /\bFailed to fetch\b/, // Chromium's fetch TypeError
    /\bNetworkError when attempting to fetch resource\b/, // Firefox's fetch TypeError
    /^(TypeError: )?Load failed$/, // Safari's fetch TypeError
];

/**
 * Known messages, each with what the user sees instead.
 */
const KNOWN_MESSAGES = [
    {
        // The wallet signed as another account than the one asked for: Freighter
        // does not hold the chosen account and signs as its active one instead.
        // Worded by the SDK's signer (sdk/web/src/signer.rs) for transactions,
        // and by wallet-signer-guard.js for the app's own wallet calls.
        test: /\bnot the requested\b|\bsigned with a different account\b/i,
        message: 'The account chosen to sign and pay isn\'t in Freighter, so it signed with another account. Add the account to Freighter or pick another one.',
    },
    {
        // The pool reads an allowlist the manifest does not name.
        test: /deployment manifest does not name/i,
        message: 'This pool now uses an allowlist this version of the app does not know. Reload the page. If that does not help, the operator has not published the updated deployment yet.',
    },
    {
        // SDK rpc::Error::NotQueued
        test: /\bTRY_AGAIN_LATER\b/,
        message: 'The network was too busy to take the transaction. An earlier copy may still go through, so check your balance before you send it again.',
    },
    {
        // SDK pool_err: AspMembershipSync::RegisterAtASP
        test: /^register at ASP before transacting$/,
        message: 'Your account is not registered with the Association Set Provider yet. Share your note public key and ASP secret with the ASP provider, then try again.',
    },
    {
        // SDK pool_err: AspMembershipSync::SyncRequired
        test: /^indexer sync in progress; try again shortly$/,
        message: 'Still syncing with the network. Try again in a moment.',
    },
    {
        test: /^Local data is locked\. Use Unlock to continue\.$/,
        message: 'Local data is locked. Use Unlock to continue.',
    },
    {
        // ASP membership issues
        test: (msg) => {
            const lower = msg.toLowerCase();
            return lower.includes('membership') && (lower.includes('not found') || lower.includes('leaf'));
        },
        message: 'Your ASP membership could not be verified. Ensure you are registered with the Association Set Provider.',
    },
    {
        // Stellar's txINSUFFICIENT_BALANCE and the like. The pool's token may
        // not be XLM, but the network fee always is.
        test: /insufficient/i,
        message: 'Not enough funds. The account that signs and pays needs enough of the pool\'s token for the amount, and XLM for the network fee.',
    },
    {
        test: /\bresources?\b.*\bexceed/i,
        message: 'The transaction needs more network resources than one transaction may use. Try again; if it keeps failing, tell the pool operator.',
    },
    {
        // The SDK's "transaction simulation failed" and rpc::Error::Simulation,
        // for a contract error with no message of its own above.
        test: /\bsimulation failed\b/i,
        message: 'The network rejected the transaction when it was tested, so nothing was sent.',
    },
    {
        test: /\bmerkle proof\b.*\bnot\b/i,
        message: 'Merkle proof not found. Please sync the pool state and try again.',
    },
    {
        test: /\bout of sync\b|\broot mismatch\b/i,
        message: 'Pool state is out of sync. Please wait for sync to complete and try again.',
    },
];

const matches = (test, msg) => (typeof test === 'function' ? test(msg) : test.test(msg));

/**
 * Safely extracts the error message from an error object.
 * @param {Error|string|unknown} error - The error to extract message from
 * @returns {string} The error message
 */
function getErrorMessage(error) {
    if (!error) return '';
    if (typeof error === 'string') return error;
    if (error instanceof Error) return error.message || String(error);
    if (typeof error === 'object' && 'message' in error) return String(error.message ?? '');
    return String(error);
}

/**
 * Extracts the wallet-authored portion of an error message.
 *
 * Wallet adapters wrap the original wallet error and expose it as `cause`
 * (`normalizeWalletError` in wallet.js, `throwFreighterError` in the SDK's
 * freighter.js, `copy_js_error_fields` in sdk/web/src/signer.rs). The composed
 * `message` therefore mixes the wallet's text with prefixes we author
 * ourselves, e.g. "signer.signTransaction failed: <wallet text>".
 *
 * Substring classification must only see the wallet's own words — otherwise any
 * message we write that happens to contain "rejected"/"denied"/"cancelled"
 * silently classifies itself as a user cancellation. Falls back to the composed
 * message when no cause text is available.
 *
 * @param {Error|string|unknown} error - The error to extract text from
 * @returns {string} Wallet-provided message when present, else the full message
 */
function walletProvidedMessage(error) {
    const cause = error?.cause;
    if (typeof cause === 'string' && cause) return cause;
    if (cause && typeof cause === 'object' && cause.message) return String(cause.message);
    return getErrorMessage(error);
}

/**
 * Checks if an error indicates the user cancelled/rejected the action.
 * @param {Error|string|unknown} error - The error to check
 * @returns {boolean} True if user cancelled
 */
export function isUserCancelledError(error) {
    // SEP-0043 v1.2.1 defines -4 as the user-rejection code. Some adapters
    // also expose a string 'USER_REJECTED' code for app-level compatibility.
    // The structured code is authoritative; the substring check below is only a
    // fallback for wallets/versions that do not set it, and deliberately looks
    // at the wallet's own text rather than the full composed message.
    if (error && (error.code === -4 || error.code === 'USER_REJECTED')) {
        return true;
    }
    const msg = walletProvidedMessage(error).toLowerCase();
    return msg.includes('rejected') ||
           msg.includes('denied') ||
           msg.includes('cancelled') ||
           msg.includes('user_rejected');
}

/**
 * @typedef {object} ErrorDescription
 * @property {'cancelled'|'user'|'contract'|'known'|'network'|'unknown'} kind
 * @property {string} message - What the user sees.
 * @property {string} details - The raw error text to copy, or '' when the
 *   message already is the whole story (a cancellation or a user-facing error).
 */

/**
 * Describes an error for the user.
 * @param {Error|string|unknown} error - The error object or message
 * @param {string} [operationType='Transaction'] - Deposit, Withdraw, etc.
 * @returns {ErrorDescription}
 */
export function describeError(error, operationType = 'Transaction') {
    if (isUserCancelledError(error)) {
        return { kind: 'cancelled', message: `${operationType} cancelled.`, details: '' };
    }
    const raw = getErrorMessage(error).trim();
    if (error?.code === USER_FACING && raw) {
        return { kind: 'user', message: raw, details: '' };
    }
    // A refusal the SDK codes that pool-errors.js has no wording for.
    if (error?.code === 'WITHDRAWAL_TO_CONTRACT') {
        return { kind: 'user', message: 'You can\'t withdraw to a pool or token contract of this deployment, because nobody could move the tokens out again. Withdraw to another address.', details: '' };
    }
    const contractCode = raw.match(/Error\(Contract,\s*#(\d+)\)/)?.[1];
    const contractMessage = contractCode != null ? CONTRACT_MESSAGES[Number(contractCode)] : undefined;
    if (contractMessage) {
        return { kind: 'contract', message: contractMessage, details: raw };
    }
    const known = KNOWN_MESSAGES.find(({ test }) => matches(test, raw));
    if (known) return { kind: 'known', message: known.message, details: raw };
    const facade = raw && friendlyErrorMessage(raw);
    if (facade && facade !== raw) return { kind: 'known', message: facade, details: raw };
    if (NETWORK_MESSAGES.some((pattern) => pattern.test(raw))) {
        return { kind: 'network', message: NETWORK_ERROR, details: raw };
    }
    return { kind: 'unknown', message: `${operationType} failed. Something went wrong.`, details: raw };
}

/**
 * Gets a user-friendly error message for a transaction error.
 * @param {Error|string|unknown} error - The error object or message
 * @param {string} [operationType='Transaction'] - Type of operation (Deposit, Withdraw, etc.)
 * @returns {string} User-friendly error message
 */
export function getFriendlyErrorMessage(error, operationType = 'Transaction') {
    return describeError(error, operationType).message;
}

/**
 * Describes a failed public key registration.
 * @param {Error|string|unknown} error - The error object
 * @returns {ErrorDescription}
 */
export function describeRegistrationError(error) {
    if (isUserCancelledError(error)) {
        return { kind: 'cancelled', message: 'Registration cancelled.', details: '' };
    }
    const rawMessage = getErrorMessage(error);
    const registry = (message) => ({ kind: 'contract', message, details: rawMessage });
    // Only the first host error failed the call; the event log may hold others.
    const hostError = rawMessage.match(/Error\((\w+),\s*#?(\w+)\)/);
    if (hostError?.[1] === 'Contract') {
        const registryMessage = CONTRACT_ERRORS.registry[parseInt(hostError[2], 10)];
        if (registryMessage) return registry(registryMessage);
    }
    // ed25519_verify traps with this when a signature doesn't verify.
    if (hostError?.[1] === 'Crypto' && hostError[2] === 'InvalidInput') {
        return registry('The registry rejected a signature. Sign the registration message with the account you are registering.');
    }
    if (rawMessage.includes('public key registry uses key derivation domain')) {
        return registry('The address book was deployed for other keys than this app uses. Reload the page. If that does not help, the operator has not published a matching deployment yet.');
    }
    if (rawMessage.includes('signature was not made by the note owner')) {
        return registry('The registration message was signed by another account. Sign it with the account you are registering.');
    }
    return describeError(error, 'Registration');
}

/**
 * Gets an appropriate toast message for a transaction error.
 *
 * @param {Error|string|unknown} error - The error object
 * @param {string} operationType - Type of operation (Deposit, Withdraw, Transfer, Transaction)
 * @returns {string} Message suitable for displaying in a toast
 */
export function getTransactionErrorMessage(error, operationType) {
    return describeError(error, operationType).message;
}
