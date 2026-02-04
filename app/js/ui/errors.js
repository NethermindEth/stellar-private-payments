/**
 * Error handling utilities for user-friendly transaction error messages.
 * 
 * Maps contract error codes and common failure patterns to human-readable messages.
 * @module ui/errors
 */

/**
 * Contract error code mappings.
 * These map to the Error enums defined in the Soroban contracts.
 */
const CONTRACT_ERRORS = {
    // Pool contract errors
    pool: {
        7: 'Proof verification failed. The ZK proof is invalid.',
        8: 'Invalid merkle root. The pool state may have changed.',
        9: 'Note already spent. This is a double-spend attempt.',
    },
    // Groth16 verifier errors 
    verifier: {
        0: 'Proof verification failed.',
    },
    // ASP Non-Membership errors 
    aspNonMembership: {
        2: 'Key not found in ASP tree.',
        4: 'ASP non-membership proof verification failed.',
    },
    // ASP Membership errors
    aspMembership: {
        3: 'Not authorized to perform this action.',
    },
};

/**
 * User-friendly messages for common error patterns.
 */
const ERROR_PATTERNS = [
    {
        // Pool InvalidProof (#7) or Verifier InvalidProof (#0)
        test: (msg) => {
            const lower = msg.toLowerCase();
            return (lower.includes('contract') && lower.includes('#7')) ||
                   (lower.includes('contract') && lower.includes('#0') && lower.includes('verif'));
        },
        message: 'Proof verification failed. This can happen if the pool state changed during proof generation. Please ensure your membership in the proper ASP tree is synced and try again.',
    },
    {
        // Double-spend attempt (#9)
        test: (msg) => msg.toLowerCase().includes('#9') && msg.toLowerCase().includes('contract'),
        message: 'This note has already been spent. Please refresh your notes and try with different inputs.',
    },
    {
        // Invalid merkle root (#8)
        test: (msg) => msg.toLowerCase().includes('#8') && msg.toLowerCase().includes('contract'),
        message: 'Pool state has changed. Please wait for sync to complete and try again.',
    },
    {
        // ASP membership issues
        test: (msg) => {
            const lower = msg.toLowerCase();
            return lower.includes('membership') && (lower.includes('not found') || lower.includes('leaf'));
        },
        message: 'Your ASP membership could not be verified. Ensure you are registered in the Attestation Service Provider.',
    },
    {
        // Simulation failures
        test: (msg) => {
            const lower = msg.toLowerCase();
            return lower.includes('simulation') && lower.includes('fail');
        },
        message: 'Transaction simulation failed. The contract rejected the transaction.',
    },
    {
        // Insufficient balance / resource exhaustion
        test: (msg) => {
            const lower = msg.toLowerCase();
            return lower.includes('insufficient') || 
                   (lower.includes('resource') && lower.includes('exceed'));
        },
        message: 'Insufficient balance or resources. Ensure you have enough XLM to cover the transaction fee.',
    },
    {
        // Network/RPC errors
        test: (msg) => {
            const lower = msg.toLowerCase();
            return lower.includes('network') || 
                   lower.includes('timeout') ||
                   lower.includes('fetch') ||
                   lower.includes('connection');
        },
        message: 'Network error. Please check your connection and try again.',
    },
    {
        // User rejected signature
        test: (msg) => {
            const lower = msg.toLowerCase();
            return lower.includes('rejected') || 
                   lower.includes('denied') ||
                   lower.includes('cancelled') ||
                   lower.includes('user_rejected');
        },
        message: 'Transaction was cancelled.',
    },
    {
        // Merkle proof not found
        test: (msg) => {
            const lower = msg.toLowerCase();
            return lower.includes('merkle proof') && lower.includes('not');
        },
        message: 'Merkle proof not found. Please sync the pool state and try again.',
    },
    {
        // Pool state out of sync
        test: (msg) => {
            const lower = msg.toLowerCase();
            return lower.includes('out of sync') || lower.includes('root mismatch');
        },
        message: 'Pool state is out of sync. Please wait for sync to complete and try again.',
    },
];

/**
 * Safely extracts the error message from an error object.
 * @param {Error|string|unknown} error - The error to extract message from
 * @returns {string} The error message
 */
export function getErrorMessage(error) {
    if (!error) return '';
    if (typeof error === 'string') return error;
    if (error instanceof Error) return error.message || String(error);
    if (typeof error === 'object' && 'message' in error) return String(error.message);
    return String(error);
}

/**
 * Checks if an error message indicates a proof verification failure.
 * @param {string} message - Error message to check
 * @returns {boolean} True if this is a proof verification error
 */
export function isProofVerificationError(message) {
    const msg = (message || '').toLowerCase();
    // Pool contract InvalidProof is #7; verifier InvalidProof is #0.
    return (msg.includes('contract') && msg.includes('#7')) ||
           (msg.includes('contract') && msg.includes('#0') && msg.includes('verif'));
}

/**
 * Checks if an error indicates the user cancelled/rejected the action.
 * @param {Error|string|unknown} error - The error to check
 * @returns {boolean} True if user cancelled
 */
export function isUserCancelledError(error) {
    const msg = getErrorMessage(error).toLowerCase();
    return msg.includes('rejected') || 
           msg.includes('denied') ||
           msg.includes('cancelled') ||
           msg.includes('user_rejected');
}

/**
 * Gets a user-friendly error message for a transaction error.
 * @param {Error|string|unknown} error - The error object or message
 * @param {string} [operationType='Transaction'] - Type of operation (Deposit, Withdraw, etc.)
 * @returns {string} User-friendly error message
 */
export function getFriendlyErrorMessage(error, operationType = 'Transaction') {
    const rawMessage = getErrorMessage(error);
    if (!rawMessage) return `${operationType} failed. Please try again.`;
    
    // Check against known error patterns
    for (const pattern of ERROR_PATTERNS) {
        if (pattern.test(rawMessage)) {
            return pattern.message;
        }
    }
    
    // Try to extract contract error code
    const contractErrorMatch = rawMessage.match(/Error\(Contract,\s*#(\d+)\)/i) ||
                               rawMessage.match(/contract.*#(\d+)/i);
    if (contractErrorMatch) {
        const errorCode = parseInt(contractErrorMatch[1], 10);
        // Check pool errors first (most common)
        if (CONTRACT_ERRORS.pool[errorCode]) {
            return CONTRACT_ERRORS.pool[errorCode];
        }
    }
    
    // If the message is very long or contains technical details, truncate it
    if (rawMessage.length > 150) {
        // Try to extract just the meaningful part
        const shortMsg = rawMessage.split('\n')[0].slice(0, 100);
        return `${operationType} failed: ${shortMsg}...`;
    }
    
    // Return the original message with the operation type prefix
    return `${operationType} failed: ${rawMessage}`;
}

/**
 * Gets an appropriate toast message for a transaction error.
 * This is the main function to use in catch blocks.
 * 
 * @param {Error|string|unknown} error - The error object
 * @param {string} operationType - Type of operation (Deposit, Withdraw, Transfer, Transaction)
 * @returns {string} Message suitable for displaying in a toast
 */
export function getTransactionErrorMessage(error, operationType) {
    // If user cancelled, return a simple message
    if (isUserCancelledError(error)) {
        return `${operationType} cancelled.`;
    }
    
    return getFriendlyErrorMessage(error, operationType);
}

