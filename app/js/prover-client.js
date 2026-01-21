/**
 * Prover Client - Promise-based API for the ZK Proof WebWorker
 * 
 * Provides a clean interface for initializing the prover and generating proofs
 * without blocking the main UI thread.
 */

let worker = null;
let messageId = 0;
let pendingRequests = new Map();
let initPromise = null;

// State
const state = {
    modulesReady: false,
    witnessReady: false,
    proverReady: false,
    initializing: false,
    error: null,
};

// Event listeners for progress updates
const progressListeners = new Set();

/**
 * Add a progress listener. Called during prover initialization.
 * @param {function} callback - (loaded, total, message, percent) => void
 * @returns {function} Unsubscribe function
 */
export function onProgress(callback) {
    progressListeners.add(callback);
    return () => progressListeners.delete(callback);
}

function notifyProgress(loaded, total, message, percent) {
    for (const listener of progressListeners) {
        try {
            listener(loaded, total, message, percent);
        } catch (e) {
            console.error('[ProverClient] Progress listener error:', e);
        }
    }
}

// Promise for worker readiness
let workerReadyPromise = null;

/**
 * Ensures the WebWorker is created and ready.
 * @returns {Promise<Worker>} The worker instance
 */
function ensureWorker() {
    // If worker is already created and ready, return it
    if (worker && workerReadyPromise === null) {
        return Promise.resolve(worker);
    }

    // If we're currently initializing, return the existing promise
    if (workerReadyPromise) {
        return workerReadyPromise;
    }

    workerReadyPromise = new Promise((resolve, reject) => {
        try {
            const w = new Worker(new URL('./worker.js', import.meta.url), { type: 'module' });
            
            // Timeout for worker initialization
            const timeoutId = setTimeout(() => {
                workerReadyPromise = null;
                reject(new Error('Worker initialization timeout'));
            }, 10000);

            w.onmessage = (event) => {
                const { type, messageId: msgId, ...data } = event.data;

                // Handle READY signal
                if (type === 'READY') {
                    console.log('[ProverClient] Worker ready');
                    clearTimeout(timeoutId);
                    worker = w;
                    workerReadyPromise = null;
                    resolve(w);
                    return;
                }

                // Handle progress updates
                if (type === 'PROGRESS') {
                    notifyProgress(data.loaded, data.total, data.message, data.percent);
                    return;
                }

                // Handle responses to pending requests
                const pending = pendingRequests.get(msgId);
                if (pending) {
                    pendingRequests.delete(msgId);
                    if (data.success !== false) {
                        pending.resolve(data);
                    } else {
                        console.error('[ProverClient] Worker returned error:', data);
                        pending.reject(new Error(data.error || `Worker error (type: ${type})`));
                    }
                }
            };

            w.onerror = (error) => {
                console.error('[ProverClient] Worker error:', error);
                state.error = error.message || 'Worker error';
                clearTimeout(timeoutId);
                workerReadyPromise = null;
                reject(error);
            };

        } catch (e) {
            workerReadyPromise = null;
            reject(e);
        }
    });

    return workerReadyPromise;
}

/**
 * Send a message to the worker and wait for response.
 * @param {string} type - Message type
 * @param {Object} data - Message data
 * @returns {Promise<Object>} Response data
 */
async function sendMessage(type, data = {}) {
    const w = await ensureWorker();
    const id = ++messageId;

    return new Promise((resolve, reject) => {
        pendingRequests.set(id, { resolve, reject });
        w.postMessage({ type, messageId: id, data });

        // Timeout for long operations
        const timeout = type === 'PROVE' ? 120000 : 60000;
        setTimeout(() => {
            if (pendingRequests.has(id)) {
                pendingRequests.delete(id);
                reject(new Error(`${type} timeout`));
            }
        }, timeout);
    });
}

/**
 * Initialize the prover with lazy loading of artifacts.
 * Downloads proving key and R1CS if not cached.
 * 
 * @param {Object} options
 * @param {function} options.onProgress - Progress callback
 * @returns {Promise<Object>} Prover info
 */
export async function initializeProver(options = {}) {
    if (state.proverReady) {
        return { success: true, state };
    }

    if (initPromise) {
        return initPromise;
    }

    state.initializing = true;

    // Set up progress listener if provided
    let unsubscribe;
    if (options.onProgress) {
        unsubscribe = onProgress(options.onProgress);
    }

    initPromise = (async () => {
        try {
            const result = await sendMessage('INIT_PROVER');
            state.modulesReady = true;
            state.witnessReady = true;
            state.proverReady = true;
            state.initializing = false;
            return result;
        } catch (e) {
            state.error = e.message;
            state.initializing = false;
            throw e;
        } finally {
            if (unsubscribe) unsubscribe();
            initPromise = null;
        }
    })();

    return initPromise;
}

/**
 * Check if prover is ready for proof generation.
 * @returns {boolean}
 */
export function isReady() {
    return state.proverReady;
}

/**
 * Get current state.
 * @returns {Object}
 */
export function getState() {
    return { ...state };
}

/**
 * Check if proving artifacts are cached.
 * @returns {Promise<boolean>}
 */
export async function isCached() {
    const result = await sendMessage('CHECK_CACHE');
    return result.cached;
}

/**
 * Clear cached artifacts.
 * @returns {Promise<void>}
 */
export async function clearCache() {
    await sendMessage('CLEAR_CACHE');
}

/**
 * Generate a ZK proof from circuit inputs.
 * 
 * @param {Object} inputs - Circuit inputs
 * @param {Object} options
 * @param {boolean} options.sorobanFormat - Return proof in Soroban-compatible format (256 bytes)
 * @returns {Promise<{proof: Uint8Array, publicInputs: Uint8Array, sorobanFormat: boolean, timings: Object}>}
 */
export async function prove(inputs, options = {}) {
    if (!state.proverReady) {
        await initializeProver();
    }

    const result = await sendMessage('PROVE', { 
        inputs, 
        sorobanFormat: options.sorobanFormat || false,
    });

    return {
        proof: new Uint8Array(result.proof),
        publicInputs: new Uint8Array(result.publicInputs),
        sorobanFormat: result.sorobanFormat,
        timings: result.timings,
    };
}

/**
 * Convert compressed proof bytes to Soroban format.
 * 
 * @param {Uint8Array} proofBytes - Compressed proof bytes
 * @returns {Promise<Uint8Array>} Soroban-format proof (256 bytes)
 */
export async function convertProofToSoroban(proofBytes) {
    const result = await sendMessage('CONVERT_PROOF_TO_SOROBAN', {
        proofBytes: Array.from(proofBytes),
    });
    return new Uint8Array(result.proof);
}

/**
 * Verify a proof locally.
 * 
 * @param {Uint8Array} proofBytes - Proof bytes
 * @param {Uint8Array} publicInputsBytes - Public inputs bytes
 * @returns {Promise<boolean>}
 */
export async function verify(proofBytes, publicInputsBytes) {
    if (!state.proverReady) {
        throw new Error('Prover not initialized');
    }

    const result = await sendMessage('VERIFY', {
        proofBytes: Array.from(proofBytes),
        publicInputsBytes: Array.from(publicInputsBytes),
    });

    return result.verified;
}

/**
 * Derive public key from private key.
 * 
 * @param {Uint8Array} privateKey - 32-byte private key
 * @param {boolean} asHex - Return as hex string
 * @returns {Promise<Uint8Array|string>}
 */
export async function derivePublicKey(privateKey, asHex = false) {
    const result = await sendMessage('DERIVE_PUBLIC_KEY', {
        privateKey: Array.from(privateKey),
        asHex,
    });

    return asHex ? result.publicKey : new Uint8Array(result.publicKey);
}

/**
 * Compute note commitment.
 * 
 * @param {Uint8Array} amount - Amount as field bytes
 * @param {Uint8Array} publicKey - Public key as field bytes
 * @param {Uint8Array} blinding - Blinding factor as field bytes
 * @returns {Promise<Uint8Array>}
 */
export async function computeCommitment(amount, publicKey, blinding) {
    const result = await sendMessage('COMPUTE_COMMITMENT', {
        amount: Array.from(amount),
        publicKey: Array.from(publicKey),
        blinding: Array.from(blinding),
    });

    return new Uint8Array(result.commitment);
}

/**
 * Get the verifying key.
 * @param {Object} options
 * @param {boolean} options.sorobanFormat - Return VK in Soroban-compatible format
 * @returns {Promise<Uint8Array>}
 */
export async function getVerifyingKey(options = {}) {
    if (!state.proverReady) {
        throw new Error('Prover not initialized');
    }

    const result = await sendMessage('GET_VERIFYING_KEY', {
        sorobanFormat: options.sorobanFormat || false,
    });
    return new Uint8Array(result.verifyingKey);
}

/**
 * Get circuit info.
 * @returns {Promise<Object>}
 */
export async function getCircuitInfo() {
    const result = await sendMessage('GET_CIRCUIT_INFO');
    return result.info;
}

/**
 * Ping the worker to check health.
 * @returns {Promise<Object>}
 */
export async function ping() {
    return sendMessage('PING');
}

/**
 * Terminate the worker.
 */
export function terminate() {
    if (worker) {
        worker.terminate();
        worker = null;
        state.modulesReady = false;
        state.witnessReady = false;
        state.proverReady = false;
        state.initializing = false;
        pendingRequests.clear();
    }
}

export default {
    initializeProver,
    isReady,
    getState,
    isCached,
    clearCache,
    prove,
    convertProofToSoroban,
    verify,
    derivePublicKey,
    computeCommitment,
    getVerifyingKey,
    getCircuitInfo,
    ping,
    terminate,
    onProgress,
};
