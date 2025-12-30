/**
 * ZK Proof Worker - Apache-2.0 License
 * 
 * Runs heavy proving operations in a Web Worker to avoid blocking the main UI thread.
 * Communication happens via postMessage.
 * 
 * This worker coordinates between:
 * - Module 1 (GPL-3.0): Witness generation
 * - Module 2 (Apache-2.0): Input preparation + proof generation
 */

import {
    // Initialization
    configure,
    initModules,
    initWitnessModule,
    initProver,
    init,
    isInitialized,
    isWitnessReady,
    isProverReady,
    isProvingCached,
    clearCache,
    
    // Witness & Proof
    generateWitness,
    generateProofBytes,
    extractPublicInputs,
    verifyProofLocal,
    getVerifyingKey,
    getCircuitInfo,
    
    // Crypto utilities
    derivePublicKey,
    derivePublicKeyHex,
    computeCommitment,
    computeNullifier,
    createMerkleTree,
    bigintToField,
    numberToField,
    hexToField,
    fieldToHex,
} from './bridge.js';

// State
let modulesReady = false;
let witnessReady = false;
let proverReady = false;

/**
 * Send progress update to main thread
 */
function sendProgress(messageId, loaded, total, message) {
    self.postMessage({
        type: 'PROGRESS',
        messageId,
        loaded,
        total,
        message,
        percent: total > 0 ? Math.round((loaded / total) * 100) : 0,
    });
}

/**
 * Initialize WASM modules only (fast, no downloads)
 */
async function handleInitModules(data) {
    try {
        await initModules();
        modulesReady = true;
        return { success: true, modulesReady: true };
    } catch (error) {
        return { success: false, error: error.message };
    }
}

/**
 * Initialize witness calculator (downloads circuit.wasm if needed)
 */
async function handleInitWitness(data, messageId) {
    const { circuitWasmUrl } = data || {};
    
    try {
        const circuitInfo = await initWitnessModule(circuitWasmUrl);
        witnessReady = true;
        return { success: true, circuitInfo, witnessReady: true };
    } catch (error) {
        return { success: false, error: error.message };
    }
}

/**
 * Initialize prover with lazy loading (downloads proving key + R1CS if not cached)
 */
async function handleInitProver(data, messageId) {
    try {
        // Progress callback that sends updates to main thread
        const onProgress = (loaded, total, message) => {
            sendProgress(messageId, loaded, total, message);
        };
        
        const info = await initProver(onProgress);
        proverReady = true;
        
        return { 
            success: true, 
            info,
            proverReady: true,
        };
    } catch (error) {
        return { success: false, error: error.message };
    }
}

/**
 * Full initialization with explicit bytes (backwards compatible)
 */
async function handleInit(data) {
    const { circuitWasmUrl, provingKeyBytes, r1csBytes } = data;
    
    try {
        const info = await init(
            circuitWasmUrl,
            new Uint8Array(provingKeyBytes),
            new Uint8Array(r1csBytes)
        );
        modulesReady = true;
        witnessReady = true;
        proverReady = true;
        return { success: true, info };
    } catch (error) {
        return { success: false, error: error.message };
    }
}

/**
 * Configure URLs for lazy loading
 */
function handleConfigure(data) {
    try {
        configure(data);
        return { success: true };
    } catch (error) {
        return { success: false, error: error.message };
    }
}

/**
 * Check if proving artifacts are cached
 */
async function handleCheckCache() {
    try {
        const cached = await isProvingCached();
        return { success: true, cached };
    } catch (error) {
        return { success: false, error: error.message };
    }
}

/**
 * Clear cached artifacts
 */
async function handleClearCache() {
    try {
        await clearCache();
        return { success: true };
    } catch (error) {
        return { success: false, error: error.message };
    }
}

/**
 * Generate a ZK proof from circuit inputs
 */
async function handleProve(data, messageId) {
    const { inputs } = data;
    
    try {
        // Lazy init prover if needed
        if (!proverReady) {
            const onProgress = (loaded, total, message) => {
                sendProgress(messageId, loaded, total, message);
            };
            await initProver(onProgress);
            proverReady = true;
        }
        
        const startTime = performance.now();
        
        // Step 1: Generate witness
        const witnessTime = performance.now();
        const witnessBytes = await generateWitness(inputs);
        console.log(`[Worker] Witness generation: ${(performance.now() - witnessTime).toFixed(0)}ms`);
        
        // Step 2: Generate proof
        const proveTime = performance.now();
        const proofBytes = generateProofBytes(witnessBytes);
        console.log(`[Worker] Proof generation: ${(performance.now() - proveTime).toFixed(0)}ms`);
        
        // Step 3: Extract public inputs
        const publicInputsBytes = extractPublicInputs(witnessBytes);
        
        console.log(`[Worker] Total prove time: ${(performance.now() - startTime).toFixed(0)}ms`);
        
        return {
            success: true,
            proof: Array.from(proofBytes),
            publicInputs: Array.from(publicInputsBytes),
            timings: {
                witness: performance.now() - witnessTime,
                prove: performance.now() - proveTime,
                total: performance.now() - startTime,
            },
        };
    } catch (error) {
        return { success: false, error: error.message };
    }
}

/**
 * Verify a proof locally
 */
function handleVerify(data) {
    if (!proverReady) {
        return { success: false, error: 'Prover not initialized' };
    }
    
    const { proofBytes, publicInputsBytes } = data;
    
    try {
        const verified = verifyProofLocal(
            new Uint8Array(proofBytes),
            new Uint8Array(publicInputsBytes)
        );
        return { success: true, verified };
    } catch (error) {
        return { success: false, error: error.message };
    }
}

/**
 * Derive public key from private key
 */
function handleDerivePublicKey(data) {
    const { privateKey, asHex } = data;
    
    try {
        const pkBytes = new Uint8Array(privateKey);
        if (asHex) {
            return { success: true, publicKey: derivePublicKeyHex(pkBytes) };
        } else {
            return { success: true, publicKey: Array.from(derivePublicKey(pkBytes)) };
        }
    } catch (error) {
        return { success: false, error: error.message };
    }
}

/**
 * Compute commitment
 */
function handleComputeCommitment(data) {
    const { amount, publicKey, blinding } = data;
    
    try {
        const commitment = computeCommitment(
            new Uint8Array(amount),
            new Uint8Array(publicKey),
            new Uint8Array(blinding)
        );
        return { success: true, commitment: Array.from(commitment) };
    } catch (error) {
        return { success: false, error: error.message };
    }
}

/**
 * Get the verifying key
 */
function handleGetVerifyingKey() {
    if (!proverReady) {
        return { success: false, error: 'Prover not initialized' };
    }
    
    try {
        const vkBytes = getVerifyingKey();
        return { success: true, verifyingKey: Array.from(vkBytes) };
    } catch (error) {
        return { success: false, error: error.message };
    }
}

/**
 * Get circuit info
 */
function handleGetCircuitInfo() {
    if (!witnessReady) {
        return { success: false, error: 'Witness not initialized' };
    }
    
    return { success: true, info: getCircuitInfo() };
}

/**
 * Get current state
 */
function handleGetState() {
    return {
        success: true,
        state: {
            modulesReady,
            witnessReady,
            proverReady,
        },
    };
}

// =============================================================================
// Message Handler
// =============================================================================

self.onmessage = async function(event) {
    const { type, messageId, data } = event.data;
    
    let result;
    
    switch (type) {
        // Initialization
        case 'INIT_MODULES':
            result = await handleInitModules(data);
            break;
            
        case 'INIT_WITNESS':
            result = await handleInitWitness(data, messageId);
            break;
            
        case 'INIT_PROVER':
            result = await handleInitProver(data, messageId);
            break;
            
        case 'INIT':
            result = await handleInit(data);
            break;
            
        case 'CONFIGURE':
            result = handleConfigure(data);
            break;
            
        // Caching
        case 'CHECK_CACHE':
            result = await handleCheckCache();
            break;
            
        case 'CLEAR_CACHE':
            result = await handleClearCache();
            break;
            
        // Proving
        case 'PROVE':
            result = await handleProve(data, messageId);
            break;
            
        case 'VERIFY':
            result = handleVerify(data);
            break;
            
        // Crypto utilities
        case 'DERIVE_PUBLIC_KEY':
            result = handleDerivePublicKey(data);
            break;
            
        case 'COMPUTE_COMMITMENT':
            result = handleComputeCommitment(data);
            break;
            
        // Info
        case 'GET_VERIFYING_KEY':
            result = handleGetVerifyingKey();
            break;
            
        case 'GET_CIRCUIT_INFO':
            result = handleGetCircuitInfo();
            break;
            
        case 'GET_STATE':
            result = handleGetState();
            break;
            
        case 'PING':
            result = { 
                success: true, 
                ready: proverReady,
                state: { modulesReady, witnessReady, proverReady },
            };
            break;
            
        default:
            result = { success: false, error: `Unknown message type: ${type}` };
    }
    
    self.postMessage({ type, messageId, ...result });
};

// Signal that worker script has loaded
self.postMessage({ type: 'LOADED' });
