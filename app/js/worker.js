/**
 * ZK Proof Worker 
 * 
 * Runs heavy proving operations in a Web Worker to avoid blocking the main UI thread.
 * Communication happens via postMessage.
 * 
 * This worker coordinates between:
 * - Module 1: Witness generation
 * - Module 2: Input preparation + proof generation
 */

import {
    // Initialization
    configure,
    initProverWasm,
    initWitnessModule,
    initProver,
    init,
    isProvingCached,
    clearCache,
    
    // Witness & Proof
    generateWitness,
    generateProofBytes,
    generateProofBytesSoroban,
    extractPublicInputs,
    verifyProofLocal,
    getVerifyingKey,
    getVerifyingKeySoroban,
    getCircuitInfo,
    proofBytesToSoroban,
    
    // Crypto utilities
    derivePublicKey,
    derivePublicKeyHex,
    computeCommitment,
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
async function handleInitModules() {
    try {
        await initProverWasm();
        modulesReady = true;
        return { success: true, modulesReady: true };
    } catch (error) {
        return { success: false, error: error.message };
    }
}

/**
 * Initialize witness calculator (downloads circuit.wasm if needed)
 */
async function handleInitWitness(data) {
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
    try {
        const { circuitWasmUrl, provingKeyBytes, r1csBytes } = data;
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
    try {
        const { inputs, sorobanFormat } = data;
        // Lazy init prover if needed
        if (!proverReady) {
            const onProgress = (loaded, total, message) => {
                sendProgress(messageId, loaded, total, message);
            };
            await initProver(onProgress);
            proverReady = true;
        }
        
        // Step 1: Generate witness
        const witnessTime = performance.now();
        const witnessBytes = await generateWitness(inputs);
        const witnessOnlyTime = performance.now() - witnessTime;
        console.log(`[Worker] Witness generation: ${(witnessOnlyTime).toFixed(0)}ms`);
        
        // Step 2: Generate proof
        const proveTime = performance.now();
        let proofBytes;
        if (sorobanFormat) {
            // Generate directly in Soroban uncompressed format (256 bytes)
            proofBytes = generateProofBytesSoroban(witnessBytes);
            console.log(`[Worker] Proof generation (Soroban): ${(performance.now() - proveTime).toFixed(0)}ms`);
        } else {
            // Generate compressed format
            proofBytes = generateProofBytes(witnessBytes);
            console.log(`[Worker] Proof generation: ${(performance.now() - proveTime).toFixed(0)}ms`);
        }
        
        // Step 3: Extract public inputs
        console.log('[Worker] Extracting public inputs...');
        const publicInputsBytes = extractPublicInputs(witnessBytes);
        console.log(`[Worker] Public inputs extracted: ${publicInputsBytes?.length || 0} bytes`);
        
        // Convert to arrays for serialization
        const proofArray = Array.from(proofBytes);
        const publicInputsArray = Array.from(publicInputsBytes);
        console.log(`[Worker] Proof: ${proofArray.length} bytes, Public inputs: ${publicInputsArray.length} bytes`);
        
        return {
            success: true,
            proof: proofArray,
            publicInputs: publicInputsArray,
            sorobanFormat: !!sorobanFormat,
            timings: {
                witness: witnessOnlyTime,
                prove: performance.now() - proveTime,
                total: performance.now() - witnessTime,
            },
        };
    } catch (error) {
        console.error('[Worker] handleProve error:', error);
        return { success: false, error: error?.message || String(error) || 'Proof generation failed' };
    }
}

/**
 * Convert compressed proof to Soroban format
 */
function handleConvertProofToSoroban(data) {
    try {
        const { proofBytes } = data;
        const sorobanProof = proofBytesToSoroban(new Uint8Array(proofBytes));
        return { success: true, proof: Array.from(sorobanProof) };
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
    
    try {
        const { proofBytes, publicInputsBytes } = data;
        
        // Log sizes for debugging
        const proofArr = new Uint8Array(proofBytes);
        const pubInputsArr = new Uint8Array(publicInputsBytes);
        console.log(`[Worker] Verifying proof: ${proofArr.length} bytes, public inputs: ${pubInputsArr.length} bytes`);
        
        // Expected sizes for Groth16 BN254:
        // - Proof: 256 bytes (Soroban format) or 192 bytes (compressed)
        // - Public inputs: 32 bytes per element
        const numPublicInputs = pubInputsArr.length / 32;
        console.log(`[Worker] Number of public inputs: ${numPublicInputs}`);
        
        const verified = verifyProofLocal(proofArr, pubInputsArr);
        console.log(`[Worker] Verification result: ${verified}`);
        return { success: true, verified };
    } catch (error) {
        // Capture as much error info as possible
        const errorMsg = error?.message || error?.toString() || String(error) || 'Unknown verification error';
        console.error('[Worker] Verification error:', error);
        console.error('[Worker] Error message:', errorMsg);
        console.error('[Worker] Error stack:', error?.stack);
        return { success: false, error: errorMsg };
    }
}

/**
 * Derive public key from private key
 */
function handleDerivePublicKey(data) {
    try {
        const { privateKey, asHex } = data;
        const skBytes = new Uint8Array(privateKey);
        if (asHex) {
            return { success: true, publicKey: derivePublicKeyHex(skBytes) };
        } else {
            return { success: true, publicKey: Array.from(derivePublicKey(skBytes)) };
        }
    } catch (error) {
        return { success: false, error: error.message };
    }
}

/**
 * Compute commitment
 */
function handleComputeCommitment(data) {
    try {
        const { amount, publicKey, blinding } = data;
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
function handleGetVerifyingKey(data = {}) {
    if (!proverReady) {
        return { success: false, error: 'Prover not initialized' };
    }
    
    try {
        const { sorobanFormat } = data;
        const vkBytes = sorobanFormat ? getVerifyingKeySoroban() : getVerifyingKey();
        return { success: true, verifyingKey: Array.from(vkBytes), sorobanFormat: !!sorobanFormat };
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

// Message Handler
self.onmessage = async function(event) {
    const { type, messageId, data } = event.data;
    
    let result;
    
    switch (type) {
        // Initialization
        case 'INIT_MODULES':
            result = await handleInitModules();
            break;
            
        case 'INIT_WITNESS':
            result = await handleInitWitness(data);
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
            
        case 'CONVERT_PROOF_TO_SOROBAN':
            result = handleConvertProofToSoroban(data);
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
            result = handleGetVerifyingKey(data);
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
self.postMessage({ type: 'READY' });
