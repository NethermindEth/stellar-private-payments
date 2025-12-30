/**
 * ZK Proof Bridge - Apache-2.0 License
 * 
 * Coordinates between:
 * - Module 1 (GPL-3.0): Witness generation (witness_calculator.js)
 * - Module 2 (Apache-2.0): Proof generation (prover-wasm)
 * 
 * Data-only exchange between modules via Uint8Array.
 */

// Prover Module: Input Preparation (Apache-2.0)
// Path is relative to dist/js/ where this file runs
import initProverModule, {
    Prover,
    MerkleTree,
    MerkleProof,
    derive_public_key,
    derive_public_key_hex,
    compute_commitment,
    compute_signature,
    compute_nullifier,
    poseidon2_hash2,
    poseidon2_hash3,
    u64_to_field_bytes,
    decimal_to_field_bytes,
    hex_to_field_bytes,
    field_bytes_to_hex,
    verify_proof,
    version as proverVersion,
} from './prover/prover.js';

// Witness Generation Module (GPL-3.0)
// Path is relative to dist/js/ where this file runs
import {
    initWitness,
    computeWitness,
    computeWitnessArray,
    getCircuitInfo,
    bytesToWitness,
} from './witness/index.js';

// =============================================================================
// Configuration
// =============================================================================

const DEFAULT_CONFIG = {
    circuitName: 'compliant_test',
    circuitWasmUrl: '/circuits/compliant_test.wasm',
    provingKeyUrl: '/keys/compliant_test_proving_key.bin',
    r1csUrl: '/circuits/compliant_test.r1cs',
    cacheName: 'zk-proving-artifacts-v1',
};

let config = { ...DEFAULT_CONFIG };

// =============================================================================
// State
// =============================================================================

let prover = null;
let proverModuleInitialized = false;
let witnessInitialized = false;
let proverInitialized = false;

// Cached artifacts (in-memory after first load)
let cachedProvingKey = null;
let cachedR1cs = null;

// Download state
let downloadPromise = null;

// =============================================================================
// Caching (Cache API)
// =============================================================================

/**
 * Get cached artifact from Cache API
 * @param {string} url 
 * @returns {Promise<Uint8Array|null>}
 */
async function getCached(url) {
    try {
        const cache = await caches.open(config.cacheName);
        const response = await cache.match(url);
        if (response) {
            return new Uint8Array(await response.arrayBuffer());
        }
    } catch (e) {
        console.warn('[ZK] Cache read failed:', e.message);
    }
    return null;
}

/**
 * Store artifact in Cache API
 * @param {string} url 
 * @param {Uint8Array} bytes 
 */
async function setCache(url, bytes) {
    try {
        const cache = await caches.open(config.cacheName);
        const response = new Response(bytes, {
            headers: { 'Content-Type': 'application/octet-stream' }
        });
        await cache.put(url, response);
    } catch (e) {
        console.warn('[ZK] Cache write failed:', e.message);
    }
}

/**
 * Clear all cached artifacts
 */
export async function clearCache() {
    try {
        await caches.delete(config.cacheName);
        cachedProvingKey = null;
        cachedR1cs = null;
        downloadPromise = null;
        console.log('[ZK] Cache cleared');
    } catch (e) {
        console.warn('[ZK] Cache clear failed:', e.message);
    }
}

// =============================================================================
// Download with Progress
// =============================================================================

/**
 * Download a file with progress tracking
 * @param {string} url 
 * @param {function} onProgress - Called with (loaded, total, url)
 * @returns {Promise<Uint8Array>}
 */
async function downloadWithProgress(url, onProgress) {
    const response = await fetch(url);
    
    if (!response.ok) {
        throw new Error(`Failed to fetch ${url}: ${response.status}`);
    }
    
    const contentLength = response.headers.get('Content-Length');
    const total = contentLength ? parseInt(contentLength, 10) : 0;
    
    // If no Content-Length or no body, fall back to simple fetch
    if (!total || !response.body) {
        const bytes = new Uint8Array(await response.arrayBuffer());
        if (onProgress) onProgress(bytes.length, bytes.length, url);
        return bytes;
    }
    
    const reader = response.body.getReader();
    const chunks = [];
    let loaded = 0;
    
    while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        
        chunks.push(value);
        loaded += value.length;
        
        if (onProgress) {
            onProgress(loaded, total, url);
        }
    }
    
    // Combine chunks into single Uint8Array
    const result = new Uint8Array(loaded);
    let offset = 0;
    for (const chunk of chunks) {
        result.set(chunk, offset);
        offset += chunk.length;
    }
    
    return result;
}

// =============================================================================
// Lazy Loading
// =============================================================================

/**
 * Ensure proving artifacts are loaded (with caching and progress)
 * 
 * @param {function} onProgress - Optional callback: (loaded, total, message) => void
 * @returns {Promise<{provingKey: Uint8Array, r1cs: Uint8Array}>}
 */
export async function ensureProvingArtifacts(onProgress) {
    // Already in memory
    if (cachedProvingKey && cachedR1cs) {
        return { provingKey: cachedProvingKey, r1cs: cachedR1cs };
    }
    
    // Download already in progress
    if (downloadPromise) {
        return downloadPromise;
    }
    
    downloadPromise = (async () => {
        // Try cache first
        let pk = cachedProvingKey || await getCached(config.provingKeyUrl);
        let r1cs = cachedR1cs || await getCached(config.r1csUrl);
        
        const needsPk = !pk;
        const needsR1cs = !r1cs;
        
        if (needsPk || needsR1cs) {
            // Estimate sizes for progress calculation
            const pkSize = needsPk ? 5000000 : 0;   // ~5MB
            const r1csSize = needsR1cs ? 3500000 : 0; // ~3.5MB
            const totalSize = pkSize + r1csSize;
            let pkLoaded = 0;
            let r1csLoaded = 0;
            
            const reportProgress = () => {
                if (onProgress) {
                    const loaded = pkLoaded + r1csLoaded;
                    const message = needsPk && pkLoaded < pkSize 
                        ? 'Downloading proving key...'
                        : 'Downloading circuit constraints...';
                    onProgress(loaded, totalSize, message);
                }
            };
            
            // Download in parallel
            const downloads = [];
            
            if (needsPk) {
                downloads.push(
                    downloadWithProgress(config.provingKeyUrl, (loaded, total, url) => {
                        pkLoaded = loaded;
                        reportProgress();
                    }).then(async (bytes) => {
                        pk = bytes;
                        await setCache(config.provingKeyUrl, bytes);
                        console.log(`[ZK] Proving key downloaded: ${(bytes.length / 1024 / 1024).toFixed(2)} MB`);
                    })
                );
            }
            
            if (needsR1cs) {
                downloads.push(
                    downloadWithProgress(config.r1csUrl, (loaded, total, url) => {
                        r1csLoaded = loaded;
                        reportProgress();
                    }).then(async (bytes) => {
                        r1cs = bytes;
                        await setCache(config.r1csUrl, bytes);
                        console.log(`[ZK] R1CS downloaded: ${(bytes.length / 1024 / 1024).toFixed(2)} MB`);
                    })
                );
            }
            
            await Promise.all(downloads);
            
            if (onProgress) {
                onProgress(totalSize, totalSize, 'Download complete');
            }
        } else {
            console.log('[ZK] Proving artifacts loaded from cache');
        }
        
        // Store in memory
        cachedProvingKey = pk;
        cachedR1cs = r1cs;
        
        return { provingKey: pk, r1cs: r1cs };
    })();
    
    return downloadPromise;
}

/**
 * Check if proving artifacts are cached (no download needed)
 * @returns {Promise<boolean>}
 */
export async function isProvingCached() {
    if (cachedProvingKey && cachedR1cs) return true;
    
    const pk = await getCached(config.provingKeyUrl);
    const r1cs = await getCached(config.r1csUrl);
    return pk !== null && r1cs !== null;
}

// =============================================================================
// Initialization
// =============================================================================

/**
 * Configure the ZK system URLs
 * Call before any initialization if using non-default paths
 * 
 * @param {Object} options
 * @param {string} options.circuitName - Circuit name (e.g., 'compliant_test')
 * @param {string} options.circuitWasmUrl - URL to circuit.wasm
 * @param {string} options.provingKeyUrl - URL to proving key
 * @param {string} options.r1csUrl - URL to R1CS file
 */
export function configure(options) {
    config = { ...config, ...options };
}

/**
 * Initialize only the WASM modules (fast, no large downloads)
 * Call this early to prepare for crypto operations
 * 
 * @returns {Promise<void>}
 */
export async function initModules() {
    if (!proverModuleInitialized) {
        await initProverModule();
        proverModuleInitialized = true;
        console.log('[ZK] Prover WASM module initialized');
    }
}

/**
 * Initialize witness generation (needed for input preparation)
 * 
 * @param {string} circuitWasmUrl - Optional, uses config if not provided
 * @returns {Promise<Object>} Circuit info
 */
export async function initWitnessModule(circuitWasmUrl) {
    await initModules();
    
    if (!witnessInitialized) {
        const url = circuitWasmUrl || config.circuitWasmUrl;
        await initWitness(url);
        witnessInitialized = true;
        console.log('[ZK] Witness calculator initialized');
    }
    
    return getCircuitInfo();
}

/**
 * Initialize the full prover (lazy loads proving artifacts)
 * 
 * @param {function} onProgress - Optional progress callback
 * @returns {Promise<Object>} Prover info
 */
export async function initProver(onProgress) {
    if (proverInitialized && prover) {
        return {
            version: proverVersion(),
            numPublicInputs: prover.num_public_inputs,
            numConstraints: prover.num_constraints,
            numWires: prover.num_wires,
        };
    }
    
    // Ensure modules are ready
    await initWitnessModule();
    
    // Load proving artifacts (lazy, cached)
    const { provingKey, r1cs } = await ensureProvingArtifacts(onProgress);
    
    // Create prover
    prover = new Prover(provingKey, r1cs);
    proverInitialized = true;
    
    console.log('[ZK] Prover initialized');
    console.log(`[ZK]   - ${prover.num_constraints} constraints`);
    console.log(`[ZK]   - ${prover.num_wires} wires`);
    console.log(`[ZK]   - ${prover.num_public_inputs} public inputs`);
    
    return {
        version: proverVersion(),
        circuitInfo: getCircuitInfo(),
        numPublicInputs: prover.num_public_inputs,
        numConstraints: prover.num_constraints,
        numWires: prover.num_wires,
    };
}

/**
 * Full initialization (backwards compatible)
 * 
 * @param {string} circuitWasmUrl - URL to circuit.wasm
 * @param {Uint8Array} provingKeyBytes - Proving key bytes (if already loaded)
 * @param {Uint8Array} r1csBytes - R1CS bytes (if already loaded)
 * @returns {Promise<Object>}
 */
export async function init(circuitWasmUrl, provingKeyBytes, r1csBytes) {
    await initModules();
    await initWitness(circuitWasmUrl);
    witnessInitialized = true;
    
    prover = new Prover(provingKeyBytes, r1csBytes);
    proverInitialized = true;
    
    return {
        version: proverVersion(),
        circuitInfo: getCircuitInfo(),
        numPublicInputs: prover.num_public_inputs,
        numConstraints: prover.num_constraints,
        numWires: prover.num_wires,
    };
}

/**
 * Check initialization state
 */
export function isInitialized() {
    return proverInitialized && witnessInitialized;
}

export function isWitnessReady() {
    return witnessInitialized;
}

export function isProverReady() {
    return proverInitialized;
}

// =============================================================================
// Input Preparation (available immediately after initModules)
// =============================================================================

/**
 * Derive public key from private key
 * @param {Uint8Array} privateKey - 32 bytes, Little-Endian
 * @returns {Uint8Array} Public key (32 bytes, Little-Endian)
 */
export function derivePublicKey(privateKey) {
    return derive_public_key(privateKey);
}

/**
 * Derive public key and return as hex string
 * @param {Uint8Array} privateKey - 32 bytes, Little-Endian
 * @returns {string} Public key as hex string (0x prefixed)
 */
export function derivePublicKeyHex(privateKey) {
    return derive_public_key_hex(privateKey);
}

/**
 * Compute commitment: hash(amount, publicKey, blinding)
 */
export { compute_commitment as computeCommitment };

/**
 * Compute signature for nullifier derivation
 */
export { compute_signature as computeSignature };

/**
 * Compute nullifier: hash(commitment, pathIndices, signature)
 */
export { compute_nullifier as computeNullifier };

/**
 * Poseidon2 hash with 2 inputs
 */
export { poseidon2_hash2 as poseidon2Hash2 };

/**
 * Poseidon2 hash with 3 inputs
 */
export { poseidon2_hash3 as poseidon2Hash3 };

// =============================================================================
// Merkle Tree Operations
// =============================================================================

/**
 * Create a new Merkle tree
 * @param {number} depth - Tree depth (e.g., 20 for 2^20 leaves)
 * @returns {MerkleTree} Merkle tree instance
 */
export function createMerkleTree(depth) {
    return new MerkleTree(depth);
}

export { MerkleTree, MerkleProof };

// =============================================================================
// Serialization Utilities
// =============================================================================

/**
 * Convert a JavaScript number to field element bytes
 */
export function numberToField(value) {
    if (!Number.isSafeInteger(value) || value < 0) {
        throw new Error('Value must be a non-negative safe integer');
    }
    return u64_to_field_bytes(BigInt(value));
}

/**
 * Convert a BigInt to field element bytes
 */
export function bigintToField(value) {
    const hex = '0x' + value.toString(16);
    return hex_to_field_bytes(hex);
}

export { decimal_to_field_bytes as decimalToField };
export { hex_to_field_bytes as hexToField };
export { field_bytes_to_hex as fieldToHex };

// =============================================================================
// Witness Generation
// =============================================================================

/**
 * Generate witness from circuit inputs
 * 
 * @param {Object} inputs - Circuit inputs as { signalName: value | value[] }
 * @returns {Promise<Uint8Array>} Witness bytes (Little-Endian, 32 bytes per element)
 */
export async function generateWitness(inputs) {
    if (!witnessInitialized) {
        throw new Error('Witness module not initialized. Call initWitnessModule() first.');
    }
    return await computeWitness(inputs);
}

/**
 * Generate witness and return as BigInt array (for debugging)
 */
export async function generateWitnessArray(inputs) {
    if (!witnessInitialized) {
        throw new Error('Witness module not initialized. Call initWitnessModule() first.');
    }
    return await computeWitnessArray(inputs);
}

// =============================================================================
// Proof Generation
// =============================================================================

/**
 * Generate a ZK proof from witness bytes
 * 
 * @param {Uint8Array} witnessBytes - Witness from generateWitness()
 * @returns {Object} Proof object with { a, b, c } points
 */
export function generateProof(witnessBytes) {
    if (!proverInitialized || !prover) {
        throw new Error('Prover not initialized. Call initProver() first.');
    }
    return prover.prove(witnessBytes);
}

/**
 * Generate a ZK proof and return as concatenated bytes
 * 
 * @param {Uint8Array} witnessBytes - Witness from generateWitness()
 * @returns {Uint8Array} Proof bytes [A || B || C]
 */
export function generateProofBytes(witnessBytes) {
    if (!proverInitialized || !prover) {
        throw new Error('Prover not initialized. Call initProver() first.');
    }
    return prover.prove_bytes(witnessBytes);
}

/**
 * Extract public inputs from witness
 * 
 * @param {Uint8Array} witnessBytes - Full witness bytes
 * @returns {Uint8Array} Public inputs bytes
 */
export function extractPublicInputs(witnessBytes) {
    if (!proverInitialized || !prover) {
        throw new Error('Prover not initialized. Call initProver() first.');
    }
    return prover.extract_public_inputs(witnessBytes);
}

/**
 * Verify a proof locally
 * 
 * @param {Uint8Array} proofBytes - Proof bytes [A || B || C]
 * @param {Uint8Array} publicInputsBytes - Public inputs bytes
 * @returns {boolean} True if proof is valid
 */
export function verifyProofLocal(proofBytes, publicInputsBytes) {
    if (!proverInitialized || !prover) {
        throw new Error('Prover not initialized. Call initProver() first.');
    }
    return prover.verify(proofBytes, publicInputsBytes);
}

/**
 * Get the verifying key (for on-chain deployment)
 * @returns {Uint8Array} Serialized verifying key
 */
export function getVerifyingKey() {
    if (!proverInitialized || !prover) {
        throw new Error('Prover not initialized. Call initProver() first.');
    }
    return prover.get_verifying_key();
}

// =============================================================================
// High-Level Proof Flow
// =============================================================================

/**
 * Generate a complete ZK proof from circuit inputs
 * 
 * This function:
 * 1. Ensures prover is initialized (lazy loads if needed)
 * 2. Generates witness
 * 3. Generates proof
 * 
 * @param {Object} inputs - Circuit inputs
 * @param {function} onProgress - Optional progress callback for artifact download
 * @returns {Promise<{proof: Uint8Array, publicInputs: Uint8Array}>}
 */
export async function prove(inputs, onProgress) {
    // Lazy initialize prover if needed
    if (!proverInitialized) {
        await initProver(onProgress);
    }
    
    // Generate witness
    const witnessBytes = await generateWitness(inputs);
    
    // Generate proof
    const proofBytes = generateProofBytes(witnessBytes);
    const publicInputsBytes = extractPublicInputs(witnessBytes);
    
    return {
        proof: proofBytes,
        publicInputs: publicInputsBytes,
    };
}

/**
 * Generate proof and verify locally
 * 
 * @param {Object} inputs - Circuit inputs
 * @param {function} onProgress - Optional progress callback
 * @returns {Promise<{proof: Uint8Array, publicInputs: Uint8Array, verified: boolean}>}
 */
export async function proveAndVerify(inputs, onProgress) {
    const { proof, publicInputs } = await prove(inputs, onProgress);
    const verified = verifyProofLocal(proof, publicInputs);
    
    return {
        proof,
        publicInputs,
        verified,
    };
}

// =============================================================================
// Re-exports
// =============================================================================

export { getCircuitInfo, bytesToWitness };
export { verify_proof as verifyWithKey };
