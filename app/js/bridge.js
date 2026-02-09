/**
 * ZK Proof Bridge
 * 
 * Coordinates between:
 * - Module 1: Witness generation (witness-wasm using ark-circom)
 * - Module 2: Proof generation (prover-wasm using ark-groth16)
 * 
 * Data exchange via Uint8Array.
 */

// Prover Module
import initProverModule, {
    Prover,
    MerkleTree,
    MerkleProof,
    WasmSparseMerkleTree,
    derive_public_key,
    derive_public_key_hex,
    compute_commitment,
    compute_signature,
    compute_nullifier,
    poseidon2_hash2,
    poseidon2_compression_wasm,
    u64_to_field_bytes,
    hex_to_field_bytes,
    field_bytes_to_hex,
    derive_keypair_from_signature,
    derive_note_private_key,
    generate_random_blinding,
    encrypt_note_data,
    decrypt_note_data,
    convert_proof_to_soroban,
    version as proverVersion,
    bn256_modulus,
    zero_leaf
} from './prover.js';

// Witness Module (ark-circom WASM)
import initWitnessWasm, {
    WitnessCalculator,
    version as witnessVersion,
} from './witness/witness.js';

// Configuration
const DEFAULT_CONFIG = {
    circuitName: 'policy_test',
    circuitWasmUrl: '/circuits/policy_test.wasm',
    provingKeyUrl: '/keys/policy_test_proving_key.bin',
    r1csUrl: '/circuits/policy_test.r1cs',
    cacheName: 'zk-proving-artifacts',
};

let config = { ...DEFAULT_CONFIG };

// State
let prover = null;
let witnessCalc = null;
let proverModuleInitialized = false;
let witnessModuleInitialized = false;
let proverInitialized = false;
let witnessInitialized = false;

// Cached artifacts
let cachedProvingKey = null;
let cachedR1cs = null;
let cachedCircuitWasm = null;

// Download state
let downloadPromise = null;

// Caching (Cache API)
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
        cachedCircuitWasm = null;
        downloadPromise = null;
        console.log('[ZK] Cache cleared');
    } catch (e) {
        console.warn('[ZK] Cache clear failed:', e.message);
    }
}

// Download with Progress

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
        if (onProgress) onProgress(loaded, total, url);
    }

    const result = new Uint8Array(loaded);
    let offset = 0;
    for (const chunk of chunks) {
        result.set(chunk, offset);
        offset += chunk.length;
    }

    return result;
}

// Lazy Loading

/**
 * Ensure proving artifacts are loaded (with caching and progress)
 * 
 * @param {function} onProgress - Optional callback: (loaded, total, message) => void
 * @returns {Promise<{provingKey: Uint8Array, r1cs: Uint8Array}>}
 */
export async function ensureProvingArtifacts(onProgress) {
    if (cachedProvingKey && cachedR1cs) {
        return { provingKey: cachedProvingKey, r1cs: cachedR1cs };
    }

    if (downloadPromise) {
        return downloadPromise;
    }

    downloadPromise = (async () => {
        try {
            let pk = cachedProvingKey || await getCached(config.provingKeyUrl);
            let r1cs = cachedR1cs || await getCached(config.r1csUrl);

            const needsPk = !pk;
            const needsR1cs = !r1cs;

            if (needsPk || needsR1cs) {
                const pkSize = needsPk ? 5000000 : 0;
                const r1csSize = needsR1cs ? 3500000 : 0;
                const totalSize = pkSize + r1csSize;
                let pkLoaded = 0, r1csLoaded = 0;

                const reportProgress = () => {
                    if (onProgress) {
                        const loaded = pkLoaded + r1csLoaded;
                        const message = needsPk && pkLoaded < pkSize 
                            ? 'Downloading proving key...'
                            : 'Downloading circuit constraints...';
                        onProgress(loaded, totalSize, message);
                    }
                };

                const downloads = [];

                if (needsPk) {
                    downloads.push(
                        downloadWithProgress(config.provingKeyUrl, (loaded) => {
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
                        downloadWithProgress(config.r1csUrl, (loaded) => {
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
            return { provingKey: pk, r1cs };
        } finally {
            // Reset so failed downloads can be retried
            downloadPromise = null;
        }
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

// Initialization

/**
 * Configure the ZK system URLs
 * Call before any initialization if using non-default paths
 * 
 * @param {Object} options
 * @param {string} options.circuitName - Circuit name (e.g., 'policy_test')
 * @param {string} options.circuitWasmUrl - URL to circuit.wasm
 * @param {string} options.provingKeyUrl - URL to proving key
 * @param {string} options.r1csUrl - URL to R1CS file
 */
export function configure(options) {
    config = { ...config, ...options };
}

/**
 * Initializes the prover WASM module
 * 
 * @returns {Promise<void>}
 */
export async function initProverWasm() {
    if (!proverModuleInitialized) {
        await initProverModule();
        proverModuleInitialized = true;
        console.log('[ZK] Prover WASM module initialized');
    }
}

/**
 * Initialize the witness WASM module (ark-circom)
 */
export async function initWitnessModuleWasm() {
    if (!witnessModuleInitialized) {
        await initWitnessWasm();
        witnessModuleInitialized = true;
        console.log(`[ZK] Witness WASM module initialized (v${witnessVersion()})`);
    }
}

/**
 * Initialize witness calculator with circuit files
 * 
 * @param {string} circuitWasmUrl - Optional URL to circuit.wasm
 * @param {string} r1csUrl - Optional URL to circuit.r1cs
 * @returns {Promise<Object>} Circuit info
 */
export async function initWitnessModule(circuitWasmUrl, r1csUrl) {
    await initWitnessModuleWasm();
 
    if (witnessInitialized && witnessCalc) {
        return getCircuitInfo();
    }

    const wasmUrl = circuitWasmUrl || config.circuitWasmUrl;
    const r1cs = r1csUrl || config.r1csUrl;

    // Load circuit WASM
    let circuitWasm = cachedCircuitWasm || await getCached(wasmUrl);
    if (!circuitWasm) {
        const response = await fetch(wasmUrl);
        if (!response.ok) throw new Error(`Failed to fetch circuit WASM: ${response.status}`);
        circuitWasm = new Uint8Array(await response.arrayBuffer());
        await setCache(wasmUrl, circuitWasm);
        cachedCircuitWasm = circuitWasm;
        console.log(`[ZK] Circuit WASM downloaded: ${(circuitWasm.length / 1024).toFixed(2)} KB`);
    }

    // Load R1CS
    let r1csBytes = cachedR1cs || await getCached(r1cs);
    if (!r1csBytes) {
        const response = await fetch(r1cs);
        if (!response.ok) throw new Error(`Failed to fetch R1CS: ${response.status}`);
        r1csBytes = new Uint8Array(await response.arrayBuffer());
        await setCache(r1cs, r1csBytes);
        cachedR1cs = r1csBytes;
        console.log(`[ZK] R1CS downloaded: ${(r1csBytes.length / 1024 / 1024).toFixed(2)} MB`);
    }

    // Create witness calculator
    witnessCalc = new WitnessCalculator(circuitWasm, r1csBytes);
    witnessInitialized = true;

    console.log('[ZK] Witness calculator initialized (ark-circom)');
    console.log(`[ZK]   - Witness size: ${witnessCalc.witness_size} elements`);
    console.log(`[ZK]   - Public inputs: ${witnessCalc.num_public_inputs}`);

    return getCircuitInfo();
}

/**
 * Initialize the full prover
 * 
 * Runs witness module init and artifact download in parallel for faster startup.
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

    // Initialize both modules and download artifacts in parallel
    const [, { provingKey, r1cs }] = await Promise.all([
        initWitnessModule(),
        ensureProvingArtifacts(onProgress),
    ]);

    await initProverWasm();

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
 * Full init with explicit bytes
 * 
 * @param {string} circuitWasmUrl - URL to circuit.wasm
 * @param {Uint8Array} provingKeyBytes - Proving key bytes (if already loaded)
 * @param {Uint8Array} r1csBytes - R1CS bytes (if already loaded)
 * @returns {Promise<Object>}
 */
export async function init(circuitWasmUrl, provingKeyBytes, r1csBytes) {
    await initWitnessModuleWasm();
    await initProverWasm();

    // Load circuit WASM for witness calculator
    const response = await fetch(circuitWasmUrl);
    if (!response.ok) {
        throw new Error(`Failed to fetch circuit WASM: ${response.status}`);
    }
    const circuitWasm = new Uint8Array(await response.arrayBuffer());

    witnessCalc = new WitnessCalculator(circuitWasm, r1csBytes);
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

// Circuit Info
/**
 * Get circuit info
 */
export function getCircuitInfo() {
    if (!witnessCalc) {
        throw new Error('Witness calculator not initialized.');
    }
    return {
        witnessSize: witnessCalc.witness_size,
        numPublicInputs: witnessCalc.num_public_inputs,
    };
}

// Input Preparation

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
 * Poseidon2 compression
 */
export { poseidon2_compression_wasm as poseidon2_compression_wasm };

// Merkle Tree Operations

/**
 * Create a new Merkle tree
 * @param {number} depth - Tree depth (e.g., 20 for 2^20 leaves)
 * @returns {MerkleTree} Merkle tree instance
 */
export function createMerkleTree(depth) {
    return new MerkleTree(depth);
}

/**
 * Create a new Merkle tree with a custom zero leaf value.
 * Used for matching contract implementations that use non-zero empty leaves.
 * @param {number} depth - Tree depth (e.g., 5 for 2^5 leaves)
 * @param {Uint8Array} zeroLeafBytes - Custom zero leaf value as 32 bytes (Little-Endian)
 * @returns {MerkleTree} Merkle tree instance
 */
export function createMerkleTreeWithZeroLeaf(depth, zeroLeafBytes) {
    return MerkleTree.new_with_zero_leaf(depth, zeroLeafBytes);
}

export { MerkleTree, MerkleProof, WasmSparseMerkleTree };

// Serialization Utilities

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

export { hex_to_field_bytes as hexToField };
export { field_bytes_to_hex as fieldToHex };

/**
 * Convert little-endian bytes to BigInt.
 * 
 * Field elements from the prover are serialized as LE bytes.
 * This correctly interprets them as BigInt for circuit inputs.
 * 
 * @param {Uint8Array} bytes - Little-endian bytes (32 bytes for field elements)
 * @returns {bigint} The BigInt value
 */
export function bytesToBigIntLE(bytes) {
    let result = 0n;
    for (let i = bytes.length - 1; i >= 0; i--) {
        result = (result << 8n) | BigInt(bytes[i]);
    }
    return result;
}

// Witness Generation

/**
 * Generate witness from circuit inputs
 * 
 * @param {Object} inputs - Circuit inputs as { signalName: value | value[] }
 * @returns {Promise<Uint8Array>} Witness bytes (Little-Endian, 32 bytes per element)
 */
export async function generateWitness(inputs) {
    if (!witnessInitialized || !witnessCalc) {
        throw new Error('Witness module not initialized. Call initWitnessModule() first.');
    }

    const inputsJson = JSON.stringify(inputs);
    const witnessBytes = witnessCalc.compute_witness(inputsJson);

    return new Uint8Array(witnessBytes);
}

/**
 * Convert bytes to BigInt array (for debugging)
 */
export function bytesToWitness(bytes) {
    const FIELD_SIZE = 32;
    if (bytes.length % FIELD_SIZE !== 0) {
        throw new Error(`Witness bytes length ${bytes.length} is not a multiple of ${FIELD_SIZE}`);
    }

    const numElements = bytes.length / FIELD_SIZE;
    const witness = new Array(numElements);

    for (let i = 0; i < numElements; i++) {
        let value = 0n;
        for (let j = FIELD_SIZE - 1; j >= 0; j--) {
            value = (value << 8n) | BigInt(bytes[i * FIELD_SIZE + j]);
        }
        witness[i] = value;
    }

    return witness;
}

// Proof Generation

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

/**
 * Convert compressed proof bytes to Soroban-compatible uncompressed format.
 *
 * @param {Uint8Array} proofBytes - Compressed proof bytes from generateProofBytes()
 * @returns {Uint8Array} Uncompressed proof bytes ready for Soroban contracts
 */
export function proofBytesToSoroban(proofBytes) {
    return convert_proof_to_soroban(proofBytes);
}

/**
 * Generate proof and return as uncompressed Soroban-ready bytes.
 * 
 * @param {Uint8Array} witnessBytes - Witness from generateWitness()
 * @returns {Uint8Array} Uncompressed proof bytes [A || B || C] = 256 bytes
 */
export function generateProofBytesSoroban(witnessBytes) {
    if (!proverInitialized || !prover) {
        throw new Error('Prover not initialized. Call initProver() first.');
    }
    return prover.prove_bytes_uncompressed(witnessBytes);
}

/**
 * Derive X25519 encryption keypair from Freighter signature.
 * Used for encrypting/decrypting note data (amount, blinding).
 * 
 * Derivation: signature (64 bytes) → SHA-256 → X25519 keypair
 * Message: "Sign to access Privacy Pool [v1]"
 * 
 * @param {Uint8Array} signature - Stellar Ed25519 signature (64 bytes)
 * @returns {{publicKey: Uint8Array, privateKey: Uint8Array}} X25519 keypair
 */
export function deriveEncryptionKeypairFromSignature(signature) {
    if (signature.length !== 64) {
        throw new Error('Signature must be 64 bytes (Ed25519)');
    }
    
    const result = derive_keypair_from_signature(signature);
    return {
        publicKey: new Uint8Array(result.slice(0, 32)),
        privateKey: new Uint8Array(result.slice(32, 64)),
    };
}

/**
 * Derive note private key (BN254 scalar) from Freighter signature.
 * Used inside ZK circuits to prove ownership of notes.
 * 
 * Derivation: signature (64 bytes) → SHA-256 → BN254 scalar
 * Message: "Privacy Pool Spending Key [v1]"
 * 
 * The corresponding public key is derived via: Poseidon2(privateKey, 0, domain=0x03)
 * 
 * @param {Uint8Array} signature - Stellar Ed25519 signature (64 bytes)
 * @returns {Uint8Array} Note private key (32 bytes, BN254 scalar)
 */
export function deriveNotePrivateKeyFromSignature(signature) {
    if (signature.length !== 64) {
        throw new Error('Signature must be 64 bytes (Ed25519)');
    }
    
    return new Uint8Array(derive_note_private_key(signature));
}

/**
 * Generate a cryptographically random blinding factor for a note.
 * Each note needs a unique blinding to ensure commitment uniqueness.
 * 
 * Unlike private keys, blindings are NOT derived from signatures.
 * They are random per-note and stored encrypted on-chain.
 * 
 * @returns {Uint8Array} Random blinding (32 bytes, BN254 scalar)
 */
export function generateBlinding() {
    return new Uint8Array(generate_random_blinding());
}

/**
 * Encrypt note data for a recipient (X25519-XSalsa20-Poly1305).
 * 
 * Output format: [ephemeralPubKey (32)] [nonce (24)] [ciphertext+tag (56)]
 * Total: 112 bytes
 * 
 * @param {Uint8Array} recipientPubKey - Recipient's X25519 encryption public key (32 bytes)
 * @param {Object} noteData - { amount: bigint, blinding: Uint8Array (32 bytes) }
 * @returns {Uint8Array} Encrypted data (112 bytes)
 */
export function encryptNoteData(recipientPubKey, noteData) {
    if (recipientPubKey.length !== 32) {
        throw new Error('Recipient public key must be 32 bytes');
    }
    
    // Prepare plaintext: amount (8 bytes LE) + blinding (32 bytes) = 40 bytes
    const plaintext = new Uint8Array(40);
    const amountBytes = bigintToLittleEndian(noteData.amount, 8);
    plaintext.set(amountBytes, 0);
    plaintext.set(noteData.blinding, 8);
    
    return new Uint8Array(encrypt_note_data(recipientPubKey, plaintext));
}

/**
 * Decrypt note data using our X25519 private key.
 * 
 * If decryption succeeds, the note was addressed to us.
 * If it fails, the note was for someone else.
 * 
 * @param {Uint8Array} privateKey - Our X25519 encryption private key (32 bytes)
 * @param {Uint8Array} encryptedData - Encrypted data from on-chain event
 * @returns {Object|null} { amount: bigint, blinding: Uint8Array } or null if not for us
 */
export function decryptNoteData(privateKey, encryptedData) {
    if (privateKey.length !== 32) {
        return null;
    }
    
    try {
        const plaintext = decrypt_note_data(privateKey, encryptedData);
        
        // Empty result means decryption failed (not addressed to us)
        if (plaintext.length !== 40) {
            return null;
        }
        
        const amountBytes = plaintext.slice(0, 8);
        const blinding = new Uint8Array(plaintext.slice(8, 40));
        
        // Convert amount from little-endian
        let amount = 0n;
        for (let i = 7; i >= 0; i--) {
            amount = (amount << 8n) | BigInt(amountBytes[i]);
        }
        
        return { amount, blinding };
    } catch (e) {
        console.warn('[bridge] decryptNoteData error:', e);
        return null;
    }
}

/**
 * Convert bigint to little-endian byte array.
 * @param {bigint} value - Value to convert
 * @param {number} length - Output byte length
 * @returns {Uint8Array}
 */
export function bigintToLittleEndian(value, length) {
    const bytes = new Uint8Array(length);
    let v = value;
    for (let i = 0; i < length; i++) {
        bytes[i] = Number(v & 0xFFn);
        v = v >> 8n;
    }
    return bytes;
}

// High-Level API

/**
 * Generate a complete ZK proof from circuit inputs
 * 
 * @param {Object} inputs - Circuit inputs
 * @param {function} onProgress - Optional progress callback for artifact download
 * @returns {Promise<{proof: Uint8Array, publicInputs: Uint8Array}>}
 */
export async function prove(inputs, onProgress) {
    if (!proverInitialized) {
        await initProver(onProgress);
    }

    const witnessBytes = await generateWitness(inputs);
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

    return { proof, publicInputs, verified };
}


// We copy this helper function here to keep bridge.js self-contained.
// This way we don't need to bundle it with additional files from the frontend.
/**
 * Transforms bytes into a hex String
 * @param bytes
 * @returns {string}
 */
function bytesToHex(bytes) {
    return '0x' + Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

export function getBN256Modulus() {
    return bytesToHex(bn256_modulus())
}

export function getZeroLeaf() {
    return bytesToHex(zero_leaf())
}