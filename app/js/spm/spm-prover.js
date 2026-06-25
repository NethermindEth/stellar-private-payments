/**
 * SPM Prover Utilities
 * Handles ZK proof generation for vote submissions using snarkjs
 * 
 * This module provides:
 * - Poseidon hashing (using circomlibjs or fallback)
 * - Vote commitment generation
 * - Nullifier generation
 * - ZK proof generation via snarkjs (when WASM is available)
 * 
 * Required resources (loaded dynamically):
 * - snarkjs library
 * - circomlibjs for Poseidon
 * - WASM prover from circuit compilation
 * - Verification key from trusted setup
 */

// Field prime for BN254
const FIELD_PRIME = '21888242871839275222246405745257275088548364400416034343698204186575808495617';

// Pre-generated VK parameters for the SPM circuit
// From trusted setup ceremony at circuits/testdata/
export const SPM_VK = {
    alpha: [
        "20491192805390485299153009773594534940189261866228447918068658471970481763042",
        "9383485363053290200918347156157836566562967994039712273449902621266178545958",
        "1"
    ],
    beta: [
        [
            "4254721685818098701783170215890134850466005299641409500528792082283532222074",
            "6375614351688725206403948262868962793625744043794305715222011528459656738731"
        ],
        [
            "2184709360559954549471216984807972045183575412164539507322028326063825888289",
            "1050524262637026227755290108209435669740983568022059097187317134030482525587"
        ],
        ["1", "0"]
    ],
    gamma: [
        [
            "11559732032986387107991004021392285783925812861821192530917403151452391805634",
            "10857046999023057135944570762232829481370756359578518086990519993285655852781"
        ],
        [
            "4082367875863433681332203403145435568316851327593401208105741076214120093531",
            "8495653923123431417604973247489272438418190587263600148770280649306958101930"
        ],
        ["1", "0"]
    ],
    delta: [
        [
            "15783017124344870385500234244231281207463293850615882076646238333413896018414",
            "4828890285726297462724392016056444727072516691098302725874750009972369715995"
        ],
        [
            "17359853821369175172372724751326026809387507588711211623918591475683972612742",
            "6076550856428168319448640750403119928937661079586295305614919653643163662433"
        ],
        ["1", "0"]
    ],
    IC: [
        ["3353031288059533942658390886683067124040920775575537747144343083137631628272", 
         "19321533766552368860946552437480515441416830039777911637913418824951667761761", "1"],
        ["0", "1", "0"],
        ["0", "1", "0"]
    ]
};

/**
 * Load snarkjs from CDN
 */
async function loadSnarkjs() {
    if (typeof window === 'undefined') {
        const snarkjs = await import('snarkjs');
        return snarkjs;
    }
    
    if (window.snarkjs) return window.snarkjs;
    
    return new Promise((resolve, reject) => {
        const script = document.createElement('script');
        script.src = 'https://cdn.jsdelivr.net/npm/snarkjs@0.7.3/build/snarkjs.min.js';
        script.onload = () => resolve(window.snarkjs);
        script.onerror = reject;
        document.head.appendChild(script);
    });
}

/**
 * Load circomlibjs for Poseidon
 */
async function loadCircomlibjs() {
    if (typeof window === 'undefined') return null;
    if (window.circomlibjs) return window.circomlibjs;
    
    return new Promise((resolve, reject) => {
        const script = document.createElement('script');
        script.src = 'https://cdn.jsdelivr.net/npm/circomlibjs@0.1.7/bundle.min.js';
        script.onload = () => resolve(window.circomlibjs);
        script.onerror = reject;
        document.head.appendChild(script);
    });
}

/**
 * Convert a number to a field element (big-endian 32 bytes)
 */
export function toFieldElement(value) {
    const hex = BigInt(value).toString(16).padStart(64, '0');
    return '0x' + hex;
}

/**
 * Generate a random field element
 */
function randomFieldElement() {
    let hex = '';
    for (let i = 0; i < 64; i++) {
        hex += Math.floor(Math.random() * 16).toString(16);
    }
    return BigInt('0x' + hex) % BigInt(FIELD_PRIME);
}

/**
 * Generate a random hex string
 */
export function randomHex(bytes) {
    let hex = '';
    for (let i = 0; i < bytes * 2; i++) {
        hex += Math.floor(Math.random() * 16).toString(16);
    }
    return '0x' + hex;
}

/**
 * Poseidon hash implementation
 * Uses circomlibjs for proper Poseidon when available
 */
export async function poseidonHash(values) {
    try {
        const circomlibjs = await loadCircomlibjs();
        if (circomlibjs) {
            const poseidon = await circomlibjs.buildPoseidon();
            const hash = poseidon.F.toObject(poseidon(values.map(x => BigInt(x))));
            return toFieldElement(hash);
        }
    } catch (e) {
        console.warn('[SPM Prover] circomlibjs not available, using fallback');
    }
    
    // Fallback: simplified hash (NOT cryptographically secure - for testing only)
    const input = values.reduce((acc, v) => acc + BigInt(v).toString(16), '');
    let hash = 0n;
    for (let i = 0; i < input.length; i++) {
        hash = (hash * 31n + BigInt(input.charCodeAt(i))) % BigInt(FIELD_PRIME);
    }
    return toFieldElement(hash);
}

/**
 * Generate a vote commitment: H(vote, nonce)
 * @param {number} vote - 0 (no) or 1 (yes)
 * @param {string} nonce - Random nonce
 */
export async function generateVoteCommitment(vote, nonce) {
    return await poseidonHash([BigInt(vote).toString(), nonce]);
}

/**
 * Generate a nullifier: H(voterSecret)
 * @param {string} voterSecret - Secret unique to this vote
 */
export async function generateNullifier(voterSecret) {
    return await poseidonHash([voterSecret]);
}

/**
 * Generate Merkle proof path (simplified for demo)
 * @param {string} nullifier - The nullifier hash
 * @param {number} treeDepth - Depth of the tree
 */
export function generateMerkleProof(nullifier, treeDepth = 10) {
    const pathIndices = [];
    const pathElements = [];

    for (let i = 0; i < treeDepth; i++) {
        pathIndices.push(Math.floor(Math.random() * 2));
        pathElements.push(randomHex(32));
    }

    return {
        nullifier,
        pathIndices,
        pathElements
    };
}

/**
 * Generate mock ZK proof (for demo purposes)
 * In production, this would call the WASM prover with actual circuit
 */
export async function generateMockProof({ vote, nonce, voterSecret, nullifierRoot }) {
    console.log('[SPM Prover] Generating mock proof...');

    // Generate commitment and nullifier
    const voteCommitment = await generateVoteCommitment(vote, nonce);
    const nullifier = await generateNullifier(voterSecret);

    // Generate Merkle proof
    const merkleProof = generateMerkleProof(nullifier);

    // Generate mock proof data (in production, this comes from snarkjs)
    const mockProof = {
        a: [randomHex(32), randomHex(32)],
        b: [[randomHex(32), randomHex(32)], [randomHex(32), randomHex(32)]],
        c: [randomHex(32), randomHex(32)],
        publicSignals: [nullifierRoot, voteCommitment]
    };

    console.log('[SPM Prover] Mock proof generated:', {
        voteCommitment,
        nullifier,
        proof: mockProof
    });

    return {
        proof: mockProof,
        publicSignals: mockProof.publicSignals,
        voteCommitment,
        nullifier,
        merkleProof
    };
}

/**
 * Generate a complete vote proof payload for the contract
 * @param {Object} params
 * @param {number} params.vote - 0 (no) or 1 (yes)
 * @param {string} params.nullifierRoot - Current nullifier root
 */
export async function generateVoteProof({ vote, nullifierRoot }) {
    // Generate random nonce and voter secret
    const nonce = Math.floor(Math.random() * Number.MAX_SAFE_INTEGER).toString();
    const voterSecret = Math.floor(Math.random() * Number.MAX_SAFE_INTEGER).toString();

    // Generate the proof
    const result = await generateMockProof({
        vote,
        nonce,
        voterSecret,
        nullifierRoot
    });

    // Format for contract submission
    return {
        nullifier: result.nullifier,
        voteCommitment: result.voteCommitment,
        proofData: JSON.stringify(result.proof),
        merkleProof: result.merkleProof
    };
}

/**
 * Verify a proof locally (simplified)
 */
export async function verifyProof(proof, publicSignals, verificationKey) {
    // In production, use snarkjs verify
    // This is a placeholder that always returns true for demo
    console.log('[SPM Prover] Verifying proof...');
    return true;
}

/**
 * Check if WASM prover is available
 */
export function isWasmProverAvailable() {
    // Would check if circomlibjs/snakjs WASM is loaded
    return false;
}

/**
 * Load WASM prover (for future implementation)
 */
export async function loadWasmProver() {
    // Would load the circomlibjs and snarkjs WASM modules
    console.log('[SPM Prover] WASM prover not yet implemented');
    return false;
}