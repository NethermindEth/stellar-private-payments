/**
 * SPM Proof Generator
 * Generates ZK proofs for vote submissions
 * 
 * Usage: node prove.js <vote> <nullifier_secret>
 *   vote: 0 (no) or 1 (yes)
 *   nullifier_secret: random secret to prevent double-voting
 */

const fs = require('fs');
const path = require('path');

// Load snarkjs
let snarkjs;
try {
    snarkjs = require('snarkjs');
} catch (e) {
    console.error('snarkjs not found. Run: npm install snarkjs');
    process.exit(1);
}

// Field prime for BN254
const FIELD_PRIME = BigInt('21888242871839275222246405745257275088548364400416034343698204186575808495617');

// Load VK
const vkPath = path.join(__dirname, '../testdata/verification_key.json');
const vk = JSON.parse(fs.readFileSync(vkPath, 'utf8'));

// Simulated Merkle tree for nullifiers
// In production, this would be maintained off-chain
class SimpleMerkleTree {
    constructor(depth = 10) {
        this.depth = depth;
        this.leaves = [];
        this.nodes = new Map();
    }
    
    // Simple hash function for tree
    hashPair(a, b) {
        if (!a || a === '0') return b;
        if (!b || b === '0') return a;
        const input = a.toString() + b.toString();
        return this.poseidonHash([a, b]);
    }
    
    // Poseidon hash (simplified - use circomlibjs in production)
    poseidonHash(values) {
        const input = values.reduce((acc, v) => acc + v.toString(), '');
        let hash = 0n;
        for (let i = 0; i < input.length; i++) {
            hash = (hash * 31n + BigInt(input.charCodeAt(i))) % FIELD_PRIME;
        }
        return hash.toString();
    }
    
    // Insert a leaf and return the new root
    insert(leaf) {
        this.leaves.push(leaf);
        
        // Build tree bottom-up
        let currentLevel = this.leaves.map(l => l.toString());
        
        while (currentLevel.length > 1) {
            const nextLevel = [];
            for (let i = 0; i < currentLevel.length; i += 2) {
                const left = currentLevel[i];
                const right = i + 1 < currentLevel.length ? currentLevel[i + 1] : '0';
                nextLevel.push(this.hashPair(left, right));
            }
            currentLevel = nextLevel;
        }
        
        return currentLevel[0];
    }
    
    // Get Merkle proof for a leaf
    getProof(leaf) {
        const leafStr = leaf.toString();
        const index = this.leaves.indexOf(leafStr);
        if (index === -1) {
            // Try as bigint
            const index2 = this.leaves.indexOf(leaf.toString());
            if (index2 === -1) throw new Error('Leaf not in tree');
        }
        
        const idx = index2 !== -1 ? index2 : index;
        
        let currentLevel = this.leaves.map(l => l.toString());
        const proof = [];
        const pathIndices = [];
        
        let currentIndex = idx;
        
        for (let i = 0; i < this.depth; i++) {
            const siblingIndex = currentIndex % 2 === 0 ? currentIndex + 1 : currentIndex - 1;
            
            if (siblingIndex < currentLevel.length) {
                proof.push(currentLevel[siblingIndex]);
            } else {
                proof.push('0');
            }
            
            pathIndices.push(currentIndex % 2);
            
            // Move up
            const nextLevel = [];
            for (let j = 0; j < currentLevel.length; j += 2) {
                const left = currentLevel[j];
                const right = j + 1 < currentLevel.length ? currentLevel[j + 1] : '0';
                nextLevel.push(this.hashPair(left, right));
            }
            currentLevel = nextLevel;
            currentIndex = Math.floor(currentIndex / 2);
        }
        
        return {
            pathElements: proof,
            pathIndices: pathIndices.reduce((acc, idx) => {
                acc = (acc << 1) | idx;
                return acc;
            }, 0)
        };
    }
    
    getRoot() {
        if (this.leaves.length === 0) return '0';
        let currentLevel = this.leaves.map(l => l.toString());
        while (currentLevel.length > 1) {
            const nextLevel = [];
            for (let i = 0; i < currentLevel.length; i += 2) {
                const right = i + 1 < currentLevel.length ? currentLevel[i + 1] : '0';
                nextLevel.push(this.hashPair(currentLevel[i], right));
            }
            currentLevel = nextLevel;
        }
        return currentLevel[0];
    }
}

// Poseidon hash function (simplified for testing)
// In production, use circomlibjs
function poseidonHash(values) {
    const input = values.reduce((acc, v) => acc + v.toString(), '');
    let hash = 0n;
    for (let i = 0; i < input.length; i++) {
        hash = (hash * 31n + BigInt(input.charCodeAt(i))) % FIELD_PRIME;
    }
    return hash;
}

// Generate vote commitment: H(vote, nonce)
function computeVoteCommitment(vote, nonce) {
    return poseidonHash([BigInt(vote), BigInt(nonce)]);
}

// Generate nullifier: H(voterSecret)
function computeNullifier(voterSecret) {
    return poseidonHash([BigInt(voterSecret)]);
}

// Main proof generation
async function generateProof(vote, voterSecret, merkleTree) {
    console.log('=== SPM ZK Proof Generation ===\n');
    
    // Parse inputs
    const voteNum = parseInt(vote);
    const secret = voterSecret || Math.floor(Math.random() * Number.MAX_SAFE_INTEGER).toString();
    
    console.log('Inputs:');
    console.log('  vote:', voteNum, voteNum === 1 ? '(YES)' : '(NO)');
    console.log('  voter secret:', secret);
    
    // Generate nullifier
    const nullifier = computeNullifier(secret);
    console.log('\nNullifier:', nullifier.toString());
    
    // Insert nullifier into Merkle tree
    const nullifierRoot = merkleTree.insert(nullifier);
    console.log('Nullifier root:', nullifierRoot);
    
    // Generate Merkle proof
    const merkleProof = merkleTree.getProof(nullifier);
    console.log('Merkle path indices:', merkleProof.pathIndices);
    
    // Generate nonce (random)
    const nonce = Math.floor(Math.random() * Number.MAX_SAFE_INTEGER);
    console.log('\nNonce:', nonce);
    
    // Compute vote commitment
    const voteCommitment = computeVoteCommitment(voteNum, nonce);
    console.log('Vote commitment:', voteCommitment.toString());
    
    // Prepare inputs for the circuit
    // Note: The circuit expects pathIndices as a single signal (not array)
    const input = {
        nullifier_root: nullifierRoot.toString(),
        vote_commitment: voteCommitment.toString(),
        nonce: nonce.toString(),
        vote: voteNum.toString(),
        nullifier: nullifier.toString(),
        nullifier_path_elements: merkleProof.pathElements.map(e => e.toString()),
        nullifier_path_indices: merkleProof.pathIndices.toString()
    };
    
    console.log('\nCircuit inputs prepared');
    console.log('  nullifier_root:', input.nullifier_root);
    console.log('  vote_commitment:', input.vote_commitment);
    
    // For demo purposes, we'll create a mock proof
    // In production, you would:
    // 1. Compile the circuit with circom
    // 2. Generate witness with WASM
    // 3. Generate proof with snarkjs groth16 proof
    
    console.log('\n=== Generating ZK Proof ===');
    console.log('(Using mock proof for demo - requires WASM prover for real proofs)');
    
    // Mock proof data (this is what would be generated by snarkjs in production)
    const mockProof = {
        a: [
            snarkjs.bigInt(Math.floor(Math.random() * Number.MAX_SAFE_INTEGER)).toString(),
            snarkjs.bigInt(Math.floor(Math.random() * Number.MAX_SAFE_INTEGER)).toString()
        ],
        b: [[
            snarkjs.bigInt(Math.floor(Math.random() * Number.MAX_SAFE_INTEGER)).toString(),
            snarkjs.bigInt(Math.floor(Math.random() * Number.MAX_SAFE_INTEGER)).toString()
        ], [
            snarkjs.bigInt(Math.floor(Math.random() * Number.MAX_SAFE_INTEGER)).toString(),
            snarkjs.bigInt(Math.floor(Math.random() * Number.MAX_SAFE_INTEGER)).toString()
        ]],
        c: [
            snarkjs.bigInt(Math.floor(Math.random() * Number.MAX_SAFE_INTEGER)).toString(),
            snarkjs.bigInt(Math.floor(Math.random() * Number.MAX_SAFE_INTEGER)).toString()
        ]
    };
    
    const publicSignals = [input.nullifier_root, input.vote_commitment];
    
    console.log('\nProof generated (mock):');
    console.log('  A:', mockProof.a);
    console.log('  B:', mockProof.b);
    console.log('  C:', mockProof.c);
    console.log('  Public signals:', publicSignals);
    
    // Save proof to file
    const proofData = {
        proof: mockProof,
        publicSignals: publicSignals,
        inputs: input,
        metadata: {
            vote: voteNum,
            nullifier: nullifier.toString(),
            voteCommitment: voteCommitment.toString(),
            nullifierRoot: nullifierRoot.toString(),
            merkleProof: merkleProof,
            timestamp: new Date().toISOString()
        }
    };
    
    const outputPath = path.join(__dirname, '../testdata/proof.json');
    fs.writeFileSync(outputPath, JSON.stringify(proofData, null, 2));
    console.log('\nProof saved to:', outputPath);
    
    // Output contract-formatted data
    console.log('\n=== Contract Submission Data ===');
    console.log(JSON.stringify({
        nullifier: '0x' + nullifier.toString(16).padStart(64, '0'),
        vote_commitment: '0x' + voteCommitment.toString(16).padStart(64, '0'),
        proof_a: mockProof.a,
        proof_b: mockProof.b,
        proof_c: mockProof.c
    }, null, 2));
    
    return proofData;
}

// Run if executed directly
if (require.main === module) {
    const vote = process.argv[2] || '1';
    const secret = process.argv[3];
    
    const merkleTree = new SimpleMerkleTree(10);
    
    generateProof(vote, secret, merkleTree)
        .then(proof => {
            console.log('\n=== Proof Generation Complete ===');
            process.exit(0);
        })
        .catch(err => {
            console.error('Error:', err);
            process.exit(1);
        });
}

module.exports = { generateProof, SimpleMerkleTree, poseidonHash, computeNullifier, computeVoteCommitment };
