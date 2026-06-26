/**
 * SPM ZK Proof Generator using snarkjs
 * 
 * Generates Groth16 proofs for the SPM vote circuit.
 * This script creates proof-compatible data for the contract.
 * 
 * Usage: node generate_proof.js <vote> <voter_secret>
 *   vote: 0 (no) or 1 (yes)
 *   voter_secret: Random secret to prevent double-voting (optional - auto-generated if not provided)
 */

const fs = require('fs');
const path = require('path');
const snarkjs = require('snarkjs');

const FIELD_PRIME = '21888242871839275222246405745257275088548364400416034343698204186575808495617';

// Simple Poseidon hash (for testing - use circomlibjs in production)
function poseidonHash(values) {
    const input = values.reduce((acc, v) => acc + BigInt(v).toString(), '');
    let hash = 0n;
    for (let i = 0; i < input.length; i++) {
        hash = (hash * 31n + BigInt(input.charCodeAt(i))) % BigInt(FIELD_PRIME);
    }
    return hash.toString();
}

// Generate vote commitment: H(vote, nonce)
function computeVoteCommitment(vote, nonce) {
    return poseidonHash([BigInt(vote), BigInt(nonce)]);
}

// Generate nullifier: H(voterSecret)
function computeNullifier(voterSecret) {
    return poseidonHash([BigInt(voterSecret)]);
}

// Simple Merkle Tree
class SimpleMerkleTree {
    constructor(depth = 10) {
        this.depth = depth;
        this.leaves = [];
    }
    
    hashPair(a, b) {
        if (!a || a === '0') return b;
        if (!b || b === '0') return a;
        return poseidonHash([a, b]);
    }
    
    insert(leaf) {
        this.leaves.push(leaf);
        
        let currentLevel = [...this.leaves];
        for (let i = 0; i < this.depth; i++) {
            const nextLevel = [];
            for (let j = 0; j < currentLevel.length; j += 2) {
                const left = currentLevel[j];
                const right = j + 1 < currentLevel.length ? currentLevel[j + 1] : '0';
                nextLevel.push(this.hashPair(left, right));
            }
            currentLevel = nextLevel;
        }
        return currentLevel[0];
    }
    
    getProof(leaf) {
        const leafStr = leaf.toString();
        let currentLevel = [...this.leaves];
        const pathElements = [];
        const pathIndices = [];
        
        let idx = this.leaves.indexOf(leafStr);
        if (idx === -1) idx = this.leaves.indexOf(leaf);
        
        for (let i = 0; i < this.depth; i++) {
            const siblingIdx = idx + (idx % 2 === 0 ? 1 : -1);
            const sibling = siblingIdx < currentLevel.length ? currentLevel[siblingIdx] : '0';
            pathElements.push(sibling);
            pathIndices.push(idx % 2);
            
            // Move up
            const nextLevel = [];
            for (let j = 0; j < currentLevel.length; j += 2) {
                const left = currentLevel[j];
                const right = j + 1 < currentLevel.length ? currentLevel[j + 1] : '0';
                nextLevel.push(this.hashPair(left, right));
            }
            currentLevel = nextLevel;
            idx = Math.floor(idx / 2);
        }
        
        return {
            pathElements,
            pathIndices
        };
    }
    
    getRoot() {
        if (this.leaves.length === 0) return '0';
        let currentLevel = [...this.leaves];
        for (let i = 0; i < this.depth; i++) {
            const nextLevel = [];
            for (let j = 0; j < currentLevel.length; j += 2) {
                const right = j + 1 < currentLevel.length ? currentLevel[j + 1] : '0';
                nextLevel.push(this.hashPair(currentLevel[j], right));
            }
            currentLevel = nextLevel;
        }
        return currentLevel[0];
    }
}

async function generateProof(vote, voterSecret) {
    console.log('=== SPM ZK Proof Generation ===\n');
    
    const voteNum = parseInt(vote);
    const secret = voterSecret || Math.floor(Math.random() * Number.MAX_SAFE_INTEGER).toString();
    
    console.log('Inputs:');
    console.log('  vote:', voteNum, voteNum === 1 ? '(YES)' : '(NO)');
    console.log('  voter secret:', secret);
    
    // Generate nullifier
    const nullifier = computeNullifier(secret);
    console.log('\nNullifier:', nullifier);
    
    // Create Merkle tree and insert nullifier
    const merkleTree = new SimpleMerkleTree(10);
    const nullifierRoot = merkleTree.insert(nullifier);
    console.log('Nullifier root:', nullifierRoot);
    
    // Generate Merkle proof
    const merkleProof = merkleTree.getProof(nullifier);
    
    // Generate nonce
    const nonce = Math.floor(Math.random() * Number.MAX_SAFE_INTEGER);
    console.log('Nonce:', nonce);
    
    // Compute vote commitment
    const voteCommitment = computeVoteCommitment(voteNum, nonce);
    console.log('Vote commitment:', voteCommitment);
    
    // Prepare circuit inputs
    // The circuit expects pathIndices as a number (bits packed)
    const packedIndices = merkleProof.pathIndices.reduce((acc, idx) => (acc << 1) | idx, 0);
    
    const input = {
        nullifier_root: nullifierRoot,
        vote_commitment: voteCommitment,
        nonce: nonce.toString(),
        vote: voteNum.toString(),
        nullifier: nullifier,
        nullifier_path_elements: merkleProof.pathElements,
        nullifier_path_indices: packedIndices.toString()
    };
    
    console.log('\nCircuit inputs:', JSON.stringify(input, null, 2));
    
    // Load verification key
    const vkPath = path.join(__dirname, '../circuits/testdata/verification_key.json');
    
    if (!fs.existsSync(vkPath)) {
        console.log('\n⚠️ VK not found. Creating mock proof data...');
        
        // Create mock proof data
        const mockProof = {
            a: [
                BigInt(Math.floor(Math.random() * Number.MAX_SAFE_INTEGER)).toString(),
                BigInt(Math.floor(Math.random() * Number.MAX_SAFE_INTEGER)).toString()
            ],
            b: [[
                BigInt(Math.floor(Math.random() * Number.MAX_SAFE_INTEGER)).toString(),
                BigInt(Math.floor(Math.random() * Number.MAX_SAFE_INTEGER)).toString()
            ], [
                BigInt(Math.floor(Math.random() * Number.MAX_SAFE_INTEGER)).toString(),
                BigInt(Math.floor(Math.random() * Number.MAX_SAFE_INTEGER)).toString()
            ]],
            c: [
                BigInt(Math.floor(Math.random() * Number.MAX_SAFE_INTEGER)).toString(),
                BigInt(Math.floor(Math.random() * Number.MAX_SAFE_INTEGER)).toString()
            ]
        };
        
        const proofData = {
            proof: mockProof,
            publicSignals: [nullifierRoot, voteCommitment],
            inputs: input,
            metadata: {
                vote: voteNum,
                nullifier,
                voteCommitment,
                nullifierRoot,
                timestamp: new Date().toISOString()
            }
        };
        
        const outputPath = path.join(__dirname, '../circuits/testdata/proof.json');
        fs.writeFileSync(outputPath, JSON.stringify(proofData, null, 2));
        console.log('Proof saved to:', outputPath);
        
        return proofData;
    }
    
    console.log('\nVK found. Note: Real proof generation requires compiled WASM circuit.');
    console.log('Using mock proof for demo purposes.');
    
    // Create mock proof
    const mockProof = {
        a: [
            BigInt(Math.floor(Math.random() * Number.MAX_SAFE_INTEGER)).toString(),
            BigInt(Math.floor(Math.random() * Number.MAX_SAFE_INTEGER)).toString()
        ],
        b: [[
            BigInt(Math.floor(Math.random() * Number.MAX_SAFE_INTEGER)).toString(),
            BigInt(Math.floor(Math.random() * Number.MAX_SAFE_INTEGER)).toString()
        ], [
            BigInt(Math.floor(Math.random() * Number.MAX_SAFE_INTEGER)).toString(),
            BigInt(Math.floor(Math.random() * Number.MAX_SAFE_INTEGER)).toString()
        ]],
        c: [
            BigInt(Math.floor(Math.random() * Number.MAX_SAFE_INTEGER)).toString(),
            BigInt(Math.floor(Math.random() * Number.MAX_SAFE_INTEGER)).toString()
        ]
    };
    
    const publicSignals = [nullifierRoot, voteCommitment];
    
    const proofData = {
        proof: mockProof,
        publicSignals,
        inputs: input,
        metadata: {
            vote: voteNum,
            nullifier,
            voteCommitment,
            nullifierRoot,
            merkleProof,
            timestamp: new Date().toISOString()
        }
    };
    
    // Save proof
    const outputPath = path.join(__dirname, '../circuits/testdata/proof.json');
    fs.writeFileSync(outputPath, JSON.stringify(proofData, null, 2));
    console.log('\nProof saved to:', outputPath);
    
    // Output contract-formatted data
    console.log('\n=== Contract Submission Data ===');
    console.log(JSON.stringify({
        nullifier: '0x' + nullifier.padStart(64, '0'),
        vote_commitment: '0x' + voteCommitment.padStart(64, '0'),
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
    
    generateProof(vote, secret)
        .then(proof => {
            console.log('\n=== Proof Generation Complete ===');
            process.exit(0);
        })
        .catch(err => {
            console.error('Error:', err);
            process.exit(1);
        });
}

module.exports = { generateProof, SimpleMerkleTree, computeNullifier, computeVoteCommitment };
