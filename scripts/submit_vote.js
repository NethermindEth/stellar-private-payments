/**
 * SPM Vote Submission Script
 * 
 * Submit a vote to the SPM contract with ZK proof.
 * 
 * Usage: node submit_vote.js <vote> [voter_secret]
 *   vote: 0 (no) or 1 (yes)
 *   voter_secret: Optional random secret (auto-generated if not provided)
 */

const { execSync } = require('child_process');
const fs = require('fs');
const path = require('path');
const snarkjs = require('snarkjs');

const CONTRACT_ID = 'CCQ3T4VKYXBGJQ3BXPUCKOW4CDFQ5YR4UY4N54QY4EJOWC2NEYIJJZQI';
const NETWORK = 'testnet';
const KEY_ALIAS = 'spm-deployer';

const FIELD_PRIME = '21888242871839275222246405745257275088548364400416034343698204186575808495617';

// Simple Poseidon hash (for testing)
function poseidonHash(values) {
    const input = values.reduce((acc, v) => acc + BigInt(v).toString(), '');
    let hash = 0n;
    for (let i = 0; i < input.length; i++) {
        hash = (hash * 31n + BigInt(input.charCodeAt(i))) % BigInt(FIELD_PRIME);
    }
    return hash.toString();
}

// Convert to hex string of specified byte length
function toHex(value, bytes) {
    const hex = BigInt(value).toString(16);
    return hex.padStart(bytes * 2, '0');
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
                const right = j + 1 < currentLevel.length ? currentLevel[j + 1] : '0';
                nextLevel.push(this.hashPair(currentLevel[j], right));
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
            
            const nextLevel = [];
            for (let j = 0; j < currentLevel.length; j += 2) {
                const right = j + 1 < currentLevel.length ? currentLevel[j + 1] : '0';
                nextLevel.push(this.hashPair(currentLevel[j], right));
            }
            currentLevel = nextLevel;
            idx = Math.floor(idx / 2);
        }
        
        return { pathElements, pathIndices };
    }
}

// Generate mock proof (for demo)
function generateMockProof() {
    return {
        a: [
            toHex(Math.floor(Math.random() * Number.MAX_SAFE_INTEGER), 32),
            toHex(Math.floor(Math.random() * Number.MAX_SAFE_INTEGER), 32)
        ],
        b: [
            [
                toHex(Math.floor(Math.random() * Number.MAX_SAFE_INTEGER), 32),
                toHex(Math.floor(Math.random() * Number.MAX_SAFE_INTEGER), 32)
            ],
            [
                toHex(Math.floor(Math.random() * Number.MAX_SAFE_INTEGER), 32),
                toHex(Math.floor(Math.random() * Number.MAX_SAFE_INTEGER), 32)
            ]
        ],
        c: [
            toHex(Math.floor(Math.random() * Number.MAX_SAFE_INTEGER), 32),
            toHex(Math.floor(Math.random() * Number.MAX_SAFE_INTEGER), 32)
        ]
    };
}

async function submitVote(vote, voterSecret) {
    console.log('=== SPM Vote Submission ===\n');
    
    const voteNum = parseInt(vote);
    const secret = voterSecret || Math.floor(Math.random() * Number.MAX_SAFE_INTEGER).toString();
    
    console.log('Vote:', voteNum, '(' + (voteNum === 1 ? 'YES' : 'NO') + ')');
    console.log('Voter secret:', secret);
    
    // Generate nullifier
    const nullifier = computeNullifier(secret);
    console.log('Nullifier:', nullifier);
    
    // Create Merkle tree and insert
    const merkleTree = new SimpleMerkleTree(10);
    const nullifierRoot = merkleTree.insert(nullifier);
    console.log('Nullifier root:', nullifierRoot);
    
    // Generate nonce and commitment
    const nonce = Math.floor(Math.random() * Number.MAX_SAFE_INTEGER);
    const voteCommitment = computeVoteCommitment(voteNum, nonce);
    console.log('Vote commitment:', voteCommitment);
    
    // Generate proof
    const proof = generateMockProof();
    
    // Load VK
    const vk = JSON.parse(fs.readFileSync(
        path.join(__dirname, '../circuits/testdata/verification_key.json'), 'utf8'
    ));
    
    // Build the command
    const cmd = [
        'stellar contract invoke',
        `--id ${CONTRACT_ID}`,
        `--source-account ${KEY_ALIAS}`,
        `--network ${NETWORK}`,
        '--',
        'submit_vote',
        `--voter GDRXE2BQUC3AZNPVFSCEZ76NJ3TSL9NSESYFPJKGNWQYLHOQVTVEJ3E2`,
        `--nullifier 0x${toHex(nullifier, 32)}`,
        `--vote_commitment 0x${toHex(voteCommitment, 32)}`,
        `--proof_a '[${proof.a.map(p => `"0x${p}"`).join(',')}]'`,
        `--proof_b '[[${proof.b[0].map(p => `"0x${p}"`).join(',')}], [${proof.b[1].map(p => `"0x${p}"`).join(',')}]]'`,
        `--proof_c '[${proof.c.map(p => `"0x${p}"`).join(',')}]'`,
        `--vk_alpha '[${vk.vk_alpha_1.map(p => `"${p}"`).join(',')}]'`,
        `--vk_beta '${JSON.stringify(vk.vk_beta_2)}'`,
        `--vk_gamma '${JSON.stringify(vk.vk_gamma_2)}'`,
        `--vk_delta '${JSON.stringify(vk.vk_delta_2)}'`,
        `--vk_ic '${JSON.stringify(vk.IC)}'`
    ].join(' ');
    
    console.log('\nSubmitting vote...');
    
    try {
        const result = execSync(cmd, { encoding: 'utf8' });
        console.log('\n✅ Vote submitted successfully!');
        console.log('Result:', result);
        
        // Extract transaction hash
        const txMatch = result.match(/tx\/([a-f0-9]+)/);
        const txHash = txMatch ? txMatch[1] : null;
        
        // Save vote record
        const record = {
            vote: voteNum,
            voterSecret: secret,
            nullifier,
            voteCommitment,
            nullifierRoot,
            txHash,
            timestamp: new Date().toISOString(),
            explorer: txHash ? `https://stellar.expert/explorer/${NETWORK}/tx/${txHash}` : null
        };
        
        const recordPath = path.join(__dirname, `../docs/vote_record_${Date.now()}.json`);
        fs.writeFileSync(recordPath, JSON.stringify(record, null, 2));
        console.log('\nVote record saved to:', recordPath);
        
        return record;
    } catch (e) {
        console.error('\n❌ Error submitting vote:', e.message);
        if (e.stderr) console.error('stderr:', e.stderr.toString());
        throw e;
    }
}

// Run if executed directly
if (require.main === module) {
    const vote = process.argv[2] || '1';
    const secret = process.argv[3];
    
    submitVote(vote, secret)
        .then(record => {
            console.log('\n=== Complete ===');
            process.exit(0);
        })
        .catch(err => {
            console.error(err);
            process.exit(1);
        });
}

module.exports = { submitVote };
