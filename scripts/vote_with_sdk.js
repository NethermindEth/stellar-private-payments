/**
 * SPM Vote Submission using Stellar SDK
 * 
 * This script submits a vote to the SPM contract using the Stellar SDK directly,
 * bypassing CLI argument parsing issues with complex types.
 */

const { Keypair, Networks, TransactionBuilder, Operation, StrKey } = require('@stellar/stellar-sdk');
const fs = require('fs');

// Configuration
const CONTRACT_ID = 'CCQ3T4VKYXBGJQ3BXPUCKOW4CDFQ5YR4UY4N54QY4EJOWC2NEYIJJZQI';
const NETWORK = Networks.TESTNET;
const SECRET = 'SAQYS6WOJOTCR57LSBYFIEGRPLFPVNLHMGICLIC6HYMUDKK5QTH7B3QF'; // spm-deployer secret

// Load VK
const vk = JSON.parse(fs.readFileSync('./circuits/testdata/verification_key.json', 'utf8'));

// Helper: Convert snarkjs VK to contract format
function g1ToBytes(pt) {
    const x = BigInt(pt[0]).toString(16).padStart(64, '0');
    const y = BigInt(pt[1]).toString(16).padStart(64, '0');
    return x + y;
}

function g2ToBytes(pt) {
    const x1 = BigInt(pt[0][0]).toString(16).padStart(64, '0');
    const x2 = BigInt(pt[0][1]).toString(16).padStart(64, '0');
    const y1 = BigInt(pt[1][0]).toString(16).padStart(64, '0');
    const y2 = BigInt(pt[1][1]).toString(16).padStart(64, '0');
    return x1 + x2 + y1 + y2;
}

async function submitVote() {
    console.log('=== SPM Vote Submission via SDK ===\n');
    
    // Load deployer keypair
    const keypair = Keypair.fromSecret(SECRET);
    console.log('Voter:', keypair.publicKey());
    
    // Generate vote data (mock)
    const vote = 1; // YES
    const secret = Math.floor(Math.random() * Number.MAX_SAFE_INTEGER).toString();
    const nonce = Math.floor(Math.random() * Number.MAX_SAFE_INTEGER);
    
    // Simplified Poseidon-like hash
    const FIELD_PRIME = BigInt('21888242871839275222246405745257275088548364400416034343698204186575808495617');
    function simpleHash(values) {
        const input = values.reduce((acc, v) => acc + BigInt(v).toString(), '');
        let hash = 0n;
        for (let i = 0; i < input.length; i++) {
            hash = (hash * 31n + BigInt(input.charCodeAt(i))) % FIELD_PRIME;
        }
        return hash;
    }
    
    const nullifier = simpleHash([BigInt(secret)]);
    const voteCommitment = simpleHash([BigInt(vote), BigInt(nonce)]);
    
    console.log('Vote:', vote, '(YES)');
    console.log('Nullifier:', nullifier.toString());
    console.log('Vote Commitment:', voteCommitment.toString());
    
    // Mock proof values (real proofs need circom WASM)
    const mockProof = {
        a: ['0000000000000000000000000000000000000000000000000000000000000001', '0000000000000000000000000000000000000000000000000000000000000002'],
        b: ['0000000000000000000000000000000000000000000000000000000000000003', '0000000000000000000000000000000000000000000000000000000000000004', '0000000000000000000000000000000000000000000000000000000000000005', '0000000000000000000000000000000000000000000000000000000000000006'],
        c: ['0000000000000000000000000000000000000000000000000000000000000007', '0000000000000000000000000000000000000000000000000000000000000008']
    };
    
    // Convert VK to contract format
    const vkAlpha = g1ToBytes(vk.vk_alpha_1);
    const vkBeta = g2ToBytes(vk.vk_beta_2);
    const vkGamma = g2ToBytes(vk.vk_gamma_2);
    const vkDelta = g2ToBytes(vk.vk_delta_2);
    const vkIc = vk.IC.map(pt => g1ToBytes(pt));
    
    console.log('\nVK prepared');
    console.log('vk_ic count:', vkIc.length);
    
    // Build contract invoke operation
    // Note: The SDK doesn't directly support SorobanContractInvoke, we use XDR
    
    console.log('\n⚠️ SDK-based Soroban transaction building requires additional setup.');
    console.log('The stellar CLI is the recommended way to invoke contract methods.');
    console.log('\nPlease use the following CLI command:');
    
    // Generate the CLI command
    console.log('\n=== CLI Command ===');
    console.log(`stellar contract invoke \\`);
    console.log(`  --id ${CONTRACT_ID} \\`);
    console.log(`  --source-account spm-deployer \\`);
    console.log(`  --network testnet \\`);
    console.log(`  --send=yes \\`);
    console.log(`  -- submit_vote \\`);
    console.log(`  --voter ${keypair.publicKey()} \\`);
    console.log(`  --nullifier ${nullifier.toString().padStart(64, '0')} \\`);
    console.log(`  --vote_commitment ${voteCommitment.toString().padStart(64, '0')} \\`);
    console.log(`  --proof_a ${mockProof.a.join('')} \\`);
    console.log(`  --proof_b ${mockProof.b.join('')} \\`);
    console.log(`  --proof_c ${mockProof.c.join('')}`);
    
    // Save vote data for reference
    const voteData = {
        voter: keypair.publicKey(),
        vote,
        secret,
        nullifier: nullifier.toString(),
        voteCommitment: voteCommitment.toString(),
        proof: mockProof,
        timestamp: new Date().toISOString()
    };
    
    fs.writeFileSync('./docs/vote_data_' + Date.now() + '.json', JSON.stringify(voteData, null, 2));
    console.log('\nVote data saved to docs/vote_data_*.json');
    
    return voteData;
}

submitVote().catch(console.error);
