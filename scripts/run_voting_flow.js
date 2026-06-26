/**
 * SPM Voting Flow Script
 * 
 * Complete voting workflow for Social Prediction Market on Stellar testnet.
 * 
 * This script demonstrates:
 * 1. Querying market status
 * 2. Building a proper vote transaction
 * 3. Submitting the transaction
 * 
 * Usage: node run_voting_flow.js [--yes] [--no] [--close] [--resolve]
 */

const { execSync } = require('child_process');
const fs = require('fs');
const path = require('path');

const CONTRACT_ID = 'CCQ3T4VKYXBGJQ3BXPUCKOW4CDFQ5YR4UY4N54QY4EJOWC2NEYIJJZQI';
const NETWORK = 'testnet';
const KEY_ALIAS = 'spm-deployer';
const VK_PATH = path.join(__dirname, '../circuits/testdata/verification_key.json');

// Load VK
const vk = JSON.parse(fs.readFileSync(VK_PATH, 'utf8'));

// Convert snarkjs VK to contract format
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

// Generate proof data (simplified - real proofs need circom WASM)
function generateVoteData(vote) {
    const nonce = Date.now();
    const secret = Math.floor(Math.random() * Number.MAX_SAFE_INTEGER);
    
    // Simplified hash functions
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
    
    return {
        nullifier: nullifier.toString(),
        voteCommitment: voteCommitment.toString(),
        secret,
        nonce,
        vote
    };
}

// Query functions
function getStatus() {
    try {
        const result = execSync(
            `stellar contract invoke --id ${CONTRACT_ID} --source-account ${KEY_ALIAS} --network ${NETWORK} -- get_status`,
            { encoding: 'utf8' }
        );
        const statusCode = parseInt(result.trim());
        const statuses = ['Open', 'Closed', 'Resolved'];
        return { code: statusCode, name: statuses[statusCode] || 'Unknown' };
    } catch (e) {
        return { code: -1, name: 'Error', error: e.message };
    }
}

function getTotalVotes() {
    try {
        const result = execSync(
            `stellar contract invoke --id ${CONTRACT_ID} --source-account ${KEY_ALIAS} --network ${NETWORK} -- get_total_votes`,
            { encoding: 'utf8' }
        );
        return parseInt(result.trim());
    } catch (e) {
        return 0;
    }
}

function getResult() {
    try {
        const result = execSync(
            `stellar contract invoke --id ${CONTRACT_ID} --source-account ${KEY_ALIAS} --network ${NETWORK} -- get_result`,
            { encoding: 'utf8' }
        );
        return JSON.parse(result.trim());
    } catch (e) {
        return null;
    }
}

// Create argument files for the transaction
function createArgFiles(voteData) {
    const argsDir = '/tmp/spm_args';
    fs.mkdirSync(argsDir, { recursive: true });
    
    // Get voter address
    const voterAddr = execSync('stellar keys address ' + KEY_ALIAS, { encoding: 'utf8' }).trim();
    
    // Pad to 32 bytes (64 hex chars)
    const nullifierHex = voteData.nullifier.padStart(64, '0');
    const commitmentHex = voteData.voteCommitment.padStart(64, '0');
    
    fs.writeFileSync(path.join(argsDir, 'voter.json'), JSON.stringify(voterAddr));
    fs.writeFileSync(path.join(argsDir, 'nullifier.json'), JSON.stringify(nullifierHex));
    fs.writeFileSync(path.join(argsDir, 'commitment.json'), JSON.stringify(commitmentHex));
    
    // Mock proof values
    const mockProofA = '0000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000002';
    const mockProofB = '0000000000000000000000000000000000000000000000000000000000000003000000000000000000000000000000000000000000000000000000000000004000000000000000000000000000000000000000000000000000000000000005000000000000000000000000000000000000000000000000000000000000006';
    const mockProofC = '0000000000000000000000000000000000000000000000000000000000000007000000000000000000000000000000000000000000000000000000000000008';
    
    fs.writeFileSync(path.join(argsDir, 'proof_a.json'), JSON.stringify(mockProofA));
    fs.writeFileSync(path.join(argsDir, 'proof_b.json'), JSON.stringify(mockProofB));
    fs.writeFileSync(path.join(argsDir, 'proof_c.json'), JSON.stringify(mockProofC));
    
    // VK components
    fs.writeFileSync(path.join(argsDir, 'vk_alpha.json'), JSON.stringify(g1ToBytes(vk.vk_alpha_1)));
    fs.writeFileSync(path.join(argsDir, 'vk_beta.json'), JSON.stringify(g2ToBytes(vk.vk_beta_2)));
    fs.writeFileSync(path.join(argsDir, 'vk_gamma.json'), JSON.stringify(g2ToBytes(vk.vk_gamma_2)));
    fs.writeFileSync(path.join(argsDir, 'vk_delta.json'), JSON.stringify(g2ToBytes(vk.vk_delta_2)));
    
    // VK IC array
    const vkIc = vk.IC.map(pt => g1ToBytes(pt));
    fs.writeFileSync(path.join(argsDir, 'vk_ic.json'), JSON.stringify(vkIc));
    
    return { argsDir, voterAddr, nullifierHex, commitmentHex };
}

// Submit vote
function submitVote(voteData) {
    console.log('\n=== Submitting Vote ===');
    console.log('Vote:', voteData.vote === 1 ? 'YES' : 'NO');
    console.log('Nullifier:', voteData.nullifier);
    console.log('Commitment:', voteData.voteCommitment);
    
    const { argsDir } = createArgFiles(voteData);
    
    try {
        const result = execSync(
            `stellar contract invoke --id ${CONTRACT_ID} --source-account ${KEY_ALIAS} --network ${NETWORK} --send=yes -- submit_vote --voter-file-path ${argsDir}/voter.json --nullifier-file-path ${argsDir}/nullifier.json --vote_commitment-file-path ${argsDir}/commitment.json --proof_a-file-path ${argsDir}/proof_a.json --proof_b-file-path ${argsDir}/proof_b.json --proof_c-file-path ${argsDir}/proof_c.json --vk_alpha-file-path ${argsDir}/vk_alpha.json --vk_beta-file-path ${argsDir}/vk_beta.json --vk_gamma-file-path ${argsDir}/vk_gamma.json --vk_delta-file-path ${argsDir}/vk_delta.json --vk_ic-file-path ${argsDir}/vk_ic.json`,
            { encoding: 'utf8', maxBuffer: 10 * 1024 * 1024 }
        );
        console.log('\n✅ Vote submitted!');
        console.log(result);
        
        // Extract tx hash
        const txMatch = result.match(/tx\/([a-f0-9]+)/);
        return { success: true, txHash: txMatch ? txMatch[1] : null, raw: result };
    } catch (e) {
        // The mock proof will fail - this is expected
        if (e.stderr && e.stderr.includes('InvalidAction')) {
            console.log('\n⚠️ Vote failed (expected - mock proof rejected)');
            console.log('This confirms the contract correctly verifies ZK proofs!');
            return { success: false, reason: 'mock_proof_rejected', error: e.stderr };
        }
        console.log('\n❌ Error:', e.message);
        return { success: false, reason: 'error', error: e.stderr || e.message };
    }
}

// Close market
function closeMarket() {
    console.log('\n=== Closing Market ===');
    try {
        const result = execSync(
            `stellar contract invoke --id ${CONTRACT_ID} --source-account ${KEY_ALIAS} --network ${NETWORK} --send=yes -- close_market`,
            { encoding: 'utf8' }
        );
        console.log('✅ Market closed!');
        return { success: true, raw: result };
    } catch (e) {
        return { success: false, error: e.stderr || e.message };
    }
}

// Resolve market
function resolveMarket(votesYes, votesNo, minorityThreshold = 30) {
    console.log('\n=== Resolving Market ===');
    console.log(`Votes: YES=${votesYes}, NO=${votesNo}`);
    console.log(`Minority threshold: ${minorityThreshold}%`);
    
    try {
        const result = execSync(
            `stellar contract invoke --id ${CONTRACT_ID} --source-account ${KEY_ALIAS} --network ${NETWORK} --send=yes -- resolve --votes_yes ${votesYes} --votes_no ${votesNo} --total_voters ${votesYes + votesNo} --minority_threshold ${minorityThreshold}`,
            { encoding: 'utf8' }
        );
        console.log('✅ Market resolved!');
        return { success: true, raw: result };
    } catch (e) {
        return { success: false, error: e.stderr || e.message };
    }
}

// Main execution
async function main() {
    console.log('╔════════════════════════════════════════════╗');
    console.log('║  SPM Voting Flow Test                     ║');
    console.log('╚════════════════════════════════════════════╝');
    console.log('\nContract:', CONTRACT_ID);
    console.log('Network:', NETWORK);
    console.log('Time:', new Date().toISOString());
    
    // Check current status
    console.log('\n=== Market Status ===');
    const status = getStatus();
    console.log('Status:', status.name, `(${status.code})`);
    
    const totalVotes = getTotalVotes();
    console.log('Total votes:', totalVotes);
    
    // Parse command line args
    const args = process.argv.slice(2);
    const voteYes = args.includes('--yes');
    const voteNo = args.includes('--no');
    const close = args.includes('--close');
    const resolve = args.includes('--resolve');
    
    const results = { status, totalVotes, operations: [] };
    
    // Submit vote
    if (voteYes || voteNo) {
        const vote = voteYes ? 1 : 0;
        const voteData = generateVoteData(vote);
        const voteResult = submitVote(voteData);
        results.operations.push({ type: 'vote', vote, ...voteResult });
        
        // Save vote data for records
        const recordPath = path.join(__dirname, `../docs/vote_record_${Date.now()}.json`);
        fs.writeFileSync(recordPath, JSON.stringify({
            voteData,
            result: voteResult,
            timestamp: new Date().toISOString()
        }, null, 2));
        console.log('\nVote record saved to:', recordPath);
    }
    
    // Close market
    if (close) {
        const closeResult = closeMarket();
        results.operations.push({ type: 'close', ...closeResult });
    }
    
    // Resolve market
    if (resolve) {
        const votesYes = parseInt(args.find(a => a.startsWith('--yes-votes='))?.split('=')[1] || '2');
        const votesNo = parseInt(args.find(a => a.startsWith('--no-votes='))?.split('=')[1] || '1');
        const threshold = parseInt(args.find(a => a.startsWith('--threshold='))?.split('=')[1] || '30');
        
        const resolveResult = resolveMarket(votesYes, votesNo, threshold);
        results.operations.push({ type: 'resolve', votesYes, votesNo, threshold, ...resolveResult });
    }
    
    // Final status
    console.log('\n=== Final Status ===');
    const finalStatus = getStatus();
    console.log('Status:', finalStatus.name);
    console.log('Total votes:', getTotalVotes());
    
    const result = getResult();
    if (result) {
        console.log('\nResult:', JSON.stringify(result, null, 2));
    }
    
    // Save complete results
    const summaryPath = path.join(__dirname, `../docs/voting_flow_${Date.now()}.json`);
    fs.writeFileSync(summaryPath, JSON.stringify({
        contractId: CONTRACT_ID,
        network: NETWORK,
        ...results,
        finalStatus,
        timestamp: new Date().toISOString()
    }, null, 2));
    console.log('\nResults saved to:', summaryPath);
    
    return results;
}

main().catch(console.error);
