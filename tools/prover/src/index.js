/**
 * ZK Vote Proof Generator
 * Generates Groth16 proofs for the social prediction market vote circuit
 */

import { groth16 } from "snarkjs";
import * as poseidon from "circomlib/src/poseidon.js";

// Circuit output paths
const CIRCUIT_PATH = "../../circuits/testdata/vote";
const ZKEY_PATH = `${CIRCUIT_PATH}/vote_final.zkey`;

/**
 * Compute Poseidon hash of a value
 */
export function poseidonHash(values) {
    return poseidon(values).toString();
}

/**
 * Generate vote commitment: H(vote, nonce)
 */
export function generateVoteCommitment(vote, nonce) {
    const voteBigInt = BigInt(vote);
    const nonceBigInt = BigInt(nonce);
    return poseidonHash([voteBigInt, nonceBigInt]);
}

/**
 * Generate nullifier: unique value to prevent double-voting
 */
export function generateNullifier(voterSecret) {
    return poseidonHash([BigInt(voterSecret)]);
}

/**
 * Build Merkle tree proof (simplified - assumes empty tree for demo)
 */
export function buildMerkleProof(nullifier, pathIndices = 0, pathElements = []) {
    return {
        nullifier,
        pathIndices,
        pathElements
    };
}

/**
 * Generate ZK proof for a vote
 */
export async function generateVoteProof({
    vote,
    nonce,
    voterSecret,
    nullifierRoot
}) {
    // Generate commitment and nullifier
    const voteCommitment = generateVoteCommitment(vote, nonce);
    const nullifier = generateNullifier(voterSecret);

    // Compute nullifier leaf hash
    const nullifierLeaf = poseidonHash([BigInt(nullifier)]);

    // For demo, compute Merkle proof with zeros (empty tree)
    // In production, this would be computed from actual nullifier tree
    const pathIndices = 0;
    const pathElements = Array(10).fill(
        "21888242871839275222246405745257275088548364400416034343698204186575808495617"
    );

    // Public inputs (matches circuit)
    const publicSignals = [
        nullifierRoot,  // nullifier_root
        voteCommitment  // vote_commitment
    ];

    // Private inputs (witness)
    const input = {
        nonce: nonce.toString(),
        vote: vote.toString(),
        nullifier_path_elements: pathElements,
        nullifier_path_indices: pathIndices.toString(),
        nullifier: nullifier
    };

    // Generate proof
    console.log("Generating ZK proof...");
    console.log("Public signals:", publicSignals);
    console.log("Input:", input);

    const { proof, publicSignals: returnedSignals } = await groth16.fullProve(
        { ...input, nullifier_root: nullifierRoot, vote_commitment: voteCommitment },
        `${CIRCUIT_PATH}/vote_js/vote.wasm`,
        ZKEY_PATH
    );

    console.log("Proof generated successfully!");

    return {
        proof,
        publicSignals: returnedSignals,
        voteCommitment,
        nullifier
    };
}

/**
 * Verify a proof
 */
export async function verifyProof(proof, publicSignals) {
    const vKey = await fetch(`${CIRCUIT_PATH}/verification_key.json`)
        .then(r => r.json());
    
    return await groth16.verify(vKey, publicSignals, proof);
}

// CLI interface
if (import.meta.url === `file://${process.argv[1]}`) {
    const args = process.argv.slice(2);
    
    if (args[0] === "prove") {
        const vote = parseInt(args[1] || "1");
        const nonce = args[2] || Math.floor(Math.random() * 1e18).toString();
        const voterSecret = args[3] || Math.floor(Math.random() * 1e18).toString();
        const nullifierRoot = args[4] || "0";

        const result = await generateVoteProof({
            vote,
            nonce,
            voterSecret,
            nullifierRoot
        });

        console.log("\n=== Proof Result ===");
        console.log(JSON.stringify(result, null, 2));
    } else if (args[0] === "verify") {
        const proof = JSON.parse(args[1]);
        const signals = JSON.parse(args[2]);
        const valid = await verifyProof(proof, signals);
        console.log("Proof valid:", valid);
    } else {
        console.log(`
ZK Vote Proof Generator

Usage:
  node src/index.js prove <vote> [nonce] [voterSecret] [nullifierRoot]
  node src/index.js verify <proof> <publicSignals>

Example:
  node src/index.js prove 1 12345 67890
        `);
    }
}
