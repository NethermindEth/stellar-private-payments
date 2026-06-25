pragma circom 2.0.0;

include "circomlib/circuits/poseidon.circom";
include "./merkleproof.circom";

// Main component: proves valid vote with non-reuse
template BinaryVote(levels) {
    // Public inputs
    signal input nullifier_root;
    signal input vote_commitment;

    // Private inputs (witness)
    signal input nonce;
    signal input vote;
    signal input nullifier_path_elements[levels];
    signal input nullifier_path_indices;
    signal input nullifier;

    // Constraints on vote value (must be 0 or 1)
    vote * (vote - 1) === 0;

    // 1. Verify vote commitment matches H(vote, nonce)
    component commitmentHasher = Poseidon(2);
    commitmentHasher.inputs[0] <== vote;
    commitmentHasher.inputs[1] <== nonce;
    commitmentHasher.out === vote_commitment;

    // 2. Verify nullifier is in the nullifier Merkle tree
    component nullifierLeaf = Poseidon(1);
    nullifierLeaf.inputs[0] <== nullifier;

    component nullifierProof = MerkleProof(levels);
    nullifierProof.leaf <== nullifierLeaf.out;
    nullifierProof.pathIndices <== nullifier_path_indices;
    for (var i = 0; i < levels; i++) {
        nullifierProof.pathElements[i] <== nullifier_path_elements[i];
    }
    
    // Assert computed root matches expected root
    nullifierProof.root === nullifier_root;
}

// Entry point - using 10 levels for the nullifier tree
component main {public [nullifier_root, vote_commitment]} = BinaryVote(10);
