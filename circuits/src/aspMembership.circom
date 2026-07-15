pragma circom 2.2.2;

// ASP membership (allowlist) policy checks.

include "./merkleProof.circom";
include "./poseidon2/poseidon2_hash.circom";

// Membership Proof
bus MembershipProof(levels) {
    signal leaf;                    // Leaf commitment
    signal blinding;                // Blinding factor used in the leaf hash
    signal pathElements[levels];    // Merkle path sibling elements required to go from leaf to root
    signal pathIndices;             // Indices off the path that signal if the node is a left or right child
}

// * nIns: Number of inputs
// * nMembershipProofs: Number of membership proofs for each input
// * levels: Number of levels in the Merkle tree
template AspMembership(nIns, nMembershipProofs, levels) {
    signal input inPublicKey[nIns];
    signal input membershipRoots[nIns][nMembershipProofs];
    input MembershipProof(levels) membershipProofs[nIns][nMembershipProofs];

    component policyMembershipHasher[nIns][nMembershipProofs];
    component membershipVerifiers[nIns][nMembershipProofs];

    for (var tx = 0; tx < nIns; tx++) {
        // Verify membership proofs
        for (var i = 0; i < nMembershipProofs; i++) {
            membershipVerifiers[tx][i] = MerkleProof(levels);
            // Check leaf structure and that the leaf is under the same public key as the valid transaction tree
            policyMembershipHasher[tx][i] = Poseidon2(2);
            policyMembershipHasher[tx][i].inputs[0] <== inPublicKey[tx];
            policyMembershipHasher[tx][i].inputs[1] <== membershipProofs[tx][i].blinding;
            policyMembershipHasher[tx][i].domainSeparation <== 0x01; // Leaf commitment for membership proof
            membershipProofs[tx][i].leaf === policyMembershipHasher[tx][i].out;

            // Verify Membership
            membershipVerifiers[tx][i].leaf <== membershipProofs[tx][i].leaf;
            membershipVerifiers[tx][i].pathIndices <== membershipProofs[tx][i].pathIndices;
            for (var j = 0; j < levels; j++) {
                membershipVerifiers[tx][i].pathElements[j] <== membershipProofs[tx][i].pathElements[j];
            }

            // Verify that the computed root matches the provided root
            membershipVerifiers[tx][i].root === membershipRoots[tx][i];
        }
    }
}
