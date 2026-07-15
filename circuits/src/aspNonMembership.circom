pragma circom 2.2.2;

// ASP non-membership (blocklist) policy checks.

include "./smt/smtverifier.circom";

// Non-Membership Proof
bus NonMembershipProof(levels) {
    signal key;                     // Key to be checked in the Sparse merkle Tree
    signal siblings[levels];        // List of sibling nodes
    signal oldKey;                  // Old key to be checked in the Sparse merkle Tree (might be 0)
    signal oldValue;                // Old value to be checked in the Sparse merkle Tree (might be 0)
    signal isOld0;                  // Boolean indicator to signal if the oldKey should be used or not (0 for not using it)
}

// * nIns: Number of inputs
// * nNonMembershipProofs: Number of non-membership proofs for each input
// * smtLevels: Number of levels in the Sparse Merkle Tree
template AspNonMembership(nIns, nNonMembershipProofs, smtLevels) {
    signal input inPublicKey[nIns];
    signal input nonMembershipRoots[nIns][nNonMembershipProofs];
    input NonMembershipProof(smtLevels) nonMembershipProofs[nIns][nNonMembershipProofs];

    component nonMembershipVerifiers[nIns][nNonMembershipProofs];
    component n2bs[nIns][nNonMembershipProofs];

    for (var tx = 0; tx < nIns; tx++) {
        // Verify non-membership proofs using SMT
        for (var i = 0; i < nNonMembershipProofs; i++) {
            nonMembershipVerifiers[tx][i] = SMTVerifier(smtLevels);
            nonMembershipVerifiers[tx][i].enabled <== 1; // Always enabled
            nonMembershipVerifiers[tx][i].root <== nonMembershipRoots[tx][i];

            // Check that the leaf is under the same public key as the valid transaction tree
            nonMembershipProofs[tx][i].key === inPublicKey[tx];

            for (var j = 0; j < smtLevels; j++) {
                nonMembershipVerifiers[tx][i].siblings[j] <== nonMembershipProofs[tx][i].siblings[j];
            }

            nonMembershipVerifiers[tx][i].oldKey <== nonMembershipProofs[tx][i].oldKey;
            nonMembershipVerifiers[tx][i].oldValue <== nonMembershipProofs[tx][i].oldValue;

            n2bs[tx][i] = Num2Bits(1);
            n2bs[tx][i].in <== nonMembershipProofs[tx][i].isOld0;

            nonMembershipVerifiers[tx][i].isOld0 <== n2bs[tx][i].out[0];
            nonMembershipVerifiers[tx][i].key <== nonMembershipProofs[tx][i].key;
            nonMembershipVerifiers[tx][i].value <== nonMembershipProofs[tx][i].key; // We do not actually use value. We only need to check that the key is not present in the tree.
            nonMembershipVerifiers[tx][i].fnc <== 1; // Always 1 to verify NON-inclusion exclusively
        }
    }
}
