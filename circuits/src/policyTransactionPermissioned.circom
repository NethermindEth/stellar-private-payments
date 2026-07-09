pragma circom 2.2.2;

// Permissioned policy transaction: open transaction core + ASP allowlist proofs.

include "./policyTransactionOpen.circom";

bus MembershipProof(levels) {
    signal leaf;
    signal blinding;
    signal pathElements[levels];
    signal pathIndices;
}

// Permissioned = PolicyTransactionOpen + membership proofs per input slot.
template PolicyTransactionPermissioned(nIns, nOuts, nMembershipProofs, nNonMembershipProofs, levels, smtLevels) {
    signal input root;
    signal input publicAmount;
    signal input extDataHash;
    signal input inputNullifier[nIns];
    signal input outputCommitment[nOuts];
    signal input membershipRoots[nIns][nMembershipProofs];
    signal input nonMembershipRoots[nIns][nNonMembershipProofs];

    input MembershipProof(levels) membershipProofs[nIns][nMembershipProofs];
    input NonMembershipProof(smtLevels) nonMembershipProofs[nIns][nNonMembershipProofs];
    signal input inAmount[nIns];
    signal input inPrivateKey[nIns];
    signal input inBlinding[nIns];
    signal input inPathIndices[nIns];
    signal input inPathElements[nIns][levels];
    signal input outAmount[nOuts];
    signal input outPubkey[nOuts];
    signal input outBlinding[nOuts];

    component open = PolicyTransactionOpen(nIns, nOuts, nNonMembershipProofs, levels, smtLevels);
    open.root <== root;
    open.publicAmount <== publicAmount;
    open.extDataHash <== extDataHash;
    for (var tx = 0; tx < nIns; tx++) {
        open.inputNullifier[tx] <== inputNullifier[tx];
        open.inAmount[tx] <== inAmount[tx];
        open.inPrivateKey[tx] <== inPrivateKey[tx];
        open.inBlinding[tx] <== inBlinding[tx];
        open.inPathIndices[tx] <== inPathIndices[tx];
        for (var level = 0; level < levels; level++) {
            open.inPathElements[tx][level] <== inPathElements[tx][level];
        }
        for (var i = 0; i < nNonMembershipProofs; i++) {
            open.nonMembershipRoots[tx][i] <== nonMembershipRoots[tx][i];
            open.nonMembershipProofs[tx][i].key <== nonMembershipProofs[tx][i].key;
            open.nonMembershipProofs[tx][i].oldKey <== nonMembershipProofs[tx][i].oldKey;
            open.nonMembershipProofs[tx][i].oldValue <== nonMembershipProofs[tx][i].oldValue;
            open.nonMembershipProofs[tx][i].isOld0 <== nonMembershipProofs[tx][i].isOld0;
            for (var j = 0; j < smtLevels; j++) {
                open.nonMembershipProofs[tx][i].siblings[j] <== nonMembershipProofs[tx][i].siblings[j];
            }
        }
    }
    for (var tx = 0; tx < nOuts; tx++) {
        open.outputCommitment[tx] <== outputCommitment[tx];
        open.outAmount[tx] <== outAmount[tx];
        open.outPubkey[tx] <== outPubkey[tx];
        open.outBlinding[tx] <== outBlinding[tx];
    }

    component inKeypair[nIns];
    component policyMembershipHasher[nIns][nMembershipProofs];
    component membershipVerifiers[nIns][nMembershipProofs];

    for (var tx = 0; tx < nIns; tx++) {
        inKeypair[tx] = Keypair();
        inKeypair[tx].privateKey <== inPrivateKey[tx];

        for (var i = 0; i < nMembershipProofs; i++) {
            membershipVerifiers[tx][i] = MerkleProof(levels);
            policyMembershipHasher[tx][i] = Poseidon2(2);
            policyMembershipHasher[tx][i].inputs[0] <== inKeypair[tx].publicKey;
            policyMembershipHasher[tx][i].inputs[1] <== membershipProofs[tx][i].blinding;
            policyMembershipHasher[tx][i].domainSeparation <== 0x01;
            membershipProofs[tx][i].leaf === policyMembershipHasher[tx][i].out;

            membershipVerifiers[tx][i].leaf <== membershipProofs[tx][i].leaf;
            membershipVerifiers[tx][i].pathIndices <== membershipProofs[tx][i].pathIndices;
            for (var j = 0; j < levels; j++) {
                membershipVerifiers[tx][i].pathElements[j] <== membershipProofs[tx][i].pathElements[j];
            }
            membershipVerifiers[tx][i].root === membershipRoots[tx][i];
        }
    }
}
