pragma circom 2.2.2;

// Allowlist policy transaction: base transact + ASP allowlist module.

include "./policyTransaction.circom";
include "./aspMembership.circom";

template PolicyTransactionAllowlist(nIns, nOuts, nMembershipProofs, levels) {
    signal input root;
    signal input publicAmount;
    signal input extDataHash;
    signal input inputNullifier[nIns];
    signal input outputCommitment[nOuts];
    signal input membershipRoots[nIns][nMembershipProofs];

    input MembershipProof(levels) membershipProofs[nIns][nMembershipProofs];
    signal input inAmount[nIns];
    signal input inPrivateKey[nIns];
    signal input inBlinding[nIns];
    signal input inPathIndices[nIns];
    signal input inPathElements[nIns][levels];
    signal input outAmount[nOuts];
    signal input outPubkey[nOuts];
    signal input outBlinding[nOuts];

    component core = PolicyTransaction(nIns, nOuts, levels);
    core.root <== root;
    core.publicAmount <== publicAmount;
    core.extDataHash <== extDataHash;
    for (var tx = 0; tx < nIns; tx++) {
        core.inputNullifier[tx] <== inputNullifier[tx];
        core.inAmount[tx] <== inAmount[tx];
        core.inPrivateKey[tx] <== inPrivateKey[tx];
        core.inBlinding[tx] <== inBlinding[tx];
        core.inPathIndices[tx] <== inPathIndices[tx];
        for (var level = 0; level < levels; level++) {
            core.inPathElements[tx][level] <== inPathElements[tx][level];
        }
    }
    for (var tx = 0; tx < nOuts; tx++) {
        core.outputCommitment[tx] <== outputCommitment[tx];
        core.outAmount[tx] <== outAmount[tx];
        core.outPubkey[tx] <== outPubkey[tx];
        core.outBlinding[tx] <== outBlinding[tx];
    }

    component membership = AspMembership(nIns, nMembershipProofs, levels);
    for (var tx = 0; tx < nIns; tx++) {
        membership.inPublicKey[tx] <== core.inPublicKey[tx];
        for (var i = 0; i < nMembershipProofs; i++) {
            membership.membershipRoots[tx][i] <== membershipRoots[tx][i];
            membership.membershipProofs[tx][i].leaf <== membershipProofs[tx][i].leaf;
            membership.membershipProofs[tx][i].blinding <== membershipProofs[tx][i].blinding;
            membership.membershipProofs[tx][i].pathIndices <== membershipProofs[tx][i].pathIndices;
            for (var j = 0; j < levels; j++) {
                membership.membershipProofs[tx][i].pathElements[j] <== membershipProofs[tx][i].pathElements[j];
            }
        }
    }
}
