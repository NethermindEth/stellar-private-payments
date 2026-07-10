pragma circom 2.2.2;

// ASP membership (allowlist) policy checks.

include "./merkleProof.circom";
include "./poseidon2/poseidon2_hash.circom";

bus MembershipProof(levels) {
    signal leaf;
    signal blinding;
    signal pathElements[levels];
    signal pathIndices;
}

template AspMembership(nIns, nMembershipProofs, levels) {
    signal input inPublicKey[nIns];
    signal input membershipRoots[nIns][nMembershipProofs];
    input MembershipProof(levels) membershipProofs[nIns][nMembershipProofs];

    component policyMembershipHasher[nIns][nMembershipProofs];
    component membershipVerifiers[nIns][nMembershipProofs];

    for (var tx = 0; tx < nIns; tx++) {
        for (var i = 0; i < nMembershipProofs; i++) {
            membershipVerifiers[tx][i] = MerkleProof(levels);
            policyMembershipHasher[tx][i] = Poseidon2(2);
            policyMembershipHasher[tx][i].inputs[0] <== inPublicKey[tx];
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
