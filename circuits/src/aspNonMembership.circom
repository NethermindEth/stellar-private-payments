pragma circom 2.2.2;

// ASP non-membership (blocklist) policy checks.

include "./smt/smtverifier.circom";

bus NonMembershipProof(levels) {
    signal key;
    signal siblings[levels];
    signal oldKey;
    signal oldValue;
    signal isOld0;
}

template AspNonMembership(nIns, nNonMembershipProofs, smtLevels) {
    signal input inPublicKey[nIns];
    signal input nonMembershipRoots[nIns][nNonMembershipProofs];
    input NonMembershipProof(smtLevels) nonMembershipProofs[nIns][nNonMembershipProofs];

    component nonMembershipVerifiers[nIns][nNonMembershipProofs];
    component n2bs[nIns][nNonMembershipProofs];

    for (var tx = 0; tx < nIns; tx++) {
        for (var i = 0; i < nNonMembershipProofs; i++) {
            nonMembershipVerifiers[tx][i] = SMTVerifier(smtLevels);
            nonMembershipVerifiers[tx][i].enabled <== 1;
            nonMembershipVerifiers[tx][i].root <== nonMembershipRoots[tx][i];
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
            nonMembershipVerifiers[tx][i].value <== nonMembershipProofs[tx][i].key;
            nonMembershipVerifiers[tx][i].fnc <== 1;
        }
    }
}
