pragma circom 2.2.2;

// Open policy transaction: blocklist only, no allowlist.

include "./smt/smtverifier.circom";
include "./merkleProof.circom";
include "./poseidon2/poseidon2_hash.circom";
include "./keypair.circom";

bus NonMembershipProof(levels) {
    signal key;
    signal siblings[levels];
    signal oldKey;
    signal oldValue;
    signal isOld0;
}

template PolicyTransactionOpen(nIns, nOuts, nNonMembershipProofs, levels, smtLevels) {
    signal input root;
    signal input publicAmount;
    signal input extDataHash;
    signal input inputNullifier[nIns];
    signal input outputCommitment[nOuts];
    signal input nonMembershipRoots[nIns][nNonMembershipProofs];

    input NonMembershipProof(smtLevels) nonMembershipProofs[nIns][nNonMembershipProofs];
    signal input inAmount[nIns];
    signal input inPrivateKey[nIns];
    signal input inBlinding[nIns];
    signal input inPathIndices[nIns];
    signal input inPathElements[nIns][levels];
    signal input outAmount[nOuts];
    signal input outPubkey[nOuts];
    signal input outBlinding[nOuts];

    component inKeypair[nIns];
    component inSignature[nIns];
    component inCommitmentHasher[nIns];
    component inNullifierHasher[nIns];
    component inTree[nIns];
    component inCheckRoot[nIns];
    component nonMembershipVerifiers[nIns][nNonMembershipProofs];
    component n2bs[nIns][nNonMembershipProofs];

    var sumIns = 0;

    for (var tx = 0; tx < nIns; tx++) {
        inKeypair[tx] = Keypair();
        inKeypair[tx].privateKey <== inPrivateKey[tx];

        inCommitmentHasher[tx] = Poseidon2(3);
        inCommitmentHasher[tx].inputs[0] <== inAmount[tx];
        inCommitmentHasher[tx].inputs[1] <== inKeypair[tx].publicKey;
        inCommitmentHasher[tx].inputs[2] <== inBlinding[tx];
        inCommitmentHasher[tx].domainSeparation <== 0x01;

        inSignature[tx] = Signature();
        inSignature[tx].privateKey <== inPrivateKey[tx];
        inSignature[tx].commitment <== inCommitmentHasher[tx].out;
        inSignature[tx].merklePath <== inPathIndices[tx];

        inNullifierHasher[tx] = Poseidon2(3);
        inNullifierHasher[tx].inputs[0] <== inCommitmentHasher[tx].out;
        inNullifierHasher[tx].inputs[1] <== inPathIndices[tx];
        inNullifierHasher[tx].inputs[2] <== inSignature[tx].out;
        inNullifierHasher[tx].domainSeparation <== 0x02;

        inNullifierHasher[tx].out === inputNullifier[tx];

        inTree[tx] = MerkleProof(levels);
        inTree[tx].leaf <== inCommitmentHasher[tx].out;
        inTree[tx].pathIndices <== inPathIndices[tx];
        for (var i = 0; i < levels; i++) {
            inTree[tx].pathElements[i] <== inPathElements[tx][i];
        }

        inCheckRoot[tx] = ForceEqualIfEnabled();
        inCheckRoot[tx].in[0] <== root;
        inCheckRoot[tx].in[1] <== inTree[tx].root;
        inCheckRoot[tx].enabled <== inAmount[tx];

        for (var i = 0; i < nNonMembershipProofs; i++) {
            nonMembershipVerifiers[tx][i] = SMTVerifier(smtLevels);
            nonMembershipVerifiers[tx][i].enabled <== 1;
            nonMembershipVerifiers[tx][i].root <== nonMembershipRoots[tx][i];
            nonMembershipProofs[tx][i].key === inKeypair[tx].publicKey;
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

        sumIns += inAmount[tx];
    }

    component outCommitmentHasher[nOuts];
    component outAmountCheck[nOuts];
    var sumOuts = 0;

    for (var tx = 0; tx < nOuts; tx++) {
        outCommitmentHasher[tx] = Poseidon2(3);
        outCommitmentHasher[tx].inputs[0] <== outAmount[tx];
        outCommitmentHasher[tx].inputs[1] <== outPubkey[tx];
        outCommitmentHasher[tx].inputs[2] <== outBlinding[tx];
        outCommitmentHasher[tx].domainSeparation <== 0x01;
        outCommitmentHasher[tx].out === outputCommitment[tx];

        outAmountCheck[tx] = Num2Bits(248);
        outAmountCheck[tx].in <== outAmount[tx];

        sumOuts += outAmount[tx];
    }

    component sameNullifiers[nIns * (nIns - 1) / 2];
    var index = 0;
    for (var i = 0; i < nIns - 1; i++) {
        for (var j = i + 1; j < nIns; j++) {
            sameNullifiers[index] = IsEqual();
            sameNullifiers[index].in[0] <== inputNullifier[i];
            sameNullifiers[index].in[1] <== inputNullifier[j];
            sameNullifiers[index].out === 0;
            index++;
        }
    }

    sumIns + publicAmount === sumOuts;
    signal extDataSquare <== extDataHash * extDataHash;
}
