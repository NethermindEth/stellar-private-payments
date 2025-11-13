pragma circom 2.2.2;

// Compliant Transaction Circuit
// Extends the base transaction with membership and non-membership proof verification for association sets support

include "./smt/smtverifier.circom";
include "./merkleProof.circom";
include "./poseidon2/poseidon2_hash.circom";
include "./keypair.circom";

// Bus definitions
bus MembershipProof(levels) {
    signal leaf;
    signal pk;
    signal blinding;
    signal pathElements[levels];
    signal pathIndices;
}

bus NonMembershipProof(levels) {
    signal key;
    signal siblings[levels];
    signal oldKey;
    signal oldValue;
    signal isOld0;
}

template CompliantTransaction(nIns, nOuts, nMembershipProofs, nNonMembershipProofs, levels, smtLevels) {
    /** PUBLIC INPUTS **/
    signal input root;
    signal input publicAmount;
    signal input extDataHash;
    
    // Compliance inputs
    input MembershipProof(levels) membershipProofs[nIns][nMembershipProofs]; 
    input NonMembershipProof(smtLevels) nonMembershipProofs[nIns][nNonMembershipProofs];
    signal input membershipRoots[nIns][nMembershipProofs];
    signal input nonMembershipRoots[nIns][nNonMembershipProofs];

    
    /** PRIVATE INPUTS **/
    // Transaction input data
    signal input inputNullifier[nIns];
    signal input inAmount[nIns];
    signal input inPrivateKey[nIns];
    signal input inBlinding[nIns];
    signal input inPathIndices[nIns];
    signal input inPathElements[nIns][levels];
    // Transaction output data
    signal input outputCommitment[nOuts];
    signal input outAmount[nOuts];
    signal input outPubkey[nOuts];
    signal input outBlinding[nOuts];
    
    // Components and variables definition
    component inKeypair[nIns];
    component inSignature[nIns];
    component inCommitmentHasher[nIns];
    component inNullifierHasher[nIns];
    component inTree[nIns];
    component inCheckRoot[nIns];
    component complianceMembershipHasher[nIns][nMembershipProofs];
    component membershipVerifiers[nIns][nMembershipProofs];
    component nonMembershipVerifiers[nIns][nNonMembershipProofs];
    component n2bs[nIns][nNonMembershipProofs];
    
    var sumIns = 0;
    
    // verify correctness of transaction inputs
    for (var tx = 0; tx < nIns; tx++) {
        // Verify that the sender actually owns the inputs
        // He knows the secret keys and the blinding factors.
        inKeypair[tx] = Keypair();
        inKeypair[tx].privateKey <== inPrivateKey[tx];

        // Computes the leaf commitment as hash(amount, publicKey, blinding)
        inCommitmentHasher[tx] = Poseidon2(3);
        inCommitmentHasher[tx].inputs[0] <== inAmount[tx];
        inCommitmentHasher[tx].inputs[1] <== inKeypair[tx].publicKey;
        inCommitmentHasher[tx].inputs[2] <== inBlinding[tx];

        // Computes the signature as hash(privateKey, commitment, merklePath)
        inSignature[tx] = Signature();
        inSignature[tx].privateKey <== inPrivateKey[tx];
        inSignature[tx].commitment <== inCommitmentHasher[tx].out;
        inSignature[tx].merklePath <== inPathIndices[tx];

        // Computes the Nullifier as h(commitment, merklePath, signature)
        // Checks it matches the input nullifier
        inNullifierHasher[tx] = Poseidon2(3);
        inNullifierHasher[tx].inputs[0] <== inCommitmentHasher[tx].out;
        inNullifierHasher[tx].inputs[1] <== inPathIndices[tx];
        inNullifierHasher[tx].inputs[2] <== inSignature[tx].out;
        inNullifierHasher[tx].out === inputNullifier[tx];

        // Verifies the merkle proofs
        inTree[tx] = MerkleProof(levels);
        inTree[tx].leaf <== inCommitmentHasher[tx].out;
        inTree[tx].pathIndices <== inPathIndices[tx];
        for (var i = 0; i < levels; i++) {
            inTree[tx].pathElements[i] <== inPathElements[tx][i];
        }

        // Check merkle proof only if amount is non-zero
        inCheckRoot[tx] = ForceEqualIfEnabled();
        inCheckRoot[tx].in[0] <== root;
        inCheckRoot[tx].in[1] <== inTree[tx].root;
        inCheckRoot[tx].enabled <== inAmount[tx];
        
        // We don't need to range check input amounts, since all inputs are valid UTXOs that
        // were already checked as outputs in the previous transaction (or zero amount UTXOs that don't
        // need to be checked either).
        
        // Compliance checks
        // 1. Verify membership proofs
        for (var i = 0; i < nMembershipProofs; i++) {
            membershipVerifiers[tx][i] = MerkleProof(levels);
            // Check leaf structure and that the leaf is under the same public key as the valid transaction tree
            complianceMembershipHasher[tx][i] = Poseidon2(2);
            complianceMembershipHasher[tx][i].inputs[0] <== membershipProofs[tx][i].pk;
            complianceMembershipHasher[tx][i].inputs[1] <== membershipProofs[tx][i].blinding;
            membershipProofs[tx][i].leaf === complianceMembershipHasher[tx][i].out;
            membershipProofs[tx][i].pk === inKeypair[tx].publicKey;
            
            // Verify Membership
            membershipVerifiers[tx][i].leaf <== membershipProofs[tx][i].leaf;
            membershipVerifiers[tx][i].pathIndices <== membershipProofs[tx][i].pathIndices;       
            for (var j = 0; j < levels ; j++) { 
                membershipVerifiers[tx][i].pathElements[j] <== membershipProofs[tx][i].pathElements[j];
            }
            
            // Verify that the computed root matches the provided root
            membershipVerifiers[tx][i].root === membershipRoots[tx][i];
        }
    
        // 2. Verify non-membership proofs using SMT
        for (var i = 0; i < nNonMembershipProofs; i++) {
            nonMembershipVerifiers[tx][i] = SMTVerifier(smtLevels);
            nonMembershipVerifiers[tx][i].enabled <== 1; // Always enabled
            nonMembershipVerifiers[tx][i].root <== nonMembershipRoots[tx][i];
            
            // Check that the leaf is under the same public key as the valid transaction tree
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
            nonMembershipVerifiers[tx][i].fnc <== 1; // Always 1 to verify NON-inclusion exclusively 
        }
   
            
        sumIns += inAmount[tx];
    }

    component outCommitmentHasher[nOuts];
    component outAmountCheck[nOuts];
    var sumOuts = 0;

    // Verify correctness of transaction outputs
    for (var tx = 0; tx < nOuts; tx++) {
        outCommitmentHasher[tx] = Poseidon2(3);
        outCommitmentHasher[tx].inputs[0] <== outAmount[tx];
        outCommitmentHasher[tx].inputs[1] <== outPubkey[tx];
        outCommitmentHasher[tx].inputs[2] <== outBlinding[tx];
        outCommitmentHasher[tx].out === outputCommitment[tx];

        // Check that amount fits into 248 bits to prevent overflow
        outAmountCheck[tx] = Num2Bits(248);
        outAmountCheck[tx].in <== outAmount[tx];

        sumOuts += outAmount[tx];
    }

    // check that there are no same nullifiers among all inputs
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

    // verify amount invariant
    sumIns + publicAmount === sumOuts;

    // optional safety constraint to make sure extDataHash cannot be changed
    signal extDataSquare <== extDataHash * extDataHash;
       
}