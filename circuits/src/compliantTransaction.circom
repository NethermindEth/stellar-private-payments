pragma circom 2.2.2;

// Compliant Transaction Circuit
// Extends the base transaction with membership and non-membership proof verification for association sets support

include "./transaction.circom";
include "./smt/smtverifier.circom";
include "./merkleProof.circom";

// Bus definitions
bus MembershipProof(levels) {
    signal leaf;
    signal pathElements[levels];
    signal pathIndices;
}

bus NonMembershipProof(levels) {
    signal key;
    signal value;
    signal siblings[levels];
    signal oldKey;
    signal oldValue;
    signal isOld0;
}

/*
Compliant Transaction Structure:
- Extends the base transaction functionality by importing transaction.circom
- Adds membership proof verification for association sets
- Adds non-membership proof verification for exclusion sets
- Uses sparse merkle trees for non-membership proofs
*/

template CompliantTransaction(levels, nIns, nOuts, zeroLeaf, nMembershipProofs, nNonMembershipProofs, smtLevels) {
    /** PUBLIC INPUTS **/
    // Base transaction inputs
    signal input root;
    signal input publicAmount;
    signal input extDataHash;
    // Compliance inputs
    input MembershipProof(levels) membershipProofs[nMembershipProofs]; 
    input NonMembershipProof(smtLevels) nonMembershipProofs[nNonMembershipProofs];
    signal input membershipRoots[nMembershipProofs];
    signal input nonMembershipRoots[nNonMembershipProofs];
    
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
    
   
    // Define base transaction
    component baseTransaction = Transaction(levels, nIns, nOuts, zeroLeaf);
    
    // Connect all base transaction inputs
    baseTransaction.root <== root;
    baseTransaction.publicAmount <== publicAmount;
    baseTransaction.extDataHash <== extDataHash;
    
    // Connect transaction inputs
    for (var i = 0; i < nIns; i++) {
        baseTransaction.inputNullifier[i] <== inputNullifier[i];
        baseTransaction.inAmount[i] <== inAmount[i];
        baseTransaction.inPrivateKey[i] <== inPrivateKey[i];
        baseTransaction.inBlinding[i] <== inBlinding[i];
        baseTransaction.inPathIndices[i] <== inPathIndices[i];
        for (var j = 0; j < levels; j++) {
            baseTransaction.inPathElements[i][j] <== inPathElements[i][j];
        }
    }
    
    // Also connect output commitments
    for (var i = 0; i < nOuts; i++) {
        baseTransaction.outputCommitment[i] <== outputCommitment[i];
        baseTransaction.outAmount[i] <== outAmount[i];
        baseTransaction.outPubkey[i] <== outPubkey[i];
        baseTransaction.outBlinding[i] <== outBlinding[i];
    }
    
    // TODO: Right now proofs are verified, but not tied together
    // TODO: We need to make sure the compliance proofs are for the same public keys.
    
    // Compliance checks
    // 1. Verify membership proofs
    component membershipVerifiers[nMembershipProofs];
    for (var i = 0; i < nMembershipProofs; i++) {
        membershipVerifiers[i] = MerkleProof(levels);
        membershipVerifiers[i].leaf <== membershipProofs[i].leaf;
        membershipVerifiers[i].pathIndices <== membershipProofs[i].pathIndices;
        
        for (var j = 0; j < levels ; j++) { 
            membershipVerifiers[i].pathElements[j] <== membershipProofs[i].pathElements[j];
        }
        
        // Verify that the computed root matches the provided root
        membershipVerifiers[i].root === membershipRoots[i];
    }

    // 2. Verify non-membership proofs using SMT
    component nonMembershipVerifiers[nNonMembershipProofs];
    for (var i = 0; i < nNonMembershipProofs; i++) {
        nonMembershipVerifiers[i] = SMTVerifier(smtLevels);
        nonMembershipVerifiers[i].enabled <== 1; // Always enabled
        nonMembershipVerifiers[i].root <== nonMembershipRoots[i];
        
        for (var j = 0; j < smtLevels; j++) {
            nonMembershipVerifiers[i].siblings[j] <== nonMembershipProofs[i].siblings[j];
        }
        
        nonMembershipVerifiers[i].oldKey <== nonMembershipProofs[i].oldKey; 
        nonMembershipVerifiers[i].oldValue <== nonMembershipProofs[i].oldValue; 
        nonMembershipVerifiers[i].isOld0 <== nonMembershipProofs[i].isOld0; 
        nonMembershipVerifiers[i].key <== nonMembershipProofs[i].key; 
        nonMembershipVerifiers[i].value <== nonMembershipProofs[i].value; 
        nonMembershipVerifiers[i].fnc <== 1; // Always 1 to verify NON-inclusion exclusively 
    }
}