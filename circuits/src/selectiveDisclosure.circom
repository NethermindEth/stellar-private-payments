pragma circom 2.2.2;

// Selective Disclosure Circuit
include "./merkleProof.circom";
include "./poseidon2/poseidon2_hash.circom";
include "./keypair.circom";

// Allows a user to demonstrate ownership of a note commitment without revealing its secrets
// * levels: Number of levels in the Merkle tree that holds the note commitments
// * nNotes: Number of notes to prove ownership of.
// Right now we allow proving ownership of multiple notes on different roots BUT for the same external context:
// - Purpose
// - Authority 
// - Pool address
// So that you can prove multiple notes 
template SelectiveDisclosure(levels, nNotes) {
    /** PUBLIC INPUTS **/
    signal input roots[nNotes];
    signal input noteCommitments[nNotes];
    signal input extContextHash;
 
    
    /** PRIVATE INPUTS **/
    signal input inAmount[nNotes];
    signal input inPrivateKey[nNotes];
    signal input inBlinding[nNotes];
    signal input inPathIndices[nNotes];
    signal input inPathElements[nNotes][levels];
    
    // Components
    component inKeypair[nNotes];
    component inCommitmentHasher[nNotes];
    component inTree[nNotes];
    
    for (var ni = 0; ni < nNotes; ni++) {
        // Verify that the sender actually owns the inputs
        // He knows the secret keys and the blinding factors.
        inKeypair[ni] = Keypair();
        inKeypair[ni].privateKey <== inPrivateKey[ni];
        
        // Computes the leaf commitment as hash(amount, publicKey, blinding)
        inCommitmentHasher[ni] = Poseidon2(3);
        inCommitmentHasher[ni].inputs[0] <== inAmount[ni];
        inCommitmentHasher[ni].inputs[1] <== inKeypair[ni].publicKey;
        inCommitmentHasher[ni].inputs[2] <== inBlinding[ni];
        inCommitmentHasher[ni].domainSeparation <== 0x01; // Leaf commitment
        
        // Ensures it matches the claimed note
        noteCommitments[ni] === inCommitmentHasher[ni].out;
        
        // Verifies the merkle proofs
        inTree[ni] = MerkleProof(levels);
        inTree[ni].leaf <== inCommitmentHasher[ni].out;
        inTree[ni].pathIndices <== inPathIndices[ni];
        for (var i = 0; i < levels; i++) {
            inTree[ni].pathElements[i] <== inPathElements[ni][i];
        }
        // Ensure root matches the expected value
        roots[ni] === inTree[ni].root;
    }
    // Safety constraint to bind external context 
    signal extContextSquare <== extContextHash * extContextHash;   
}
