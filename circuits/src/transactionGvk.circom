pragma circom 2.2.2;
// Combined transaction + Global View Key circuit.
//
// Composes the base `Transaction(levels, nIns, nOuts)` with in-circuit GVK
// encryption of the note secrets under the authority key `D`, without modifying
// the transaction circuit. The same private note signals that the transaction
// constrains are fed into the encryptors:
//   - outputs: (outPubkey, outAmount, outBlinding)
//   - inputs:  (Keypair(inPrivateKey).publicKey, inAmount, inBlinding)
//
// Modes (compile-time `encryptInputs`):
//   0 - view-only:  encrypt output notes only.
//   1 - traceable:  encrypt input and output notes, letting the admin link
//                   notes across hops.
//
// Every encryptor shares the transaction `nonce`, so each gets a distinct
// `idx`: inputs 0..nIns-1, outputs nIns..nIns+nOuts-1. This holds across both
// modes, so an output note's ciphertext is identical whether or not inputs are
// encrypted.

include "./transaction.circom";
include "./globalViewKey.circom";
include "./keypair.circom";

template TransactionGvk(levels, nIns, nOuts, encryptInputs) {
    /** PUBLIC INPUTS (Global View Key) **/
    signal input D[2];
    signal input nonce;

    /** PUBLIC INPUTS (Transaction) **/
    signal input root;
    signal input publicAmount;
    signal input extDataHash;
    signal input inputNullifier[nIns];
    signal input outputCommitment[nOuts];

    /** PRIVATE INPUTS (Transaction) **/
    signal input inAmount[nIns];
    signal input inPrivateKey[nIns];
    signal input inBlinding[nIns];
    signal input inPathIndices[nIns];
    signal input inPathElements[nIns][levels];
    signal input outAmount[nOuts];
    signal input outPubkey[nOuts];
    signal input outBlinding[nOuts];

    /** OUTPUTS (ciphertext) **/
    var nEnc = encryptInputs ? (nIns + nOuts) : nOuts;
    var outBase = encryptInputs ? nIns : 0;
    signal output R[nEnc][2];
    signal output c1[nEnc];
    signal output c2[nEnc];
    signal output c3[nEnc];

    // === Base transaction (unmodified) ===
    component tx = Transaction(levels, nIns, nOuts);
    tx.root <== root;
    tx.publicAmount <== publicAmount;
    tx.extDataHash <== extDataHash;
    for (var i = 0; i < nIns; i++) {
        tx.inputNullifier[i] <== inputNullifier[i];
        tx.inAmount[i] <== inAmount[i];
        tx.inPrivateKey[i] <== inPrivateKey[i];
        tx.inBlinding[i] <== inBlinding[i];
        tx.inPathIndices[i] <== inPathIndices[i];
        for (var j = 0; j < levels; j++) {
            tx.inPathElements[i][j] <== inPathElements[i][j];
        }
    }
    for (var o = 0; o < nOuts; o++) {
        tx.outputCommitment[o] <== outputCommitment[o];
        tx.outAmount[o] <== outAmount[o];
        tx.outPubkey[o] <== outPubkey[o];
        tx.outBlinding[o] <== outBlinding[o];
    }

    // === Encrypt output notes (idx = nIns + k) ===
    component encOut[nOuts];
    for (var k = 0; k < nOuts; k++) {
        encOut[k] = GlobalViewKeyEncryption();
        encOut[k].D[0] <== D[0];
        encOut[k].D[1] <== D[1];
        encOut[k].nonce <== nonce;
        encOut[k].idx <== nIns + k;
        encOut[k].pk <== outPubkey[k];
        encOut[k].amount <== outAmount[k];
        encOut[k].blinding <== outBlinding[k];

        R[outBase + k][0] <== encOut[k].R[0];
        R[outBase + k][1] <== encOut[k].R[1];
        c1[outBase + k] <== encOut[k].c1;
        c2[outBase + k] <== encOut[k].c2;
        c3[outBase + k] <== encOut[k].c3;
    }

    // === Encrypt input notes in traceable mode (idx = k) ===
    if (encryptInputs == 1) {
        component inKeypair[nIns];
        component encIn[nIns];
        for (var k = 0; k < nIns; k++) {
            // Recompute the input public key from its private key.
            inKeypair[k] = Keypair();
            inKeypair[k].privateKey <== inPrivateKey[k];

            encIn[k] = GlobalViewKeyEncryption();
            encIn[k].D[0] <== D[0];
            encIn[k].D[1] <== D[1];
            encIn[k].nonce <== nonce;
            encIn[k].idx <== k;
            encIn[k].pk <== inKeypair[k].publicKey;
            encIn[k].amount <== inAmount[k];
            encIn[k].blinding <== inBlinding[k];

            R[k][0] <== encIn[k].R[0];
            R[k][1] <== encIn[k].R[1];
            c1[k] <== encIn[k].c1;
            c2[k] <== encIn[k].c2;
            c3[k] <== encIn[k].c3;
        }
    }
}
