pragma circom 2.2.2;

// Blocklist policy transaction + Global View Key.
// Base transact + ASP blocklist (non-membership) module, plus in-circuit GVK
// encryption of note secrets under the authority key D. encryptInputs toggles
// view-only (outputs only) vs traceable (inputs + outputs).

include "./policyTransaction.circom";
include "./aspNonMembership.circom";
include "./globalViewKey.circom";

template PolicyTransactionBlocklistGvk(nIns, nOuts, nNonMembershipProofs, levels, smtLevels, encryptInputs) {
    /** PUBLIC INPUTS (Global View Key) **/
    signal input D[2];
    signal input nonce;

    /** PUBLIC INPUTS (Transaction) **/
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

    /** OUTPUTS (GVK ciphertext) **/
    var nEnc = encryptInputs ? (nIns + nOuts) : nOuts;
    signal output R[nEnc][2];
    signal output c1[nEnc];
    signal output c2[nEnc];
    signal output c3[nEnc];

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

    component nonMembership = AspNonMembership(nIns, nNonMembershipProofs, smtLevels);
    for (var tx = 0; tx < nIns; tx++) {
        nonMembership.inPublicKey[tx] <== core.inPublicKey[tx];
        for (var i = 0; i < nNonMembershipProofs; i++) {
            nonMembership.nonMembershipRoots[tx][i] <== nonMembershipRoots[tx][i];
            nonMembership.nonMembershipProofs[tx][i].key <== nonMembershipProofs[tx][i].key;
            nonMembership.nonMembershipProofs[tx][i].oldKey <== nonMembershipProofs[tx][i].oldKey;
            nonMembership.nonMembershipProofs[tx][i].oldValue <== nonMembershipProofs[tx][i].oldValue;
            nonMembership.nonMembershipProofs[tx][i].isOld0 <== nonMembershipProofs[tx][i].isOld0;
            for (var j = 0; j < smtLevels; j++) {
                nonMembership.nonMembershipProofs[tx][i].siblings[j] <== nonMembershipProofs[tx][i].siblings[j];
            }
        }
    }

    // Global View Key encryption of note secrets (inputs reuse core.inPublicKey).
    component gvk = GvkNotes(nIns, nOuts, encryptInputs);
    gvk.D[0] <== D[0];
    gvk.D[1] <== D[1];
    gvk.nonce <== nonce;
    for (var k = 0; k < nIns; k++) {
        gvk.inPubkey[k] <== core.inPublicKey[k];
        gvk.inAmount[k] <== inAmount[k];
        gvk.inBlinding[k] <== inBlinding[k];
    }
    for (var k = 0; k < nOuts; k++) {
        gvk.outPubkey[k] <== outPubkey[k];
        gvk.outAmount[k] <== outAmount[k];
        gvk.outBlinding[k] <== outBlinding[k];
    }
    for (var e = 0; e < nEnc; e++) {
        R[e][0] <== gvk.R[e][0];
        R[e][1] <== gvk.R[e][1];
        c1[e] <== gvk.c1[e];
        c2[e] <== gvk.c2[e];
        c3[e] <== gvk.c3[e];
    }
}
