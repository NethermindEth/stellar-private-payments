pragma circom 2.2.2;
// Global View Key (GVK) encryption circuit.
//
// Implements an in-circuit ECIES-style one-time-pad encryption of a note's
// secrets (pk, amount, blinding) under the pool administrator's Baby JubJub
// public key `D`. The pool admin can later decrypt the memo to audit notes.
//
// The scheme performs the ECDH key exchange and the encryption *inside* the
// circuit. Encryption is a field addition of a Poseidon2-derived keystream
//  whose security rests on ECDH hardness and the pseudo-randomness of Poseidon2.
//
// Domain separation tags
//   0x05 - ephemeral scalar `r` derivation
//   0x06 - keystream KDF
//
// Encryption is deterministic: R = H(note, D, nonce, idx)*G, so confidentiality also rests on the entropy of
// `blinding`.
// Some of the requirements that cannot be enforced in-circuit and need to be 
// done at the contract level:
//   - `nonce` must be unique per transaction; a reused nonce makes identical
//     notes produce identical (R, c) and publicly linkable.
//   - every encryption sharing a nonce must receive a distinct `idx`, including
//     across input and output note sets when composed into a transaction circuit.

include "./poseidon2/poseidon2_hash.circom";
include "./poseidon2/poseidon2_perm.circom";
include "./circomlib/circuits/babyjub.circom";
include "./circomlib/circuits/comparators.circom";
include "./circomlib/circuits/escalarmulfix.circom";
include "./circomlib/circuits/escalarmulany.circom";
include "./circomlib/circuits/bitify.circom";

// Encrypts note secrets under the administrator key `D`.
template GlobalViewKeyEncryption() {
    /** PUBLIC INPUTS **/
    signal input D[2];          // D (authority Baby JubJub public key)
    signal input nonce;         // Unique nonce
    signal input idx;           // Per-note index, so sibling notes in the same transaction never reuse a keystream.
    
    /** PRIVATE INPUTS **/
    signal input pk;            // pk of note
    signal input amount;        // amount of note
    signal input blinding;      // note blinding

    /** OUTPUTS **/
    signal output R[2]; // ephemeral public key R = r * G
    signal output c1;   // encrypted pk
    signal output c2;   // encrypted amount
    signal output c3;   // encrypted blinding

    // 1. Validate the authority public key D
    // D is a non-validated public input. Enforce it satisfies the curve equation.
    component dCheck = BabyCheck();
    dCheck.x <== D[0];
    dCheck.y <== D[1];


    // 2. Derive the ephemeral scalar r
    // Chained absorb over all context to bind r and prevent nonce/keystream reuse.
    // TODO: Support larger Poseidon2 sizes to reduce the chaining
    component h1 = Poseidon2(3);
    h1.inputs[0] <== pk;
    h1.inputs[1] <== amount;
    h1.inputs[2] <== blinding;
    h1.domainSeparation <== 0x05;

    component h2 = Poseidon2(3);
    h2.inputs[0] <== h1.out;
    h2.inputs[1] <== D[0];
    h2.inputs[2] <== D[1];
    h2.domainSeparation <== 0x05;

    component hr = Poseidon2(3);
    hr.inputs[0] <== h2.out;
    hr.inputs[1] <== nonce;
    hr.inputs[2] <== idx;
    hr.domainSeparation <== 0x05;

    signal r;
    r <== hr.out;

    // Canonical bit decomposition (constrains r < p, rejecting the r / r + p ambiguity
    component rBits = Num2Bits_strict();
    rBits.in <== r;


    // 3. Ephemeral public key R = r * G
    // BASE8 is the standard Baby JubJub generator of the prime-order subgroup.
    var BASE8[2] = [
        5299619240641551281634865583518297030282874472190772894086521144482721001553,
        16950150798460657717958625567821834550301663161624707787222815936182638968203
    ];
    component mulG = EscalarMulFix(254, BASE8);
    for (var i = 0; i < 254; i++) {
        mulG.e[i] <== rBits.out[i];
    }
    R[0] <== mulG.out[0];
    R[1] <== mulG.out[1];


    // 4. Shared secret S = r * (8 * D)  (ECDH)
    // Clear the cofactor (8 = 2^3) on the possibly-untrusted D via three
    // doublings, so S lands in the prime-order subgroup regardless of D. The
    // admin recovers S as (8*d) * R.
    component dbl1 = BabyDbl();
    dbl1.x <== D[0];
    dbl1.y <== D[1];

    component dbl2 = BabyDbl();
    dbl2.x <== dbl1.xout;
    dbl2.y <== dbl1.yout;

    component dbl3 = BabyDbl();
    dbl3.x <== dbl2.xout;
    dbl3.y <== dbl2.yout;

    // Reject low-order D. 8*D always lies in the prime-order
    // subgroup, so x(8*D) = 0 iff 8*D is the identity. In which case
    // EscalarMulAny silently outputs S = (0,1) and the keystream becomes
    // publicly computable. BabyCheck does not catch this as low-order points are still on the curve.
    component lowOrderCheck = IsZero();
    lowOrderCheck.in <== dbl3.xout;
    lowOrderCheck.out === 0;

    component mulD = EscalarMulAny(254);
    for (var i = 0; i < 254; i++) {
        mulD.e[i] <== rBits.out[i];
    }
    mulD.p[0] <== dbl3.xout;
    mulD.p[1] <== dbl3.yout;

    signal S[2];
    S[0] <== mulD.out[0];
    S[1] <== mulD.out[1];


    // 5. Keystream
    // One Poseidon2 permutation over (S.x, S.y, 0, dom) yields all three pads
    // as distinct rate lanes k_i = out[i]. out[3] is never exposed and acts as
    // the capacity. The nonce is already bound into r (and into S), so it does
    // not re-enter the KDF.
    component kdf = Permutation(4);
    kdf.inputs[0] <== S[0];
    kdf.inputs[1] <== S[1];
    kdf.inputs[2] <== 0;
    kdf.inputs[3] <== 0x06;

    // 6. Encrypt
    c1 <== pk + kdf.out[0];
    c2 <== amount + kdf.out[1];
    c3 <== blinding + kdf.out[2];
}

// Encrypts `nNotes` notes under a shared administrator key `D` and `nonce`.
// Each note receives a distinct per-note index, so keystreams never collide
// across the notes of a single transaction.
template GlobalViewKey(nNotes) {
    /** PUBLIC INPUTS **/
    signal input D[2];
    signal input nonce;

    /** PRIVATE INPUTS **/
    signal input pk[nNotes];
    signal input amount[nNotes];
    signal input blinding[nNotes];

    /** OUTPUTS **/
    signal output R[nNotes][2];
    signal output c1[nNotes];
    signal output c2[nNotes];
    signal output c3[nNotes];

    component enc[nNotes];
    for (var i = 0; i < nNotes; i++) {
        enc[i] = GlobalViewKeyEncryption();
        enc[i].D[0] <== D[0];
        enc[i].D[1] <== D[1];
        enc[i].nonce <== nonce;
        enc[i].idx <== i;
        enc[i].pk <== pk[i];
        enc[i].amount <== amount[i];
        enc[i].blinding <== blinding[i];

        R[i][0] <== enc[i].R[0];
        R[i][1] <== enc[i].R[1];
        c1[i] <== enc[i].c1;
        c2[i] <== enc[i].c2;
        c3[i] <== enc[i].c3;
    }
}

// Batch encryptor for transaction composition: encrypts nOuts output notes
// (idx = nIns + k) and, in traceable mode (encryptInputs == 1), nIns input
// notes (idx = k) under a shared D and nonce. The output index is always offset
// by nIns so an output note's ciphertext is identical whether or not inputs are
// encrypted. Callers pass note public keys directly (e.g. the policy wrappers
// feed the transaction's in-circuit input public keys), so no Keypair
// recomputation happens here.
template GvkNotes(nIns, nOuts, encryptInputs) {
    /** PUBLIC INPUTS **/
    signal input D[2];
    signal input nonce;

    /** PRIVATE INPUTS **/
    signal input inPubkey[nIns];
    signal input inAmount[nIns];
    signal input inBlinding[nIns];
    signal input outPubkey[nOuts];
    signal input outAmount[nOuts];
    signal input outBlinding[nOuts];

    /** OUTPUTS **/
    var nEnc = encryptInputs ? (nIns + nOuts) : nOuts;
    var outBase = encryptInputs ? nIns : 0;
    signal output R[nEnc][2];
    signal output c1[nEnc];
    signal output c2[nEnc];
    signal output c3[nEnc];

    // Encrypt output notes (idx = nIns + k)
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

    // Encrypt input notes in traceable mode (idx = k)
    if (encryptInputs == 1) {
        component encIn[nIns];
        for (var k = 0; k < nIns; k++) {
            encIn[k] = GlobalViewKeyEncryption();
            encIn[k].D[0] <== D[0];
            encIn[k].D[1] <== D[1];
            encIn[k].nonce <== nonce;
            encIn[k].idx <== k;
            encIn[k].pk <== inPubkey[k];
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
