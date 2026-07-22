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
//   0x06 - keystream KDF lanes

include "./poseidon2/poseidon2_hash.circom";
include "./circomlib/circuits/babyjub.circom";
include "./circomlib/circuits/escalarmulfix.circom";
include "./circomlib/circuits/escalarmulany.circom";
include "./circomlib/circuits/bitify.circom";

// Encrypts note secrets under the administrator key `D`.
template GlobalViewKeyEncryption() {
    /** PUBLIC INPUTS **/
    signal input D[2];          // D (authority Baby JubJub public key)
    signal input nonce;         // Unique nonce
    signal input idx;           // Note iper-note index, so sibling notes in the same transaction never reuse a keystream.
    
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
    // TODO: Support larger Poseidon2 sizes to reduce the chaning
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
    // One field element per lane: k_i = H(S.x, S.y, i). The nonce is already
    // bound into r (and into S), so it does not re-enter the KDF.
    component kdf1 = Poseidon2(3);
    kdf1.inputs[0] <== S[0];
    kdf1.inputs[1] <== S[1];
    kdf1.inputs[2] <== 1;
    kdf1.domainSeparation <== 0x06;

    component kdf2 = Poseidon2(3);
    kdf2.inputs[0] <== S[0];
    kdf2.inputs[1] <== S[1];
    kdf2.inputs[2] <== 2;
    kdf2.domainSeparation <== 0x06;

    component kdf3 = Poseidon2(3);
    kdf3.inputs[0] <== S[0];
    kdf3.inputs[1] <== S[1];
    kdf3.inputs[2] <== 3;
    kdf3.domainSeparation <== 0x06;

    // 6. Encrypt (additive stream cipher)
    c1 <== pk + kdf1.out;
    c2 <== amount + kdf2.out;
    c3 <== blinding + kdf3.out;
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
