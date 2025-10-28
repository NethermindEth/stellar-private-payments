pragma circom 2.2.2;
// Original circuits from https://github.com/iden3/circomlib.git
// Adapted and modified by Nethermind

include "../poseidon2/poseidon2_hash.circom";
include "../poseidon2/poseidon2_compress.circom";

/*
    Hash1 = H(key | value | 1)
 */

template SMTHash1() {
    signal input key;
    signal input value;
    signal output out;
    
    component h = Poseidon2(2);   // Constant
    h.inputs[0] <== key;
    h.inputs[1] <== value;
    h.domainSeparation <== 1;

    out <== h.out;
}

/*
    This component is used to create the 2 nodes.

    Hash2 = H(Hl | Hr)
 */

template SMTHash2() {
    signal input L;
    signal input R;
    signal output out;

    component h = PoseidonCompress();   // Constant
    h.inputs[0] <== L;
    h.inputs[1] <== R;

    out <== h.out;
}
