pragma circom 2.2.2;
// Original circuits from https://github.com/iden3/circomlib.git
// Adapted and modified by Nethermind

include "../poseidon2/poseidon2_hash.circom";
include "../poseidon2/poseidon2_compress.circom";

// Hash1 = H(key | value | 1)
// Used for leaf nodes
template SMTHash1() {
    signal input key;
    signal input value;
    signal output out;
    
    component h = Poseidon2(2);   // Poseidon2 hash for 2 inputs. We set the domain separation to 1.
    h.inputs[0] <== key;
    h.inputs[1] <== value;
    h.domainSeparation <== 1;

    out <== h.out;
}

// Hash2 = H(left | right)
// Used for internal nodes
template SMTHash2() {
    signal input L;
    signal input R;
    signal output out;

    component h = PoseidonCompress();   // Constant
    h.inputs[0] <== L;
    h.inputs[1] <== R;

    out <== h.out;
}
