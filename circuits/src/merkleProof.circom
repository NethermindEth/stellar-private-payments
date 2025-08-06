pragma circom 2.2.0;
// Original circuits from https://github.com/tornadocash/tornado-nova
// Adapted and modified by Nethermind

include "./poseidon2/poseidon2_hash.circom";

// Local workaround
template Num2Bits(n) {
    signal input in;
    signal output out[n];
    var lc1=0;

    var e2=1;
    for (var i = 0; i<n; i++) {
        out[i] <-- (in >> i) & 1;
        out[i] * (out[i] -1 ) === 0;
        lc1 += out[i] * e2;
        e2 = e2+e2;
    }

    lc1 === in;
}
template Switcher() {
    signal input sel;
    signal input L;
    signal input R;
    signal output outL;
    signal output outR;

    signal aux;

    aux <== (R-L)*sel;    // We create aux in order to have only one multiplication
    outL <==  aux + L;
    outR <== -aux + R;
}

// Verifies that merkle proof is correct for given merkle root and a leaf
// pathIndices bits is an array of 0/1 selectors telling whether given pathElement is on the left or right side of merkle path
template MerkleProof(levels) {
    signal input leaf;
    signal input pathElements[levels];
    signal input pathIndices;
    signal output root;

    component switcher[levels];
    component hasher[levels];

    component indexBits = Num2Bits(levels);
    indexBits.in <== pathIndices;

    for (var i = 0; i < levels; i++) {
        switcher[i] = Switcher();
        switcher[i].L <== i == 0 ? leaf : hasher[i - 1].out;
        switcher[i].R <== pathElements[i];
        switcher[i].sel <== indexBits.out[i];

        hasher[i] = Poseidon2(2);
        hasher[i].inputs[0] <== switcher[i].outL;
        hasher[i].inputs[1] <== switcher[i].outR;
    }

    root <== hasher[levels - 1].out;
}