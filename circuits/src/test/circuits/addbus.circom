pragma circom 2.2.2;

bus Pair(levels) {
    signal a[levels];
    signal b[levels];
}

template UseBus(levels, levels2) {
    input Pair(levels) x[levels2];     // x.a[tx], x.b[tx] are inputs to the circuit
    signal output sum[levels][levels2];


    for (var tx = 0; tx < levels; tx++) {
        for (var tx2 = 0; tx2 < levels2; tx2++){
            sum[tx][tx2] <== x[tx2].a[tx] + x[tx2].b[tx];
        }


    }
}

component main = UseBus(2,3);
