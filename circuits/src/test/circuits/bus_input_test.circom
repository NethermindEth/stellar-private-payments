pragma circom 2.2.2;

// Witness graph fixture for the input checks in `sdk/native/src/zk/witness`.
// It has the same input shapes as the production circuits: a bus with an array
// field passed as a two-dimensional bus array (like `MembershipProof`), a
// nested bus, and a plain signal.
//
// The committed graph is regenerated from the repo root (after `make circuits`)
// with:
//
//   cargo clean -p circom-witness-rs
//   WITNESS_CPP=$PWD/circuits/src/test/circuits/bus_input_test.circom \
//   CIRCOM_LIBRARY_PATH=$PWD/circuits/src \
//   cargo run -p circuit-compiler --bin circuit-witness-graph-generator \
//     --features witness-graph -- --circuits circuits \
//     --out sdk/native/src/zk/witness/testdata

bus Leaf() {
    signal value;
    signal path[2];
}

bus Pair() {
    Leaf() left;
    Leaf() right;
}

template BusInputTest() {
    signal input a;
    input Leaf() leaves[2][1];
    input Pair() pair;
    signal output out;

    var sum = pair.left.value + pair.left.path[0] + pair.left.path[1]
        + pair.right.value + pair.right.path[0] + pair.right.path[1];
    for (var i = 0; i < 2; i++) {
        sum += leaves[i][0].value + leaves[i][0].path[0] + leaves[i][0].path[1];
    }
    out <== a * sum;
}

component main = BusInputTest();
