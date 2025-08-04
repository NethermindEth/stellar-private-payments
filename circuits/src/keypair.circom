pragma circom 2.2.0;
// Original circuits from https://github.com/tornadocash/tornado-nova
// Adapted and modified by Nethermind

// TODO:Update the poseidon implementation to Poseidon2
include "../node_modules/circomlib/circuits/poseidon.circom";

// Since we don't use signatures, the keypair can be based on a simple hash.
// Checks if the public key is the hash of the private key.
template Keypair() {
    signal input privateKey;
    signal output publicKey;

    component hasher = Poseidon(1);
    hasher.inputs[0] <== privateKey;
    publicKey <== hasher.out;
}

// Defines a signature as hash(privateKey, commitment, merklePath)
template Signature() {
    signal input privateKey;
    signal input commitment;
    signal input merklePath;
    signal output out;

    component hasher = Poseidon(3);
    hasher.inputs[0] <== privateKey;
    hasher.inputs[1] <== commitment;
    hasher.inputs[2] <== merklePath;
    out <== hasher.out;
}