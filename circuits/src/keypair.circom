pragma circom 2.2.2;
// Original circuits from https://github.com/tornadocash/tornado-nova
// Adapted and modified by Nethermind

include "./poseidon2/poseidon2_hash.circom";

// Since we don't use signatures, the keypair can be based on a simple hash.
// Checks if the public key is the hash of the private key.
template Keypair() {
    signal input privateKey;
    signal output publicKey;

    component hasher = Poseidon2(1);
    hasher.inputs[0] <== privateKey;
    publicKey <== hasher.out;
}

// Defines a signature as hash(privateKey, commitment, merklePath)
template Signature() {
    signal input privateKey;
    signal input commitment;
    signal input merklePath;
    signal output out;

    component hasher = Poseidon2(3);
    hasher.inputs[0] <== privateKey;
    hasher.inputs[1] <== commitment;
    hasher.inputs[2] <== merklePath;
    out <== hasher.out;
}