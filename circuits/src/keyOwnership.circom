pragma circom 2.2.2;
// Proof of ownership of a note public key for the public key registry.
include "./keypair.circom";

// Note that it simply demonstrates key ownership, not that the key is correctly derived.
// A user gains nothing from registering a valid key which is not derived using the expected derivation path.
// The encryption key for note discovery is bounded to the proof through `registrationHash`
template KeyOwnership() {
    /** PUBLIC INPUTS **/
    signal input publicKey;
    signal input registrationHash;

    /** PRIVATE INPUTS **/
    signal input privateKey;

    component keypair = Keypair();
    keypair.privateKey <== privateKey;
    publicKey === keypair.publicKey;

    // Binds registrationHash to the proof
    signal registrationHashSquare <== registrationHash * registrationHash;
}

component main {public [publicKey, registrationHash]} = KeyOwnership();
