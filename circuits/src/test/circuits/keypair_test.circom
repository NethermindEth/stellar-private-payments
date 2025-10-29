pragma circom 2.2.2;

include "../../keypair.circom";

template KeypairTest() {
    signal input privateKey;
    signal input expectedPublicKey;

    component kp = Keypair();
    kp.privateKey <== privateKey;

    kp.publicKey === expectedPublicKey;
}

component main = KeypairTest();