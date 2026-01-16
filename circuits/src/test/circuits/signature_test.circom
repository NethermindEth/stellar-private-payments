
pragma circom 2.2.2;

include "../../keypair.circom";

template SignatureTest() {
    signal input privateKey;
    signal input commitment;
    signal input merklePath;
    signal input expectedSig;

    component s = Signature();
    s.privateKey <== privateKey;
    s.commitment <== commitment;
    s.merklePath <== merklePath;

    s.out === expectedSig;
}

component main = SignatureTest();
