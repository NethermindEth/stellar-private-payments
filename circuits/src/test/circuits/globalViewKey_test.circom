pragma circom 2.2.2;

include "../../globalViewKey.circom";

template GlobalViewKeyEncryptionTest() {
    signal input D[2];
    signal input nonce;
    signal input idx;
    signal input pk;
    signal input amount;
    signal input blinding;

    signal input expectedR[2];
    signal input expectedC1;
    signal input expectedC2;
    signal input expectedC3;

    component enc = GlobalViewKeyEncryption();
    enc.D[0] <== D[0];
    enc.D[1] <== D[1];
    enc.nonce <== nonce;
    enc.idx <== idx;
    enc.pk <== pk;
    enc.amount <== amount;
    enc.blinding <== blinding;

    enc.R[0] === expectedR[0];
    enc.R[1] === expectedR[1];
    enc.c1 === expectedC1;
    enc.c2 === expectedC2;
    enc.c3 === expectedC3;
}

component main = GlobalViewKeyEncryptionTest();
