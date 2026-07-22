pragma circom 2.2.2;
// Entry point: view-only Global View Key encryption of 2 output notes.
// D and nonce are public; the note secrets stay private and R/c1/c2/c3 are
// public outputs.
include "./globalViewKey.circom";

component main {public [D, nonce]} = GlobalViewKey(2);
