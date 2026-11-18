pragma circom 2.2.2;
// Entry point: Global View Key encryption of 2 notes at idx 0 and 1.
// Not the view-only output layout, which encrypts outputs at idx 2 and 3.
// D and nonce are public; the note secrets stay private and R/c1/c2/c3 are
// public outputs.
include "../../globalViewKey.circom";

component main {public [D, nonce]} = GlobalViewKey(2);
