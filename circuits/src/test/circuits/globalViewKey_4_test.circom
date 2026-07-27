pragma circom 2.2.2;
// Entry point: traceable Global View Key encryption of 4 notes
// (2 inputs + 2 outputs). D and nonce are public; the note secrets stay private
// and R/c1/c2/c3 are public outputs.
include "../../globalViewKey.circom";

component main {public [D, nonce]} = GlobalViewKey(4);
