pragma circom 2.2.2;
// Selective disclosure for two note commitments.
include "./selectiveDisclosure.circom";

// SelectiveDisclosure(
//   levels, nNotes
// )
component main {public [roots, noteCommitments, extContextHash]} = SelectiveDisclosure(10, 2);
