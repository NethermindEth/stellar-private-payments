pragma circom 2.2.2;
// Selective disclosure for three note commitments.
include "./selectiveDisclosure.circom";

// SelectiveDisclosure(
//   levels, nNotes
// )
component main {public [roots, noteCommitments, extContextHash, expectedNullifier, inAmount]} = SelectiveDisclosure(10, 3);
