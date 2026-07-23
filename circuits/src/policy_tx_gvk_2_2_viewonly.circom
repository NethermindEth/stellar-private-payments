pragma circom 2.2.2;
// Entry point: open policy transaction + view-only Global View Key.
// 2 inputs, 2 outputs; only the output notes are encrypted under D.
include "./policyTransactionOpenGvk.circom";

component main {public [D, nonce, root, publicAmount, extDataHash, inputNullifier, outputCommitment]} = PolicyTransactionOpenGvk(2, 2, 10, 0);
