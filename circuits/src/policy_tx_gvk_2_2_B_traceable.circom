pragma circom 2.2.2;
// Entry point: blocklist policy transaction + traceable Global View Key.
// 2 inputs, 2 outputs; input and output notes are encrypted under D.
include "./policyTransactionBlocklistGvk.circom";

component main {public [D, nonce, root, publicAmount, extDataHash, inputNullifier, outputCommitment, nonMembershipRoots]} = PolicyTransactionBlocklistGvk(2, 2, 1, 10, 10, 1);
