pragma circom 2.2.2;
// Entry point: allowlist policy transaction + view-only Global View Key.
// 2 inputs, 2 outputs; only the output notes are encrypted under D.
include "./policyTransactionAllowlistGvk.circom";

component main {public [D, nonce, root, publicAmount, extDataHash, inputNullifier, outputCommitment, membershipRoots]} = PolicyTransactionAllowlistGvk(2, 2, 1, 10, 0);
