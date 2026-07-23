pragma circom 2.2.2;
// Entry point: both (allowlist + blocklist) policy transaction + view-only Global View Key.
// 2 inputs, 2 outputs; only the output notes are encrypted under D.
include "./policyTransactionBothGvk.circom";

component main {public [D, nonce, root, publicAmount, extDataHash, inputNullifier, outputCommitment, membershipRoots, nonMembershipRoots]} = PolicyTransactionBothGvk(2, 2, 1, 1, 10, 10, 0);
