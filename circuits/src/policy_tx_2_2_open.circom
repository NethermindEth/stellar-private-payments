pragma circom 2.2.2;
// Open policy transaction: blocklist only, no allowlist.
include "./policyTransactionOpen.circom";

component main {public [root, publicAmount, extDataHash, inputNullifier, outputCommitment, nonMembershipRoots]} = PolicyTransactionOpen(2, 2, 1, 10, 10);
