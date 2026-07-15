pragma circom 2.2.2;
// Entry point: policy_tx_2_2_A — allowlist only, no blocklist.
include "./policyTransactionAllowlist.circom";

component main {public [root, publicAmount, extDataHash, inputNullifier, outputCommitment, membershipRoots]} = PolicyTransactionAllowlist(2, 2, 1, 10);
