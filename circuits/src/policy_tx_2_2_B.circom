pragma circom 2.2.2;
// Entry point: policy_tx_2_2_B — blocklist only, no allowlist.
include "./policyTransactionBlocklist.circom";

component main {public [root, publicAmount, extDataHash, inputNullifier, outputCommitment, nonMembershipRoots]} = PolicyTransactionBlocklist(2, 2, 1, 10, 10);
