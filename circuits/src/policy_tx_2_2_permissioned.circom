pragma circom 2.2.2;
// Entry point: policy_tx_2_2_permissioned — allowlist + blocklist proofs.
include "./policyTransactionPermissioned.circom";

// PolicyTransactionPermissioned(
//   nIns, nOuts,
//   nMembershipProofs, nNonMembershipProofs,
//   levels, smtLevels
// )
component main {public [root, publicAmount, extDataHash, inputNullifier, outputCommitment, membershipRoots, nonMembershipRoots]} = PolicyTransactionPermissioned(2, 2, 1, 1, 10, 10);
