pragma circom 2.2.2;
// Entry point: policy_tx_2_2_AB — allowlist + blocklist proofs.
include "./policyTransactionBoth.circom";

// PolicyTransactionBoth(
//   nIns, nOuts,
//   nMembershipProofs, nNonMembershipProofs,
//   levels, smtLevels
// )
component main {public [root, publicAmount, extDataHash, inputNullifier, outputCommitment, membershipRoots, nonMembershipRoots]} = PolicyTransactionBoth(2, 2, 1, 1, 10, 10);
