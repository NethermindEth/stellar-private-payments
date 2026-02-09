pragma circom 2.2.2;
// Moved to the top level folder to ensure the main test is always compiled.
include "./policyTransaction.circom";

// PolicyTransaction(
//   nIns, nOuts,
//   nMembershipProofs, nNonMembershipProofs,
//   levels, smtLevels
// )
component main {public [root, publicAmount, extDataHash, inputNullifier, outputCommitment, membershipRoots, nonMembershipRoots]} = PolicyTransaction(2, 2, 1, 1, 10, 10);
