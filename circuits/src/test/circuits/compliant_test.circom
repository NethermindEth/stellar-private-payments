pragma circom 2.2.2;

include "../../compliantTransaction.circom";

// CompliantTransaction(
//   nIns, nOuts,
//   nMembershipProofs, nNonMembershipProofs,
//   levels, smtLevels
// )
component main {public [root, publicAmount, extDataHash, inputNullifier, outputCommitment, membershipRoots, nonMembershipRoots]} = CompliantTransaction(2, 2, 1, 1, 5, 5);
