pragma circom 2.2.2;
// Entry point: policy_tx_2_2_open — unrestricted pool transact (no ASP proofs).
include "./policyTransactionOpen.circom";

component main {public [root, publicAmount, extDataHash, inputNullifier, outputCommitment]} = PolicyTransactionOpen(2, 2, 10);
