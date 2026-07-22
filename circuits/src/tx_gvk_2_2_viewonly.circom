pragma circom 2.2.2;
// Entry point: transaction + view-only Global View Key encryption.
// 2 inputs, 2 outputs; only the output notes are encrypted under D.
include "./transactionGvk.circom";

component main {public [D, nonce, root, publicAmount, extDataHash, inputNullifier, outputCommitment]} = TransactionGvk(10, 2, 2, 0);
