pragma circom 2.2.2;
// Original circuits from https://github.com/tornadocash/tornado-nova
// Adapted and modified by Nethermind

include "./transaction.circom"; // This should be deleted once we have correct test data for compliant transactions
include "./smt/smtverifier.circom"; // This is included to force the compilation of the SMT modifications inside the main component. Will be removed later
include "./compliantTransaction.circom"; // This is included to force the compilation of the compliantTransaction file inside the main component. Will be removed later

// Transaction(levels, nIns, nOuts)
component main = Transaction(5, 2, 2);