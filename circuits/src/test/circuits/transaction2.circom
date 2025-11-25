pragma circom 2.2.2;

include "../../transaction.circom";

// Transaction(levels, nIns, nOuts)
component main = Transaction(5, 2, 2);