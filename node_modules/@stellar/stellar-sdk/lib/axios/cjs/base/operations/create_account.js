'use strict';

var curr_generated = require('../generated/curr_generated.js');
var keypair = require('../keypair.js');
var strkey = require('../strkey.js');
var operations = require('../util/operations.js');

function createAccount(opts) {
  if (!strkey.StrKey.isValidEd25519PublicKey(opts.destination)) {
    throw new Error("destination is invalid");
  }
  if (!operations.isValidAmount(opts.startingBalance, true)) {
    throw new TypeError(operations.constructAmountRequirementsError("startingBalance"));
  }
  const createAccountOp = new curr_generated.default.CreateAccountOp({
    destination: keypair.Keypair.fromPublicKey(opts.destination).xdrAccountId(),
    startingBalance: operations.toXDRAmount(opts.startingBalance)
  });
  const opAttributes = {
    sourceAccount: null,
    body: curr_generated.default.OperationBody.createAccount(createAccountOp)
  };
  operations.setSourceAccount(opAttributes, opts);
  return new curr_generated.default.Operation(opAttributes);
}

exports.createAccount = createAccount;
//# sourceMappingURL=create_account.js.map
