import types from '../generated/curr_generated.js';
import { Keypair } from '../keypair.js';
import { StrKey } from '../strkey.js';
import { isValidAmount, constructAmountRequirementsError, toXDRAmount, setSourceAccount } from '../util/operations.js';

function createAccount(opts) {
  if (!StrKey.isValidEd25519PublicKey(opts.destination)) {
    throw new Error("destination is invalid");
  }
  if (!isValidAmount(opts.startingBalance, true)) {
    throw new TypeError(constructAmountRequirementsError("startingBalance"));
  }
  const createAccountOp = new types.CreateAccountOp({
    destination: Keypair.fromPublicKey(opts.destination).xdrAccountId(),
    startingBalance: toXDRAmount(opts.startingBalance)
  });
  const opAttributes = {
    sourceAccount: null,
    body: types.OperationBody.createAccount(createAccountOp)
  };
  setSourceAccount(opAttributes, opts);
  return new types.Operation(opAttributes);
}

export { createAccount };
//# sourceMappingURL=create_account.js.map
