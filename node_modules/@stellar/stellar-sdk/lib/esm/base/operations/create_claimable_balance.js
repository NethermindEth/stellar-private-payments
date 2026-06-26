import types from '../generated/curr_generated.js';
import { Asset } from '../asset.js';
import { isValidAmount, constructAmountRequirementsError, toXDRAmount, setSourceAccount } from '../util/operations.js';

function createClaimableBalance(opts) {
  if (!(opts.asset instanceof Asset)) {
    throw new Error(
      "must provide an asset for create claimable balance operation"
    );
  }
  if (!isValidAmount(opts.amount)) {
    throw new TypeError(constructAmountRequirementsError("amount"));
  }
  if (!Array.isArray(opts.claimants) || opts.claimants.length === 0) {
    throw new Error("must provide at least one claimant");
  }
  const asset = opts.asset.toXDRObject();
  const amount = toXDRAmount(opts.amount);
  const claimants = opts.claimants.map((c) => c.toXDRObject());
  const createClaimableBalanceOp = new types.CreateClaimableBalanceOp({
    asset,
    amount,
    claimants
  });
  const opAttributes = {
    sourceAccount: null,
    body: types.OperationBody.createClaimableBalance(createClaimableBalanceOp)
  };
  setSourceAccount(opAttributes, opts);
  return new types.Operation(opAttributes);
}

export { createClaimableBalance };
//# sourceMappingURL=create_claimable_balance.js.map
