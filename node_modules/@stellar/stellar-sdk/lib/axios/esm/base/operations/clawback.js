import types from '../generated/curr_generated.js';
import { decodeAddressToMuxedAccount } from '../util/decode_encode_muxed_account.js';
import { isValidAmount, constructAmountRequirementsError, toXDRAmount, setSourceAccount } from '../util/operations.js';

function clawback(opts) {
  if (!isValidAmount(opts.amount)) {
    throw new TypeError(constructAmountRequirementsError("amount"));
  }
  let from;
  try {
    from = decodeAddressToMuxedAccount(opts.from);
  } catch {
    throw new Error("from address is invalid");
  }
  const clawbackOp = new types.ClawbackOp({
    amount: toXDRAmount(opts.amount),
    asset: opts.asset.toXDRObject(),
    from
  });
  const opAttributes = {
    sourceAccount: null,
    body: types.OperationBody.clawback(clawbackOp)
  };
  setSourceAccount(opAttributes, opts);
  return new types.Operation(opAttributes);
}

export { clawback };
//# sourceMappingURL=clawback.js.map
