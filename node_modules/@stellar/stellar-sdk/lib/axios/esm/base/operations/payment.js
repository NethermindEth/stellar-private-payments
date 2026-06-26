import types from '../generated/curr_generated.js';
import { decodeAddressToMuxedAccount } from '../util/decode_encode_muxed_account.js';
import { isValidAmount, constructAmountRequirementsError, toXDRAmount, setSourceAccount } from '../util/operations.js';

function payment(opts) {
  if (!opts.asset) {
    throw new Error("Must provide an asset for a payment operation");
  }
  if (!isValidAmount(opts.amount)) {
    throw new TypeError(constructAmountRequirementsError("amount"));
  }
  let destination;
  try {
    destination = decodeAddressToMuxedAccount(opts.destination);
  } catch {
    throw new Error("destination is invalid");
  }
  const paymentOp = new types.PaymentOp({
    destination,
    asset: opts.asset.toXDRObject(),
    amount: toXDRAmount(opts.amount)
  });
  const opAttributes = {
    sourceAccount: null,
    body: types.OperationBody.payment(paymentOp)
  };
  setSourceAccount(opAttributes, opts);
  return new types.Operation(opAttributes);
}

export { payment };
//# sourceMappingURL=payment.js.map
