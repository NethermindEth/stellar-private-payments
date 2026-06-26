import types from '../generated/curr_generated.js';
import { decodeAddressToMuxedAccount } from '../util/decode_encode_muxed_account.js';
import { isValidAmount, constructAmountRequirementsError, toXDRAmount, setSourceAccount } from '../util/operations.js';

function pathPaymentStrictReceive(opts) {
  if (!opts.sendAsset) {
    throw new Error("Must specify a send asset");
  }
  if (!isValidAmount(opts.sendMax)) {
    throw new TypeError(constructAmountRequirementsError("sendMax"));
  }
  if (!opts.destAsset) {
    throw new Error("Must provide a destAsset for a payment operation");
  }
  if (!isValidAmount(opts.destAmount)) {
    throw new TypeError(constructAmountRequirementsError("destAmount"));
  }
  let destination;
  try {
    destination = decodeAddressToMuxedAccount(opts.destination);
  } catch {
    throw new Error("destination is invalid");
  }
  const path = opts.path ? opts.path : [];
  const paymentOp = new types.PathPaymentStrictReceiveOp({
    sendAsset: opts.sendAsset.toXDRObject(),
    sendMax: toXDRAmount(opts.sendMax),
    destination,
    destAsset: opts.destAsset.toXDRObject(),
    destAmount: toXDRAmount(opts.destAmount),
    path: path.map((x) => x.toXDRObject())
  });
  const opAttributes = {
    sourceAccount: null,
    body: types.OperationBody.pathPaymentStrictReceive(paymentOp)
  };
  setSourceAccount(opAttributes, opts);
  return new types.Operation(opAttributes);
}

export { pathPaymentStrictReceive };
//# sourceMappingURL=path_payment_strict_receive.js.map
