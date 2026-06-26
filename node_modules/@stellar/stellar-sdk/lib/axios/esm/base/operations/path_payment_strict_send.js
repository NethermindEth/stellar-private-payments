import types from '../generated/curr_generated.js';
import { decodeAddressToMuxedAccount } from '../util/decode_encode_muxed_account.js';
import { isValidAmount, constructAmountRequirementsError, toXDRAmount, setSourceAccount } from '../util/operations.js';

function pathPaymentStrictSend(opts) {
  if (!opts.sendAsset) {
    throw new Error("Must specify a send asset");
  }
  if (!isValidAmount(opts.sendAmount)) {
    throw new TypeError(constructAmountRequirementsError("sendAmount"));
  }
  if (!opts.destAsset) {
    throw new Error("Must provide a destAsset for a payment operation");
  }
  if (!isValidAmount(opts.destMin)) {
    throw new TypeError(constructAmountRequirementsError("destMin"));
  }
  const sendAsset = opts.sendAsset.toXDRObject();
  const sendAmount = toXDRAmount(opts.sendAmount);
  let destination;
  try {
    destination = decodeAddressToMuxedAccount(opts.destination);
  } catch {
    throw new Error("destination is invalid");
  }
  const destAsset = opts.destAsset.toXDRObject();
  const destMin = toXDRAmount(opts.destMin);
  const path = (opts.path ?? []).map((x) => x.toXDRObject());
  const payment = new types.PathPaymentStrictSendOp({
    sendAsset,
    sendAmount,
    destination,
    destAsset,
    destMin,
    path
  });
  const opAttributes = {
    sourceAccount: null,
    body: types.OperationBody.pathPaymentStrictSend(payment)
  };
  setSourceAccount(opAttributes, opts);
  return new types.Operation(opAttributes);
}

export { pathPaymentStrictSend };
//# sourceMappingURL=path_payment_strict_send.js.map
