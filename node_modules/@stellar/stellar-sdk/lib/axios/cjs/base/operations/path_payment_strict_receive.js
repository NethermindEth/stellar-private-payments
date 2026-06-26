'use strict';

var curr_generated = require('../generated/curr_generated.js');
var decode_encode_muxed_account = require('../util/decode_encode_muxed_account.js');
var operations = require('../util/operations.js');

function pathPaymentStrictReceive(opts) {
  if (!opts.sendAsset) {
    throw new Error("Must specify a send asset");
  }
  if (!operations.isValidAmount(opts.sendMax)) {
    throw new TypeError(operations.constructAmountRequirementsError("sendMax"));
  }
  if (!opts.destAsset) {
    throw new Error("Must provide a destAsset for a payment operation");
  }
  if (!operations.isValidAmount(opts.destAmount)) {
    throw new TypeError(operations.constructAmountRequirementsError("destAmount"));
  }
  let destination;
  try {
    destination = decode_encode_muxed_account.decodeAddressToMuxedAccount(opts.destination);
  } catch {
    throw new Error("destination is invalid");
  }
  const path = opts.path ? opts.path : [];
  const paymentOp = new curr_generated.default.PathPaymentStrictReceiveOp({
    sendAsset: opts.sendAsset.toXDRObject(),
    sendMax: operations.toXDRAmount(opts.sendMax),
    destination,
    destAsset: opts.destAsset.toXDRObject(),
    destAmount: operations.toXDRAmount(opts.destAmount),
    path: path.map((x) => x.toXDRObject())
  });
  const opAttributes = {
    sourceAccount: null,
    body: curr_generated.default.OperationBody.pathPaymentStrictReceive(paymentOp)
  };
  operations.setSourceAccount(opAttributes, opts);
  return new curr_generated.default.Operation(opAttributes);
}

exports.pathPaymentStrictReceive = pathPaymentStrictReceive;
//# sourceMappingURL=path_payment_strict_receive.js.map
