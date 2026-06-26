'use strict';

var curr_generated = require('../generated/curr_generated.js');
var decode_encode_muxed_account = require('../util/decode_encode_muxed_account.js');
var operations = require('../util/operations.js');

function pathPaymentStrictSend(opts) {
  if (!opts.sendAsset) {
    throw new Error("Must specify a send asset");
  }
  if (!operations.isValidAmount(opts.sendAmount)) {
    throw new TypeError(operations.constructAmountRequirementsError("sendAmount"));
  }
  if (!opts.destAsset) {
    throw new Error("Must provide a destAsset for a payment operation");
  }
  if (!operations.isValidAmount(opts.destMin)) {
    throw new TypeError(operations.constructAmountRequirementsError("destMin"));
  }
  const sendAsset = opts.sendAsset.toXDRObject();
  const sendAmount = operations.toXDRAmount(opts.sendAmount);
  let destination;
  try {
    destination = decode_encode_muxed_account.decodeAddressToMuxedAccount(opts.destination);
  } catch {
    throw new Error("destination is invalid");
  }
  const destAsset = opts.destAsset.toXDRObject();
  const destMin = operations.toXDRAmount(opts.destMin);
  const path = (opts.path ?? []).map((x) => x.toXDRObject());
  const payment = new curr_generated.default.PathPaymentStrictSendOp({
    sendAsset,
    sendAmount,
    destination,
    destAsset,
    destMin,
    path
  });
  const opAttributes = {
    sourceAccount: null,
    body: curr_generated.default.OperationBody.pathPaymentStrictSend(payment)
  };
  operations.setSourceAccount(opAttributes, opts);
  return new curr_generated.default.Operation(opAttributes);
}

exports.pathPaymentStrictSend = pathPaymentStrictSend;
//# sourceMappingURL=path_payment_strict_send.js.map
