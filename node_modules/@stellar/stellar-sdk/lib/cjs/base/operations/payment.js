'use strict';

var curr_generated = require('../generated/curr_generated.js');
var decode_encode_muxed_account = require('../util/decode_encode_muxed_account.js');
var operations = require('../util/operations.js');

function payment(opts) {
  if (!opts.asset) {
    throw new Error("Must provide an asset for a payment operation");
  }
  if (!operations.isValidAmount(opts.amount)) {
    throw new TypeError(operations.constructAmountRequirementsError("amount"));
  }
  let destination;
  try {
    destination = decode_encode_muxed_account.decodeAddressToMuxedAccount(opts.destination);
  } catch {
    throw new Error("destination is invalid");
  }
  const paymentOp = new curr_generated.default.PaymentOp({
    destination,
    asset: opts.asset.toXDRObject(),
    amount: operations.toXDRAmount(opts.amount)
  });
  const opAttributes = {
    sourceAccount: null,
    body: curr_generated.default.OperationBody.payment(paymentOp)
  };
  operations.setSourceAccount(opAttributes, opts);
  return new curr_generated.default.Operation(opAttributes);
}

exports.payment = payment;
//# sourceMappingURL=payment.js.map
