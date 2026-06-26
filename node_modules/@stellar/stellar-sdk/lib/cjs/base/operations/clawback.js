'use strict';

var curr_generated = require('../generated/curr_generated.js');
var decode_encode_muxed_account = require('../util/decode_encode_muxed_account.js');
var operations = require('../util/operations.js');

function clawback(opts) {
  if (!operations.isValidAmount(opts.amount)) {
    throw new TypeError(operations.constructAmountRequirementsError("amount"));
  }
  let from;
  try {
    from = decode_encode_muxed_account.decodeAddressToMuxedAccount(opts.from);
  } catch {
    throw new Error("from address is invalid");
  }
  const clawbackOp = new curr_generated.default.ClawbackOp({
    amount: operations.toXDRAmount(opts.amount),
    asset: opts.asset.toXDRObject(),
    from
  });
  const opAttributes = {
    sourceAccount: null,
    body: curr_generated.default.OperationBody.clawback(clawbackOp)
  };
  operations.setSourceAccount(opAttributes, opts);
  return new curr_generated.default.Operation(opAttributes);
}

exports.clawback = clawback;
//# sourceMappingURL=clawback.js.map
