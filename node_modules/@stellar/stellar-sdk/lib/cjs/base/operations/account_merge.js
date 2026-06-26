'use strict';

var curr_generated = require('../generated/curr_generated.js');
var decode_encode_muxed_account = require('../util/decode_encode_muxed_account.js');
var operations = require('../util/operations.js');

function accountMerge(opts) {
  let body;
  try {
    body = curr_generated.default.OperationBody.accountMerge(
      decode_encode_muxed_account.decodeAddressToMuxedAccount(opts.destination)
    );
  } catch {
    throw new Error("destination is invalid");
  }
  const opAttributes = {
    sourceAccount: null,
    body
  };
  operations.setSourceAccount(opAttributes, opts);
  return new curr_generated.default.Operation(opAttributes);
}

exports.accountMerge = accountMerge;
//# sourceMappingURL=account_merge.js.map
