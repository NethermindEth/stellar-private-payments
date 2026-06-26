'use strict';

var curr_generated = require('../generated/curr_generated.js');
var strkey = require('../strkey.js');
var keypair = require('../keypair.js');
var operations = require('../util/operations.js');

function beginSponsoringFutureReserves(opts) {
  if (!strkey.StrKey.isValidEd25519PublicKey(opts.sponsoredId)) {
    throw new Error("sponsoredId is invalid");
  }
  const op = new curr_generated.default.BeginSponsoringFutureReservesOp({
    sponsoredId: keypair.Keypair.fromPublicKey(opts.sponsoredId).xdrAccountId()
  });
  const opAttributes = {
    sourceAccount: null,
    body: curr_generated.default.OperationBody.beginSponsoringFutureReserves(op)
  };
  operations.setSourceAccount(opAttributes, opts);
  return new curr_generated.default.Operation(opAttributes);
}

exports.beginSponsoringFutureReserves = beginSponsoringFutureReserves;
//# sourceMappingURL=begin_sponsoring_future_reserves.js.map
