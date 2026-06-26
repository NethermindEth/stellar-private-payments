'use strict';

var operations = require('../util/operations.js');
var curr_generated = require('../generated/curr_generated.js');

function endSponsoringFutureReserves(opts = {}) {
  const opAttributes = {
    sourceAccount: null,
    body: curr_generated.default.OperationBody.endSponsoringFutureReserves()
  };
  operations.setSourceAccount(opAttributes, opts);
  return new curr_generated.default.Operation(opAttributes);
}

exports.endSponsoringFutureReserves = endSponsoringFutureReserves;
//# sourceMappingURL=end_sponsoring_future_reserves.js.map
