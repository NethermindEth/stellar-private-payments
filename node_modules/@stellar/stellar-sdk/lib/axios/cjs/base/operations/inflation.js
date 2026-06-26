'use strict';

var operations = require('../util/operations.js');
var curr_generated = require('../generated/curr_generated.js');

function inflation(opts = {}) {
  const opAttributes = {
    sourceAccount: null,
    body: curr_generated.default.OperationBody.inflation()
  };
  operations.setSourceAccount(opAttributes, opts);
  return new curr_generated.default.Operation(opAttributes);
}

exports.inflation = inflation;
//# sourceMappingURL=inflation.js.map
