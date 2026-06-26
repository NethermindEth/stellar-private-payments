'use strict';

var operations = require('../util/operations.js');
var curr_generated = require('../generated/curr_generated.js');

function restoreFootprint(opts = {}) {
  const op = new curr_generated.default.RestoreFootprintOp({
    ext: new curr_generated.default.ExtensionPoint(0)
  });
  const opAttributes = {
    sourceAccount: null,
    body: curr_generated.default.OperationBody.restoreFootprint(op)
  };
  operations.setSourceAccount(opAttributes, opts);
  return new curr_generated.default.Operation(opAttributes);
}

exports.restoreFootprint = restoreFootprint;
//# sourceMappingURL=restore_footprint.js.map
