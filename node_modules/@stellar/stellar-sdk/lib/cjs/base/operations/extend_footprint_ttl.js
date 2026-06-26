'use strict';

var operations = require('../util/operations.js');
var curr_generated = require('../generated/curr_generated.js');

function extendFootprintTtl(opts) {
  if ((opts.extendTo ?? -1) <= 0) {
    throw new RangeError("extendTo has to be positive");
  }
  const extendFootprintOp = new curr_generated.default.ExtendFootprintTtlOp({
    ext: new curr_generated.default.ExtensionPoint(0),
    extendTo: opts.extendTo
  });
  const opAttributes = {
    sourceAccount: null,
    body: curr_generated.default.OperationBody.extendFootprintTtl(extendFootprintOp)
  };
  operations.setSourceAccount(opAttributes, opts);
  return new curr_generated.default.Operation(opAttributes);
}

exports.extendFootprintTtl = extendFootprintTtl;
//# sourceMappingURL=extend_footprint_ttl.js.map
