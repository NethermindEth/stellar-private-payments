'use strict';

var bignumber = require('../util/bignumber.js');
var operations = require('../util/operations.js');
var curr_generated = require('../generated/curr_generated.js');

function bumpSequence(opts) {
  if (typeof opts.bumpTo !== "string") {
    throw new Error("bumpTo must be a string");
  }
  try {
    new bignumber.default(opts.bumpTo);
  } catch {
    throw new Error("bumpTo must be a stringified number");
  }
  const bumpTo = curr_generated.default.Int64.fromString(opts.bumpTo);
  const bumpSequenceOp = new curr_generated.default.BumpSequenceOp({ bumpTo });
  const opAttributes = {
    sourceAccount: null,
    body: curr_generated.default.OperationBody.bumpSequence(bumpSequenceOp)
  };
  operations.setSourceAccount(opAttributes, opts);
  return new curr_generated.default.Operation(opAttributes);
}

exports.bumpSequence = bumpSequence;
//# sourceMappingURL=bump_sequence.js.map
