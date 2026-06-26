'use strict';

var buffer = require('buffer');
var operations = require('../util/operations.js');
var curr_generated = require('../generated/curr_generated.js');

function manageData(opts) {
  if (!(typeof opts.name === "string" && opts.name.length <= 64)) {
    throw new Error("name must be a string, up to 64 characters");
  }
  if (typeof opts.value !== "string" && !buffer.Buffer.isBuffer(opts.value) && opts.value !== null && opts.value !== void 0) {
    throw new Error("value must be a string, Buffer or null");
  }
  let dataValue;
  if (typeof opts.value === "string") {
    dataValue = buffer.Buffer.from(opts.value);
  } else {
    dataValue = opts.value ?? null;
  }
  if (dataValue !== null && dataValue.length > 64) {
    throw new Error("value cannot be longer that 64 bytes");
  }
  const manageDataOp = new curr_generated.default.ManageDataOp({
    dataName: opts.name,
    dataValue
  });
  const opAttributes = {
    sourceAccount: null,
    body: curr_generated.default.OperationBody.manageData(manageDataOp)
  };
  operations.setSourceAccount(opAttributes, opts);
  return new curr_generated.default.Operation(
    opAttributes
  );
}

exports.manageData = manageData;
//# sourceMappingURL=manage_data.js.map
