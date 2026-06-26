import { Buffer } from 'buffer';
import { setSourceAccount } from '../util/operations.js';
import types from '../generated/curr_generated.js';

function manageData(opts) {
  if (!(typeof opts.name === "string" && opts.name.length <= 64)) {
    throw new Error("name must be a string, up to 64 characters");
  }
  if (typeof opts.value !== "string" && !Buffer.isBuffer(opts.value) && opts.value !== null && opts.value !== void 0) {
    throw new Error("value must be a string, Buffer or null");
  }
  let dataValue;
  if (typeof opts.value === "string") {
    dataValue = Buffer.from(opts.value);
  } else {
    dataValue = opts.value ?? null;
  }
  if (dataValue !== null && dataValue.length > 64) {
    throw new Error("value cannot be longer that 64 bytes");
  }
  const manageDataOp = new types.ManageDataOp({
    dataName: opts.name,
    dataValue
  });
  const opAttributes = {
    sourceAccount: null,
    body: types.OperationBody.manageData(manageDataOp)
  };
  setSourceAccount(opAttributes, opts);
  return new types.Operation(
    opAttributes
  );
}

export { manageData };
//# sourceMappingURL=manage_data.js.map
