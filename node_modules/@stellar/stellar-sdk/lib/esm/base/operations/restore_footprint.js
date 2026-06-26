import { setSourceAccount } from '../util/operations.js';
import types from '../generated/curr_generated.js';

function restoreFootprint(opts = {}) {
  const op = new types.RestoreFootprintOp({
    ext: new types.ExtensionPoint(0)
  });
  const opAttributes = {
    sourceAccount: null,
    body: types.OperationBody.restoreFootprint(op)
  };
  setSourceAccount(opAttributes, opts);
  return new types.Operation(opAttributes);
}

export { restoreFootprint };
//# sourceMappingURL=restore_footprint.js.map
