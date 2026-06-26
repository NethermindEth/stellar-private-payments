import { setSourceAccount } from '../util/operations.js';
import types from '../generated/curr_generated.js';

function inflation(opts = {}) {
  const opAttributes = {
    sourceAccount: null,
    body: types.OperationBody.inflation()
  };
  setSourceAccount(opAttributes, opts);
  return new types.Operation(opAttributes);
}

export { inflation };
//# sourceMappingURL=inflation.js.map
