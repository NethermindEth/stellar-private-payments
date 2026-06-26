import { setSourceAccount } from '../util/operations.js';
import types from '../generated/curr_generated.js';

function endSponsoringFutureReserves(opts = {}) {
  const opAttributes = {
    sourceAccount: null,
    body: types.OperationBody.endSponsoringFutureReserves()
  };
  setSourceAccount(opAttributes, opts);
  return new types.Operation(opAttributes);
}

export { endSponsoringFutureReserves };
//# sourceMappingURL=end_sponsoring_future_reserves.js.map
