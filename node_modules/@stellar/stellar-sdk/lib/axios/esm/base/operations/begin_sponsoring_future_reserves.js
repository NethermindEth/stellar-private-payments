import types from '../generated/curr_generated.js';
import { StrKey } from '../strkey.js';
import { Keypair } from '../keypair.js';
import { setSourceAccount } from '../util/operations.js';

function beginSponsoringFutureReserves(opts) {
  if (!StrKey.isValidEd25519PublicKey(opts.sponsoredId)) {
    throw new Error("sponsoredId is invalid");
  }
  const op = new types.BeginSponsoringFutureReservesOp({
    sponsoredId: Keypair.fromPublicKey(opts.sponsoredId).xdrAccountId()
  });
  const opAttributes = {
    sourceAccount: null,
    body: types.OperationBody.beginSponsoringFutureReserves(op)
  };
  setSourceAccount(opAttributes, opts);
  return new types.Operation(opAttributes);
}

export { beginSponsoringFutureReserves };
//# sourceMappingURL=begin_sponsoring_future_reserves.js.map
