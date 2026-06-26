import types from '../generated/curr_generated.js';
import { decodeAddressToMuxedAccount } from '../util/decode_encode_muxed_account.js';
import { setSourceAccount } from '../util/operations.js';

function accountMerge(opts) {
  let body;
  try {
    body = types.OperationBody.accountMerge(
      decodeAddressToMuxedAccount(opts.destination)
    );
  } catch {
    throw new Error("destination is invalid");
  }
  const opAttributes = {
    sourceAccount: null,
    body
  };
  setSourceAccount(opAttributes, opts);
  return new types.Operation(opAttributes);
}

export { accountMerge };
//# sourceMappingURL=account_merge.js.map
