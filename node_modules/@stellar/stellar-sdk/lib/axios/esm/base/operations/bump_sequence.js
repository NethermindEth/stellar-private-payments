import BigNumber from '../util/bignumber.js';
import { setSourceAccount } from '../util/operations.js';
import types from '../generated/curr_generated.js';

function bumpSequence(opts) {
  if (typeof opts.bumpTo !== "string") {
    throw new Error("bumpTo must be a string");
  }
  try {
    new BigNumber(opts.bumpTo);
  } catch {
    throw new Error("bumpTo must be a stringified number");
  }
  const bumpTo = types.Int64.fromString(opts.bumpTo);
  const bumpSequenceOp = new types.BumpSequenceOp({ bumpTo });
  const opAttributes = {
    sourceAccount: null,
    body: types.OperationBody.bumpSequence(bumpSequenceOp)
  };
  setSourceAccount(opAttributes, opts);
  return new types.Operation(opAttributes);
}

export { bumpSequence };
//# sourceMappingURL=bump_sequence.js.map
