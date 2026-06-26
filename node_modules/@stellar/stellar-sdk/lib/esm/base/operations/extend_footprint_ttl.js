import { setSourceAccount } from '../util/operations.js';
import types from '../generated/curr_generated.js';

function extendFootprintTtl(opts) {
  if ((opts.extendTo ?? -1) <= 0) {
    throw new RangeError("extendTo has to be positive");
  }
  const extendFootprintOp = new types.ExtendFootprintTtlOp({
    ext: new types.ExtensionPoint(0),
    extendTo: opts.extendTo
  });
  const opAttributes = {
    sourceAccount: null,
    body: types.OperationBody.extendFootprintTtl(extendFootprintOp)
  };
  setSourceAccount(opAttributes, opts);
  return new types.Operation(opAttributes);
}

export { extendFootprintTtl };
//# sourceMappingURL=extend_footprint_ttl.js.map
