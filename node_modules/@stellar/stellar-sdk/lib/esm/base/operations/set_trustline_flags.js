import types from '../generated/curr_generated.js';
import { Keypair } from '../keypair.js';
import { setSourceAccount } from '../util/operations.js';

function setTrustLineFlags(opts) {
  if (typeof opts.flags !== "object" || Object.keys(opts.flags).length === 0) {
    throw new Error("opts.flags must be a map of boolean flags to modify");
  }
  const mapping = {
    authorized: types.TrustLineFlags.authorizedFlag(),
    authorizedToMaintainLiabilities: types.TrustLineFlags.authorizedToMaintainLiabilitiesFlag(),
    clawbackEnabled: types.TrustLineFlags.trustlineClawbackEnabledFlag()
  };
  let clearFlag = 0;
  let setFlag = 0;
  Object.keys(opts.flags).forEach((flagName) => {
    if (!Object.prototype.hasOwnProperty.call(mapping, flagName)) {
      throw new Error(`unsupported flag name specified: ${flagName}`);
    }
    const flagValue = opts.flags[flagName];
    const bit = mapping[flagName];
    if (!bit) {
      throw new Error(`Invalid flag name: ${flagName}`);
    }
    if (typeof flagValue !== "boolean" && typeof flagValue !== "undefined") {
      throw new TypeError(
        `opts.flags.${flagName} must be a boolean (got ${typeof flagValue})`
      );
    }
    if (flagValue === true) {
      setFlag |= bit.value;
    } else if (flagValue === false) {
      clearFlag |= bit.value;
    }
  });
  const trustor = Keypair.fromPublicKey(opts.trustor).xdrAccountId();
  const asset = opts.asset.toXDRObject();
  const opAttributes = {
    sourceAccount: null,
    body: types.OperationBody.setTrustLineFlags(
      new types.SetTrustLineFlagsOp({
        trustor,
        asset,
        clearFlags: clearFlag,
        setFlags: setFlag
      })
    )
  };
  setSourceAccount(opAttributes, opts);
  return new types.Operation(opAttributes);
}

export { setTrustLineFlags };
//# sourceMappingURL=set_trustline_flags.js.map
