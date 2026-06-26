'use strict';

var curr_generated = require('../generated/curr_generated.js');
var keypair = require('../keypair.js');
var operations = require('../util/operations.js');

function setTrustLineFlags(opts) {
  if (typeof opts.flags !== "object" || Object.keys(opts.flags).length === 0) {
    throw new Error("opts.flags must be a map of boolean flags to modify");
  }
  const mapping = {
    authorized: curr_generated.default.TrustLineFlags.authorizedFlag(),
    authorizedToMaintainLiabilities: curr_generated.default.TrustLineFlags.authorizedToMaintainLiabilitiesFlag(),
    clawbackEnabled: curr_generated.default.TrustLineFlags.trustlineClawbackEnabledFlag()
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
  const trustor = keypair.Keypair.fromPublicKey(opts.trustor).xdrAccountId();
  const asset = opts.asset.toXDRObject();
  const opAttributes = {
    sourceAccount: null,
    body: curr_generated.default.OperationBody.setTrustLineFlags(
      new curr_generated.default.SetTrustLineFlagsOp({
        trustor,
        asset,
        clearFlags: clearFlag,
        setFlags: setFlag
      })
    )
  };
  operations.setSourceAccount(opAttributes, opts);
  return new curr_generated.default.Operation(opAttributes);
}

exports.setTrustLineFlags = setTrustLineFlags;
//# sourceMappingURL=set_trustline_flags.js.map
