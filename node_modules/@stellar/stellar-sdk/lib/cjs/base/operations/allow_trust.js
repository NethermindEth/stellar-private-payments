'use strict';

var buffer = require('buffer');
var curr_generated = require('../generated/curr_generated.js');
var keypair = require('../keypair.js');
var strkey = require('../strkey.js');
var operations = require('../util/operations.js');

function allowTrust(opts) {
  if (!strkey.StrKey.isValidEd25519PublicKey(opts.trustor)) {
    throw new Error("trustor is invalid");
  }
  const trustor = keypair.Keypair.fromPublicKey(opts.trustor).xdrAccountId();
  let asset;
  if (opts.assetCode.length <= 4) {
    const code = buffer.Buffer.from(opts.assetCode.padEnd(4, "\0"));
    asset = curr_generated.default.AssetCode.assetTypeCreditAlphanum4(code);
  } else if (opts.assetCode.length <= 12) {
    const code = buffer.Buffer.from(opts.assetCode.padEnd(12, "\0"));
    asset = curr_generated.default.AssetCode.assetTypeCreditAlphanum12(code);
  } else {
    throw new Error("Asset code must be 12 characters at max.");
  }
  let authorize;
  if (typeof opts.authorize === "boolean") {
    if (opts.authorize) {
      authorize = curr_generated.default.TrustLineFlags.authorizedFlag().value;
    } else {
      authorize = 0;
    }
  } else if (opts.authorize == null) {
    throw new Error("authorize is required");
  } else {
    authorize = opts.authorize;
  }
  const allowTrustOp = new curr_generated.default.AllowTrustOp({
    trustor,
    asset,
    authorize
  });
  const opAttributes = {
    sourceAccount: null,
    body: curr_generated.default.OperationBody.allowTrust(allowTrustOp)
  };
  operations.setSourceAccount(opAttributes, opts);
  return new curr_generated.default.Operation(opAttributes);
}

exports.allowTrust = allowTrust;
//# sourceMappingURL=allow_trust.js.map
