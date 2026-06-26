import { Buffer } from 'buffer';
import types from '../generated/curr_generated.js';
import { Keypair } from '../keypair.js';
import { StrKey } from '../strkey.js';
import { setSourceAccount } from '../util/operations.js';

function allowTrust(opts) {
  if (!StrKey.isValidEd25519PublicKey(opts.trustor)) {
    throw new Error("trustor is invalid");
  }
  const trustor = Keypair.fromPublicKey(opts.trustor).xdrAccountId();
  let asset;
  if (opts.assetCode.length <= 4) {
    const code = Buffer.from(opts.assetCode.padEnd(4, "\0"));
    asset = types.AssetCode.assetTypeCreditAlphanum4(code);
  } else if (opts.assetCode.length <= 12) {
    const code = Buffer.from(opts.assetCode.padEnd(12, "\0"));
    asset = types.AssetCode.assetTypeCreditAlphanum12(code);
  } else {
    throw new Error("Asset code must be 12 characters at max.");
  }
  let authorize;
  if (typeof opts.authorize === "boolean") {
    if (opts.authorize) {
      authorize = types.TrustLineFlags.authorizedFlag().value;
    } else {
      authorize = 0;
    }
  } else if (opts.authorize == null) {
    throw new Error("authorize is required");
  } else {
    authorize = opts.authorize;
  }
  const allowTrustOp = new types.AllowTrustOp({
    trustor,
    asset,
    authorize
  });
  const opAttributes = {
    sourceAccount: null,
    body: types.OperationBody.allowTrust(allowTrustOp)
  };
  setSourceAccount(opAttributes, opts);
  return new types.Operation(opAttributes);
}

export { allowTrust };
//# sourceMappingURL=allow_trust.js.map
