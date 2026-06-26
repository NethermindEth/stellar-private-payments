import { Buffer } from 'buffer';
import types from '../generated/curr_generated.js';
import { Keypair } from '../keypair.js';
import { StrKey } from '../strkey.js';
import { checkUnsignedIntValue, setSourceAccount } from '../util/operations.js';

function weightCheckFunction(value, name) {
  if (value >= 0 && value <= 255) {
    return true;
  }
  throw new Error(`${name} value must be between 0 and 255`);
}
function setOptions(opts) {
  let inflationDest = null;
  if (opts.inflationDest) {
    if (!StrKey.isValidEd25519PublicKey(opts.inflationDest)) {
      throw new Error("inflationDest is invalid");
    }
    inflationDest = Keypair.fromPublicKey(opts.inflationDest).xdrAccountId();
  }
  const clearFlags = checkUnsignedIntValue("clearFlags", opts.clearFlags) ?? null;
  const setFlags = checkUnsignedIntValue("setFlags", opts.setFlags) ?? null;
  const masterWeight = checkUnsignedIntValue(
    "masterWeight",
    opts.masterWeight,
    weightCheckFunction
  ) ?? null;
  const lowThreshold = checkUnsignedIntValue(
    "lowThreshold",
    opts.lowThreshold,
    weightCheckFunction
  ) ?? null;
  const medThreshold = checkUnsignedIntValue(
    "medThreshold",
    opts.medThreshold,
    weightCheckFunction
  ) ?? null;
  const highThreshold = checkUnsignedIntValue(
    "highThreshold",
    opts.highThreshold,
    weightCheckFunction
  ) ?? null;
  if (opts.homeDomain !== void 0 && typeof opts.homeDomain !== "string") {
    throw new TypeError("homeDomain argument must be of type String");
  }
  const homeDomain = opts.homeDomain;
  let signer = null;
  if (opts.signer) {
    const weight = checkUnsignedIntValue(
      "signer.weight",
      opts.signer.weight,
      weightCheckFunction
    );
    let key;
    let setValues = 0;
    if (opts.signer.ed25519PublicKey) {
      if (!StrKey.isValidEd25519PublicKey(opts.signer.ed25519PublicKey)) {
        throw new Error("signer.ed25519PublicKey is invalid.");
      }
      const rawKey = StrKey.decodeEd25519PublicKey(
        opts.signer.ed25519PublicKey
      );
      key = types.SignerKey.signerKeyTypeEd25519(rawKey);
      setValues += 1;
    }
    if (opts.signer.preAuthTx) {
      let preAuthTx;
      if (typeof opts.signer.preAuthTx === "string") {
        preAuthTx = Buffer.from(opts.signer.preAuthTx, "hex");
      } else {
        preAuthTx = opts.signer.preAuthTx;
      }
      if (!(Buffer.isBuffer(preAuthTx) && preAuthTx.length === 32)) {
        throw new Error("signer.preAuthTx must be 32 bytes Buffer.");
      }
      key = types.SignerKey.signerKeyTypePreAuthTx(preAuthTx);
      setValues += 1;
    }
    if (opts.signer.sha256Hash) {
      let sha256Hash;
      if (typeof opts.signer.sha256Hash === "string") {
        sha256Hash = Buffer.from(opts.signer.sha256Hash, "hex");
      } else {
        sha256Hash = opts.signer.sha256Hash;
      }
      if (!(Buffer.isBuffer(sha256Hash) && sha256Hash.length === 32)) {
        throw new Error("signer.sha256Hash must be 32 bytes Buffer.");
      }
      key = types.SignerKey.signerKeyTypeHashX(sha256Hash);
      setValues += 1;
    }
    if (opts.signer.ed25519SignedPayload) {
      if (!StrKey.isValidSignedPayload(opts.signer.ed25519SignedPayload)) {
        throw new Error("signer.ed25519SignedPayload is invalid.");
      }
      const rawKey = StrKey.decodeSignedPayload(
        opts.signer.ed25519SignedPayload
      );
      const signedPayloadXdr = types.SignerKeyEd25519SignedPayload.fromXDR(rawKey);
      key = types.SignerKey.signerKeyTypeEd25519SignedPayload(signedPayloadXdr);
      setValues += 1;
    }
    if (setValues !== 1) {
      throw new Error(
        "Signer object must contain exactly one of signer.ed25519PublicKey, signer.sha256Hash, signer.preAuthTx, or signer.ed25519SignedPayload."
      );
    }
    if (weight === void 0) {
      throw new Error("signer weight is required.");
    }
    if (key === void 0) {
      throw new Error("signer key is required.");
    }
    signer = new types.Signer({ key, weight });
  }
  const setOptionsOp = new types.SetOptionsOp({
    inflationDest,
    clearFlags,
    setFlags,
    masterWeight,
    lowThreshold,
    medThreshold,
    highThreshold,
    homeDomain,
    signer
  });
  const opAttributes = {
    sourceAccount: null,
    body: types.OperationBody.setOptions(setOptionsOp)
  };
  setSourceAccount(opAttributes, opts);
  return new types.Operation(opAttributes);
}

export { setOptions };
//# sourceMappingURL=set_options.js.map
