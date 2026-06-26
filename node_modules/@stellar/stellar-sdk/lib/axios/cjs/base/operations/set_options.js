'use strict';

var buffer = require('buffer');
var curr_generated = require('../generated/curr_generated.js');
var keypair = require('../keypair.js');
var strkey = require('../strkey.js');
var operations = require('../util/operations.js');

function weightCheckFunction(value, name) {
  if (value >= 0 && value <= 255) {
    return true;
  }
  throw new Error(`${name} value must be between 0 and 255`);
}
function setOptions(opts) {
  let inflationDest = null;
  if (opts.inflationDest) {
    if (!strkey.StrKey.isValidEd25519PublicKey(opts.inflationDest)) {
      throw new Error("inflationDest is invalid");
    }
    inflationDest = keypair.Keypair.fromPublicKey(opts.inflationDest).xdrAccountId();
  }
  const clearFlags = operations.checkUnsignedIntValue("clearFlags", opts.clearFlags) ?? null;
  const setFlags = operations.checkUnsignedIntValue("setFlags", opts.setFlags) ?? null;
  const masterWeight = operations.checkUnsignedIntValue(
    "masterWeight",
    opts.masterWeight,
    weightCheckFunction
  ) ?? null;
  const lowThreshold = operations.checkUnsignedIntValue(
    "lowThreshold",
    opts.lowThreshold,
    weightCheckFunction
  ) ?? null;
  const medThreshold = operations.checkUnsignedIntValue(
    "medThreshold",
    opts.medThreshold,
    weightCheckFunction
  ) ?? null;
  const highThreshold = operations.checkUnsignedIntValue(
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
    const weight = operations.checkUnsignedIntValue(
      "signer.weight",
      opts.signer.weight,
      weightCheckFunction
    );
    let key;
    let setValues = 0;
    if (opts.signer.ed25519PublicKey) {
      if (!strkey.StrKey.isValidEd25519PublicKey(opts.signer.ed25519PublicKey)) {
        throw new Error("signer.ed25519PublicKey is invalid.");
      }
      const rawKey = strkey.StrKey.decodeEd25519PublicKey(
        opts.signer.ed25519PublicKey
      );
      key = curr_generated.default.SignerKey.signerKeyTypeEd25519(rawKey);
      setValues += 1;
    }
    if (opts.signer.preAuthTx) {
      let preAuthTx;
      if (typeof opts.signer.preAuthTx === "string") {
        preAuthTx = buffer.Buffer.from(opts.signer.preAuthTx, "hex");
      } else {
        preAuthTx = opts.signer.preAuthTx;
      }
      if (!(buffer.Buffer.isBuffer(preAuthTx) && preAuthTx.length === 32)) {
        throw new Error("signer.preAuthTx must be 32 bytes Buffer.");
      }
      key = curr_generated.default.SignerKey.signerKeyTypePreAuthTx(preAuthTx);
      setValues += 1;
    }
    if (opts.signer.sha256Hash) {
      let sha256Hash;
      if (typeof opts.signer.sha256Hash === "string") {
        sha256Hash = buffer.Buffer.from(opts.signer.sha256Hash, "hex");
      } else {
        sha256Hash = opts.signer.sha256Hash;
      }
      if (!(buffer.Buffer.isBuffer(sha256Hash) && sha256Hash.length === 32)) {
        throw new Error("signer.sha256Hash must be 32 bytes Buffer.");
      }
      key = curr_generated.default.SignerKey.signerKeyTypeHashX(sha256Hash);
      setValues += 1;
    }
    if (opts.signer.ed25519SignedPayload) {
      if (!strkey.StrKey.isValidSignedPayload(opts.signer.ed25519SignedPayload)) {
        throw new Error("signer.ed25519SignedPayload is invalid.");
      }
      const rawKey = strkey.StrKey.decodeSignedPayload(
        opts.signer.ed25519SignedPayload
      );
      const signedPayloadXdr = curr_generated.default.SignerKeyEd25519SignedPayload.fromXDR(rawKey);
      key = curr_generated.default.SignerKey.signerKeyTypeEd25519SignedPayload(signedPayloadXdr);
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
    signer = new curr_generated.default.Signer({ key, weight });
  }
  const setOptionsOp = new curr_generated.default.SetOptionsOp({
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
    body: curr_generated.default.OperationBody.setOptions(setOptionsOp)
  };
  operations.setSourceAccount(opAttributes, opts);
  return new curr_generated.default.Operation(opAttributes);
}

exports.setOptions = setOptions;
//# sourceMappingURL=set_options.js.map
