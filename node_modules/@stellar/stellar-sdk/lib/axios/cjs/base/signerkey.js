'use strict';

var curr_generated = require('./generated/curr_generated.js');
var strkey = require('./strkey.js');

class SignerKey {
  /**
   * Decodes a StrKey address into an xdr.SignerKey instance.
   *
   * Only ED25519 public keys (G...), pre-auth transactions (T...), hashes
   * (H...), and signed payloads (P...) can be signer keys.
   *
   * @param address - a StrKey-encoded signer address
   */
  static decodeAddress(address) {
    const vb = strkey.StrKey.getVersionByteForPrefix(address);
    if (vb === void 0) {
      throw new Error(`invalid signer key type (${vb})`);
    }
    const raw = strkey.decodeCheck(vb, address);
    switch (vb) {
      case "signedPayload":
        return curr_generated.default.SignerKey.signerKeyTypeEd25519SignedPayload(
          new curr_generated.default.SignerKeyEd25519SignedPayload({
            ed25519: raw.subarray(0, 32),
            payload: raw.subarray(36, 36 + raw.readUInt32BE(32))
          })
        );
      case "ed25519PublicKey":
        return curr_generated.default.SignerKey.signerKeyTypeEd25519(raw);
      case "preAuthTx":
        return curr_generated.default.SignerKey.signerKeyTypePreAuthTx(raw);
      case "sha256Hash":
        return curr_generated.default.SignerKey.signerKeyTypeHashX(raw);
      default:
        throw new Error(`invalid signer key type (${vb})`);
    }
  }
  /**
   * Encodes a signer key into its StrKey equivalent.
   *
   * @param signerKey - the signer
   */
  static encodeSignerKey(signerKey) {
    let strkeyType;
    let raw;
    switch (signerKey.switch()) {
      case curr_generated.default.SignerKeyType.signerKeyTypeEd25519():
        strkeyType = "ed25519PublicKey";
        raw = signerKey.value();
        break;
      case curr_generated.default.SignerKeyType.signerKeyTypePreAuthTx():
        strkeyType = "preAuthTx";
        raw = signerKey.value();
        break;
      case curr_generated.default.SignerKeyType.signerKeyTypeHashX():
        strkeyType = "sha256Hash";
        raw = signerKey.value();
        break;
      case curr_generated.default.SignerKeyType.signerKeyTypeEd25519SignedPayload():
        strkeyType = "signedPayload";
        raw = signerKey.ed25519SignedPayload().toXDR("raw");
        break;
      default:
        throw new Error(`invalid SignerKey (type: ${signerKey.switch().name})`);
    }
    return strkey.encodeCheck(strkeyType, raw);
  }
}

exports.SignerKey = SignerKey;
//# sourceMappingURL=signerkey.js.map
