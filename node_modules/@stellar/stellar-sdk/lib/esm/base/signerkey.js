import types from './generated/curr_generated.js';
import { StrKey, decodeCheck, encodeCheck } from './strkey.js';

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
    const vb = StrKey.getVersionByteForPrefix(address);
    if (vb === void 0) {
      throw new Error(`invalid signer key type (${vb})`);
    }
    const raw = decodeCheck(vb, address);
    switch (vb) {
      case "signedPayload":
        return types.SignerKey.signerKeyTypeEd25519SignedPayload(
          new types.SignerKeyEd25519SignedPayload({
            ed25519: raw.subarray(0, 32),
            payload: raw.subarray(36, 36 + raw.readUInt32BE(32))
          })
        );
      case "ed25519PublicKey":
        return types.SignerKey.signerKeyTypeEd25519(raw);
      case "preAuthTx":
        return types.SignerKey.signerKeyTypePreAuthTx(raw);
      case "sha256Hash":
        return types.SignerKey.signerKeyTypeHashX(raw);
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
      case types.SignerKeyType.signerKeyTypeEd25519():
        strkeyType = "ed25519PublicKey";
        raw = signerKey.value();
        break;
      case types.SignerKeyType.signerKeyTypePreAuthTx():
        strkeyType = "preAuthTx";
        raw = signerKey.value();
        break;
      case types.SignerKeyType.signerKeyTypeHashX():
        strkeyType = "sha256Hash";
        raw = signerKey.value();
        break;
      case types.SignerKeyType.signerKeyTypeEd25519SignedPayload():
        strkeyType = "signedPayload";
        raw = signerKey.ed25519SignedPayload().toXDR("raw");
        break;
      default:
        throw new Error(`invalid SignerKey (type: ${signerKey.switch().name})`);
    }
    return encodeCheck(strkeyType, raw);
  }
}

export { SignerKey };
//# sourceMappingURL=signerkey.js.map
