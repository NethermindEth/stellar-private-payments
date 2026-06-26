import { Buffer } from 'buffer';
import { trimEnd } from './util/util.js';
import types from './generated/curr_generated.js';
import { Keypair } from './keypair.js';
import { StrKey } from './strkey.js';
import { hash } from './hashing.js';

const AssetType = {
  native: "native",
  credit4: "credit_alphanum4",
  credit12: "credit_alphanum12",
  liquidityPoolShares: "liquidity_pool_shares"
};
function asciiCompare(a, b) {
  return Buffer.compare(Buffer.from(a, "ascii"), Buffer.from(b, "ascii"));
}
class Asset {
  /** The asset code. */
  code;
  /** The account ID of the issuer. Undefined for the native asset. */
  issuer;
  /**
   * @param code - The asset code.
   * @param issuer - The account ID of the issuer.
   */
  constructor(code, issuer) {
    if (!/^[a-zA-Z0-9]{1,12}$/.test(code)) {
      throw new Error(
        "Asset code is invalid (maximum alphanumeric, 12 characters at max)"
      );
    }
    if (String(code).toLowerCase() !== "xlm" && !issuer) {
      throw new Error("Issuer cannot be null");
    }
    if (issuer && !StrKey.isValidEd25519PublicKey(issuer)) {
      throw new Error("Issuer is invalid");
    }
    if (String(code).toLowerCase() === "xlm") {
      this.code = "XLM";
    } else {
      this.code = code;
    }
    this.issuer = issuer;
  }
  /**
   * Returns an asset object for the native asset.
   */
  static native() {
    return new Asset("XLM");
  }
  /**
   * Returns an asset object from its XDR object representation.
   * @param assetXdr - The asset xdr object.
   */
  static fromOperation(assetXdr) {
    let anum;
    let code;
    let issuer;
    switch (assetXdr.switch()) {
      case types.AssetType.assetTypeNative():
        return this.native();
      case types.AssetType.assetTypeCreditAlphanum4():
        anum = assetXdr.alphaNum4();
        issuer = StrKey.encodeEd25519PublicKey(anum.issuer().ed25519());
        code = trimEnd(anum.assetCode().toString(), "\0");
        return new this(code, issuer);
      case types.AssetType.assetTypeCreditAlphanum12():
        anum = assetXdr.alphaNum12();
        issuer = StrKey.encodeEd25519PublicKey(anum.issuer().ed25519());
        code = trimEnd(anum.assetCode().toString(), "\0");
        return new this(code, issuer);
      default:
        throw new Error(`Invalid asset type: ${assetXdr.switch().name}`);
    }
  }
  /**
   * Returns the xdr.Asset object for this asset.
   */
  toXDRObject() {
    return this._toXDRObject(types.Asset);
  }
  /**
   * Returns the xdr.ChangeTrustAsset object for this asset.
   */
  toChangeTrustXDRObject() {
    return this._toXDRObject(types.ChangeTrustAsset);
  }
  /**
   * Returns the xdr.TrustLineAsset object for this asset.
   */
  toTrustLineXDRObject() {
    return this._toXDRObject(types.TrustLineAsset);
  }
  /**
   * Returns the would-be contract ID (`C...` format) for this asset on a given
   * network.
   *
   * @param networkPassphrase - indicates which network the contract
   *    ID should refer to, since every network will have a unique ID for the
   *    same contract (see {@link Networks} for options)
   *
   * **Warning:** This makes no guarantee that this contract actually *exists*.
   */
  contractId(networkPassphrase) {
    const networkId = hash(Buffer.from(networkPassphrase));
    const preimage = types.HashIdPreimage.envelopeTypeContractId(
      new types.HashIdPreimageContractId({
        networkId,
        contractIdPreimage: types.ContractIdPreimage.contractIdPreimageFromAsset(
          this.toXDRObject()
        )
      })
    );
    return StrKey.encodeContract(hash(preimage.toXDR()));
  }
  /**
   * Returns the xdr object for this asset.
   * @param xdrAsset - The xdr asset constructor.
   */
  _toXDRObject(xdrAsset) {
    if (this.isNative()) {
      return xdrAsset.assetTypeNative();
    }
    if (!this.issuer) {
      throw new Error("Issuer cannot be null for non-native asset");
    }
    let xdrType;
    let xdrTypeString;
    if (this.code.length <= 4) {
      xdrType = types.AlphaNum4;
      xdrTypeString = "assetTypeCreditAlphanum4";
    } else {
      xdrType = types.AlphaNum12;
      xdrTypeString = "assetTypeCreditAlphanum12";
    }
    const padLength = this.code.length <= 4 ? 4 : 12;
    const paddedCode = this.code.padEnd(padLength, "\0");
    const assetType = new xdrType({
      assetCode: paddedCode,
      issuer: Keypair.fromPublicKey(this.issuer).xdrAccountId()
    });
    return new xdrAsset(xdrTypeString, assetType);
  }
  /**
   * Returns the asset code
   */
  getCode() {
    return String(this.code);
  }
  /**
   * Returns the asset issuer
   */
  getIssuer() {
    if (this.issuer === void 0) {
      return void 0;
    }
    return String(this.issuer);
  }
  /**
   * @see [Assets concept](https://developers.stellar.org/docs/glossary/assets/)
   * Returns the asset type. Can be one of following types:
   *
   *  - `native`,
   *  - `credit_alphanum4`,
   *  - `credit_alphanum12`
   * @throws Throws `Error` if asset type is unsupported.
   */
  getAssetType() {
    switch (this.getRawAssetType().value) {
      case types.AssetType.assetTypeNative().value:
        return AssetType.native;
      case types.AssetType.assetTypeCreditAlphanum4().value:
        return AssetType.credit4;
      case types.AssetType.assetTypeCreditAlphanum12().value:
        return AssetType.credit12;
      default:
        throw new Error(
          "Supported asset types are: native, credit_alphanum4, credit_alphanum12"
        );
    }
  }
  /**
   * Returns the raw XDR representation of the asset type
   */
  getRawAssetType() {
    if (this.isNative()) {
      return types.AssetType.assetTypeNative();
    }
    if (this.code.length <= 4) {
      return types.AssetType.assetTypeCreditAlphanum4();
    }
    return types.AssetType.assetTypeCreditAlphanum12();
  }
  /**
   * Returns true if this asset object is the native asset.
   */
  isNative() {
    return !this.issuer;
  }
  /**
   * Returns true if this asset equals the given asset.
   *
   * @param asset - Asset to compare
   */
  equals(asset) {
    return this.code === asset.getCode() && this.issuer === asset.getIssuer();
  }
  /**
   * Returns a string representation of this asset.
   *
   * Native assets return `"native"`. Non-native assets return `"code:issuer"`.
   */
  toString() {
    if (this.isNative()) {
      return "native";
    }
    return `${this.getCode()}:${this.getIssuer()}`;
  }
  /**
   * Compares two assets according to the criteria:
   *
   *  1. First compare the type (`native < alphanum4 < alphanum12`).
   *  2. If the types are equal, compare the assets codes.
   *  3. If the asset codes are equal, compare the issuers.
   *
   * @param assetA - the first asset
   * @param assetB - the second asset
   */
  static compare(assetA, assetB) {
    if (!assetA || !(assetA instanceof Asset)) {
      throw new Error("assetA is invalid");
    }
    if (!assetB || !(assetB instanceof Asset)) {
      throw new Error("assetB is invalid");
    }
    if (assetA.equals(assetB)) {
      return 0;
    }
    const xdrAtype = assetA.getRawAssetType().value;
    const xdrBtype = assetB.getRawAssetType().value;
    if (xdrAtype !== xdrBtype) {
      return xdrAtype < xdrBtype ? -1 : 1;
    }
    const result = asciiCompare(assetA.getCode(), assetB.getCode());
    if (result !== 0) {
      return result;
    }
    const issuerA = assetA.getIssuer();
    const issuerB = assetB.getIssuer();
    if (issuerA === void 0 || issuerB === void 0) {
      throw new Error("Issuer is undefined for non-native asset");
    }
    return asciiCompare(issuerA, issuerB);
  }
}

export { Asset, AssetType };
//# sourceMappingURL=asset.js.map
