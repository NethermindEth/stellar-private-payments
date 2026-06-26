import { Buffer } from 'buffer';
import { StrKey } from './strkey.js';
import types from './generated/curr_generated.js';

class Address {
  _type;
  _key;
  /**
   * @param address - a {@link StrKey} of the address value
   */
  constructor(address) {
    if (StrKey.isValidEd25519PublicKey(address)) {
      this._type = "account";
      this._key = StrKey.decodeEd25519PublicKey(address);
    } else if (StrKey.isValidContract(address)) {
      this._type = "contract";
      this._key = StrKey.decodeContract(address);
    } else if (StrKey.isValidMed25519PublicKey(address)) {
      this._type = "muxedAccount";
      this._key = StrKey.decodeMed25519PublicKey(address);
    } else if (StrKey.isValidClaimableBalance(address)) {
      this._type = "claimableBalance";
      this._key = StrKey.decodeClaimableBalance(address);
    } else if (StrKey.isValidLiquidityPool(address)) {
      this._type = "liquidityPool";
      this._key = StrKey.decodeLiquidityPool(address);
    } else {
      throw new Error(`Unsupported address type: ${address}`);
    }
  }
  /**
   * Parses a string and returns an Address object.
   *
   * @param address - The address to parse. ex. `GB3KJPLFUYN5VL6R3GU3EGCGVCKFDSD7BEDX42HWG5BWFKB3KQGJJRMA`
   */
  static fromString(address) {
    return new Address(address);
  }
  /**
   * Creates a new account Address object from a buffer of raw bytes.
   *
   * @param buffer - The bytes of an address to parse.
   */
  static account(buffer) {
    return new Address(StrKey.encodeEd25519PublicKey(buffer));
  }
  /**
   * Creates a new contract Address object from a buffer of raw bytes.
   *
   * @param buffer - The bytes of an address to parse.
   */
  static contract(buffer) {
    return new Address(StrKey.encodeContract(buffer));
  }
  /**
   * Creates a new claimable balance Address object from a buffer of raw bytes.
   *
   * @param buffer - The bytes of a claimable balance ID to parse.
   */
  static claimableBalance(buffer) {
    return new Address(StrKey.encodeClaimableBalance(buffer));
  }
  /**
   * Creates a new liquidity pool Address object from a buffer of raw bytes.
   *
   * @param buffer - The bytes of an LP ID to parse.
   */
  static liquidityPool(buffer) {
    return new Address(StrKey.encodeLiquidityPool(buffer));
  }
  /**
   * Creates a new muxed account Address object from a buffer of raw bytes.
   *
   * @param buffer - The bytes of an address to parse.
   */
  static muxedAccount(buffer) {
    return new Address(StrKey.encodeMed25519PublicKey(buffer));
  }
  /**
   * Convert this from an xdr.ScVal type.
   *
   * @param scVal - The xdr.ScVal type to parse
   */
  static fromScVal(scVal) {
    return Address.fromScAddress(scVal.address());
  }
  /**
   * Convert this from an xdr.ScAddress type
   *
   * @param scAddress - The xdr.ScAddress type to parse
   */
  static fromScAddress(scAddress) {
    switch (scAddress.switch().value) {
      case types.ScAddressType.scAddressTypeAccount().value:
        return Address.account(scAddress.accountId().ed25519());
      case types.ScAddressType.scAddressTypeContract().value:
        return Address.contract(scAddress.contractId());
      case types.ScAddressType.scAddressTypeMuxedAccount().value: {
        const raw = Buffer.concat([
          scAddress.muxedAccount().ed25519(),
          scAddress.muxedAccount().id().toXDR("raw")
        ]);
        return Address.muxedAccount(raw);
      }
      case types.ScAddressType.scAddressTypeClaimableBalance().value: {
        const cbi = scAddress.claimableBalanceId();
        return Address.claimableBalance(
          Buffer.concat([Buffer.from([cbi.switch().value]), cbi.v0()])
        );
      }
      case types.ScAddressType.scAddressTypeLiquidityPool().value:
        return Address.liquidityPool(
          scAddress.liquidityPoolId()
        );
      default:
        throw new Error(`Unsupported address type: ${scAddress.switch().name}`);
    }
  }
  /**
   * Serialize an address to string.
   */
  toString() {
    switch (this._type) {
      case "account":
        return StrKey.encodeEd25519PublicKey(this._key);
      case "contract":
        return StrKey.encodeContract(this._key);
      case "claimableBalance":
        return StrKey.encodeClaimableBalance(this._key);
      case "liquidityPool":
        return StrKey.encodeLiquidityPool(this._key);
      case "muxedAccount":
        return StrKey.encodeMed25519PublicKey(this._key);
      default:
        throw new Error("Unsupported address type");
    }
  }
  /**
   * Convert this Address to an xdr.ScVal type.
   */
  toScVal() {
    return types.ScVal.scvAddress(this.toScAddress());
  }
  /**
   * Convert this Address to an xdr.ScAddress type.
   */
  toScAddress() {
    switch (this._type) {
      case "account":
        return types.ScAddress.scAddressTypeAccount(
          types.PublicKey.publicKeyTypeEd25519(this._key)
        );
      case "contract":
        return types.ScAddress.scAddressTypeContract(
          this._key
        );
      case "liquidityPool":
        return types.ScAddress.scAddressTypeLiquidityPool(
          this._key
        );
      case "claimableBalance":
        return types.ScAddress.scAddressTypeClaimableBalance(
          types.ClaimableBalanceId.claimableBalanceIdTypeV0(
            this._key.subarray(1)
          )
        );
      case "muxedAccount":
        return types.ScAddress.scAddressTypeMuxedAccount(
          new types.MuxedEd25519Account({
            ed25519: this._key.subarray(0, 32),
            id: types.Uint64.fromXDR(this._key.subarray(32, 40), "raw")
          })
        );
      default:
        throw new Error("Unsupported address type");
    }
  }
  /**
   * Return the raw public key bytes for this address.
   */
  toBuffer() {
    return this._key;
  }
  /**
   * Return the type of this address.
   */
  get type() {
    return this._type;
  }
}

export { Address };
//# sourceMappingURL=address.js.map
