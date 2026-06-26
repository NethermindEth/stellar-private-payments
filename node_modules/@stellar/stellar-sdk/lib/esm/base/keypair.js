import { Buffer } from 'buffer';
import * as ed from '@noble/ed25519';
import { sha512 } from '@noble/hashes/sha2.js';
import { generate, sign, verify } from './signing.js';
import { StrKey } from './strkey.js';
import { hash } from './hashing.js';
import types from './generated/curr_generated.js';

ed.hashes.sha512 = sha512;
class Keypair {
  type;
  _publicKey;
  _secretSeed;
  _secretKey;
  /**
   * @param keys - at least one of keys must be provided.
   *   - `type`: public-key signature system name (currently only `ed25519` keys are supported)
   *   - `publicKey`: raw public key
   *   - `secretKey`: raw secret key (32-byte secret seed in ed25519)
   */
  constructor(keys) {
    if (keys.type !== "ed25519") {
      throw new Error("Invalid keys type");
    }
    this.type = keys.type;
    if ("secretKey" in keys) {
      keys.secretKey = Buffer.from(keys.secretKey);
      if (keys.secretKey.length !== 32) {
        throw new Error("secretKey length is invalid");
      }
      this._secretSeed = keys.secretKey;
      this._publicKey = generate(keys.secretKey);
      this._secretKey = keys.secretKey;
      if (keys.publicKey && !this._publicKey.equals(Buffer.from(keys.publicKey))) {
        throw new Error("secretKey does not match publicKey");
      }
    } else if ("publicKey" in keys) {
      this._publicKey = Buffer.from(keys.publicKey);
      if (this._publicKey.length !== 32) {
        throw new Error("publicKey length is invalid");
      }
    } else {
      throw new Error(
        "At least one of publicKey or secretKey must be provided"
      );
    }
  }
  /**
   * Creates a new `Keypair` instance from secret. This can either be secret key or secret seed depending
   * on underlying public-key signature system. Currently `Keypair` only supports ed25519.
   * @param secret - secret key (ex. `SDAK....`)
   */
  static fromSecret(secret) {
    const rawSecret = StrKey.decodeEd25519SecretSeed(secret);
    return this.fromRawEd25519Seed(rawSecret);
  }
  /**
   * Creates a new `Keypair` object from ed25519 secret key seed raw bytes.
   *
   * @param rawSeed - raw 32-byte ed25519 secret key seed
   */
  static fromRawEd25519Seed(rawSeed) {
    return new this({ type: "ed25519", secretKey: rawSeed });
  }
  /**
   * Returns `Keypair` object representing network master key.
   * @param networkPassphrase - passphrase of the target stellar network (e.g. "Public Global Stellar Network ; September 2015")
   */
  static master(networkPassphrase) {
    if (!networkPassphrase) {
      throw new Error(
        "No network selected. Please pass a network argument, e.g. `Keypair.master(Networks.PUBLIC)`."
      );
    }
    return this.fromRawEd25519Seed(hash(networkPassphrase));
  }
  /**
   * Creates a new `Keypair` object from public key.
   * @param publicKey - public key (ex. `GB3KJPLFUYN5VL6R3GU3EGCGVCKFDSD7BEDX42HWG5BWFKB3KQGJJRMA`)
   */
  static fromPublicKey(publicKey) {
    const publicKeyBuffer = StrKey.decodeEd25519PublicKey(publicKey);
    if (publicKeyBuffer.length !== 32) {
      throw new Error("Invalid Stellar public key");
    }
    return new this({ type: "ed25519", publicKey: publicKeyBuffer });
  }
  /**
   * Create a random `Keypair` object.
   */
  static random() {
    const secretKey = ed.utils.randomSecretKey();
    return this.fromRawEd25519Seed(Buffer.from(secretKey));
  }
  /** Returns this public key as an xdr.AccountId. */
  xdrAccountId() {
    return types.PublicKey.publicKeyTypeEd25519(this._publicKey);
  }
  /** Returns this public key as an xdr.PublicKey. */
  xdrPublicKey() {
    return types.PublicKey.publicKeyTypeEd25519(this._publicKey);
  }
  /**
   * Creates a {@link xdr.MuxedAccount} object from the public key.
   *
   * You will get a different type of muxed account depending on whether or not
   * you pass an ID.
   *
   * @param id - (optional) stringified integer indicating the underlying muxed
   *     ID of the new account object
   */
  xdrMuxedAccount(id) {
    if (typeof id !== "undefined") {
      if (typeof id !== "string") {
        throw new TypeError(`expected string for ID, got ${typeof id}`);
      }
      return types.MuxedAccount.keyTypeMuxedEd25519(
        new types.MuxedAccountMed25519({
          id: types.Uint64.fromString(id),
          ed25519: this._publicKey
        })
      );
    }
    return types.MuxedAccount.keyTypeEd25519(this._publicKey);
  }
  /**
   * Returns raw public key bytes
   */
  rawPublicKey() {
    return this._publicKey;
  }
  /**
   * Returns the signature hint for this keypair.
   * The hint is the last 4 bytes of the account ID XDR representation.
   */
  signatureHint() {
    const a = this.xdrAccountId().toXDR();
    return a.subarray(a.length - 4);
  }
  /**
   * Returns public key associated with this `Keypair` object.
   */
  publicKey() {
    return StrKey.encodeEd25519PublicKey(this._publicKey);
  }
  /**
   * Returns secret key associated with this `Keypair` object.
   *
   * The secret key is encoded in Stellar format (e.g., `SDAK....`).
   *
   * @throws if no secret key is available
   */
  secret() {
    if (!this._secretSeed) {
      throw new Error("no secret key available");
    }
    if (this.type === "ed25519") {
      return StrKey.encodeEd25519SecretSeed(this._secretSeed);
    }
    throw new Error("Invalid Keypair type");
  }
  /**
   * Returns raw secret key bytes.
   *
   * @throws if no secret seed is available
   */
  rawSecretKey() {
    if (!this._secretSeed) {
      throw new Error("no secret seed available");
    }
    return this._secretSeed;
  }
  /**
   * Returns `true` if this `Keypair` object contains secret key and can sign.
   */
  canSign() {
    return !!this._secretKey;
  }
  /**
   * Signs data.
   *
   * @param data - data to sign
   * @throws if no secret key is available
   */
  sign(data) {
    if (!this._secretKey) {
      throw new Error("cannot sign: no secret key available");
    }
    return sign(data, this._secretKey);
  }
  /**
   * Verifies if `signature` for `data` is valid.
   *
   * @param data - signed data
   * @param signature - signature to verify
   */
  verify(data, signature) {
    try {
      return verify(data, signature, this._publicKey);
    } catch {
      return false;
    }
  }
  /**
   * Returns the decorated signature (hint+sig) for arbitrary data.
   *
   * The returned structure can be added directly to a transaction envelope.
   *
   * @param data - arbitrary data to sign
   *
   * @see TransactionBase.addDecoratedSignature
   */
  signDecorated(data) {
    const signature = this.sign(data);
    const hint = this.signatureHint();
    return new types.DecoratedSignature({ hint, signature });
  }
  /**
   * Returns the raw decorated signature (hint+sig) for a signed payload signer.
   *
   *  The hint is defined as the last 4 bytes of the signer key XORed with last
   *  4 bytes of the payload (zero-left-padded if necessary).
   *
   * @param data - data to both sign and treat as the payload
   *
   * @see https://github.com/stellar/stellar-protocol/blob/master/core/cap-0040.md#signature-hint
   * @see TransactionBase.addDecoratedSignature
   */
  signPayloadDecorated(data) {
    const dataBuffer = Buffer.isBuffer(data) ? data : Buffer.from(data);
    const signature = this.sign(dataBuffer);
    const keyHint = this.signatureHint();
    let hint = Buffer.from(dataBuffer.subarray(-4));
    if (hint.length < 4) {
      hint = Buffer.concat([hint, Buffer.alloc(4 - hint.length, 0)]);
    }
    for (let i = 0; i < hint.length; i++) {
      hint[i] = hint[i] ^ keyHint[i];
    }
    return new types.DecoratedSignature({
      hint,
      signature
    });
  }
}

export { Keypair };
//# sourceMappingURL=keypair.js.map
