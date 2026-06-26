import { Buffer } from 'buffer';
import types from './generated/curr_generated.js';
import { hash } from './hashing.js';
import { Keypair } from './keypair.js';

class TransactionBase {
  _tx;
  _signatures;
  _fee;
  _networkPassphrase;
  constructor(tx, signatures, fee, networkPassphrase) {
    if (typeof networkPassphrase !== "string") {
      throw new Error(
        `Invalid passphrase provided to Transaction: expected a string but got a ${typeof networkPassphrase}`
      );
    }
    this._networkPassphrase = networkPassphrase;
    this._tx = tx;
    this._signatures = signatures;
    this._fee = fee;
  }
  /** The list of signatures for this transaction. */
  get signatures() {
    return this._signatures;
  }
  set signatures(_value) {
    throw new Error("Transaction is immutable");
  }
  /**
   * The underlying XDR transaction object.
   *
   * Returns a defensive copy so that external mutations cannot alter the
   * transaction that will be signed or serialized.
   *
   * @throws if the internal transaction is not a recognized XDR type
   */
  get tx() {
    const buf = this._tx.toXDR();
    if (this._tx instanceof types.Transaction) {
      return types.Transaction.fromXDR(buf);
    }
    if (this._tx instanceof types.TransactionV0) {
      return types.TransactionV0.fromXDR(buf);
    }
    if (this._tx instanceof types.FeeBumpTransaction) {
      return types.FeeBumpTransaction.fromXDR(buf);
    }
    throw new Error("Unknown transaction type");
  }
  set tx(_value) {
    throw new Error("Transaction is immutable");
  }
  /** The total fee for this transaction, in stroops. */
  get fee() {
    return this._fee;
  }
  set fee(_value) {
    throw new Error("Transaction is immutable");
  }
  /** The network passphrase for this transaction. */
  get networkPassphrase() {
    return this._networkPassphrase;
  }
  set networkPassphrase(_networkPassphrase) {
    throw new Error("Transaction is immutable");
  }
  /**
   * Signs the transaction with the given {@link Keypair}.
   * @param keypairs - Keypairs of signers
   */
  sign(...keypairs) {
    const txHash = this.hash();
    keypairs.forEach((kp) => {
      const sig = kp.signDecorated(txHash);
      this.signatures.push(sig);
    });
  }
  /**
   * Signs a transaction with the given {@link Keypair}. Useful if someone sends
   * you a transaction XDR for you to sign and return (see
   * `{@link Transaction.addSignature | addSignature}` for more information).
   *
   * When you get a transaction XDR to sign....
   * - Instantiate a `Transaction` object with the XDR
   * - Use {@link Keypair} to generate a keypair object for your Stellar seed.
   * - Run `getKeypairSignature` with that keypair
   * - Send back the signature along with your publicKey (not your secret seed!)
   *
   * Example:
   * ```javascript
   * // `transactionXDR` is a string from the person generating the transaction
   * const transaction = new Transaction(transactionXDR, networkPassphrase);
   * const keypair = Keypair.fromSecret(myStellarSeed);
   * return transaction.getKeypairSignature(keypair);
   * ```
   *
   * Returns the base64-encoded signature string for the given keypair.
   *
   * @param keypair - Keypair of signer
   */
  getKeypairSignature(keypair) {
    return keypair.sign(this.hash()).toString("base64");
  }
  /**
   * Add a signature to the transaction. Useful when a party wants to pre-sign
   * a transaction but doesn't want to give access to their secret keys.
   * This will also verify whether the signature is valid.
   *
   * Here's how you would use this feature to solicit multiple signatures.
   * - Use `TransactionBuilder` to build a new transaction.
   * - Make sure to set a long enough timeout on that transaction to give your
   * signers enough time to sign!
   * - Once you build the transaction, use `transaction.toXDR()` to get the
   * base64-encoded XDR string.
   * - _Warning!_ Once you've built this transaction, don't submit any other
   * transactions onto your account! Doing so will invalidate this pre-compiled
   * transaction!
   * - Send this XDR string to your other parties. They can use the instructions
   * for `{@link Transaction.getKeypairSignature | getKeypairSignature}` to sign the transaction.
   * - They should send you back their `publicKey` and the `signature` string
   * from `{@link Transaction.getKeypairSignature | getKeypairSignature}`, both of which you pass to
   * this function.
   *
   * @param publicKey - the public key of the signer
   * @param signature - the base64 value of the signature XDR
   */
  addSignature(publicKey = "", signature = "") {
    if (!signature || typeof signature !== "string") {
      throw new Error("Invalid signature");
    }
    if (!publicKey || typeof publicKey !== "string") {
      throw new Error("Invalid publicKey");
    }
    let keypair;
    let hint;
    const signatureBuffer = Buffer.from(signature, "base64");
    try {
      keypair = Keypair.fromPublicKey(publicKey);
      hint = keypair.signatureHint();
    } catch {
      throw new Error("Invalid publicKey");
    }
    if (!keypair.verify(this.hash(), signatureBuffer)) {
      throw new Error("Invalid signature");
    }
    this.signatures.push(
      new types.DecoratedSignature({
        hint,
        signature: signatureBuffer
      })
    );
  }
  /**
   * Add a decorated signature directly to the transaction envelope.
   *
   * @param signature - raw signature to add
   *
   * @see Keypair.signDecorated
   * @see Keypair.signPayloadDecorated
   */
  addDecoratedSignature(signature) {
    this.signatures.push(signature);
  }
  /**
   * Add `hashX` signer preimage as signature.
   * @param preimage - preimage of hash used as signer
   */
  signHashX(preimage) {
    if (typeof preimage === "string") {
      preimage = Buffer.from(preimage, "hex");
    }
    if (preimage.length > 64) {
      throw new Error("preimage cannot be longer than 64 bytes");
    }
    const signature = preimage;
    const hashX = hash(preimage);
    const hint = hashX.subarray(hashX.length - 4);
    this.signatures.push(new types.DecoratedSignature({ hint, signature }));
  }
  /**
   * Returns a hash for this transaction, suitable for signing.
   */
  hash() {
    return hash(this.signatureBase());
  }
  /** Returns the signature base for this transaction, to be overridden by subclasses. */
  signatureBase() {
    throw new Error("Implement in subclass");
  }
  /** Returns the XDR transaction envelope, to be overridden by subclasses. */
  toEnvelope() {
    throw new Error("Implement in subclass");
  }
  /**
   * Returns the transaction envelope as a base64-encoded XDR string.
   */
  toXDR() {
    return this.toEnvelope().toXDR().toString("base64");
  }
}

export { TransactionBase };
//# sourceMappingURL=transaction_base.js.map
