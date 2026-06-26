'use strict';

var buffer = require('buffer');
var curr_generated = require('./generated/curr_generated.js');
var hashing = require('./hashing.js');
var strkey = require('./strkey.js');
var operation = require('./operation.js');
var memo = require('./memo.js');
var transaction_base = require('./transaction_base.js');
var decode_encode_muxed_account = require('./util/decode_encode_muxed_account.js');

class Transaction extends transaction_base.TransactionBase {
  _envelopeType;
  _source = "";
  _memo;
  _sequence;
  _operations;
  _timeBounds;
  _ledgerBounds;
  _minAccountSequence;
  _minAccountSequenceAge;
  _minAccountSequenceLedgerGap;
  _extraSigners;
  /**
   * @param envelope - transaction envelope object or base64 encoded string
   * @param networkPassphrase - passphrase of the target stellar network
   *     (e.g. "Public Global Stellar Network ; September 2015")
   */
  constructor(envelope, networkPassphrase) {
    if (typeof envelope === "string") {
      const buffer$1 = buffer.Buffer.from(envelope, "base64");
      envelope = curr_generated.default.TransactionEnvelope.fromXDR(buffer$1);
    }
    const envelopeType = envelope.switch();
    if (!(envelopeType === curr_generated.default.EnvelopeType.envelopeTypeTxV0() || envelopeType === curr_generated.default.EnvelopeType.envelopeTypeTx())) {
      throw new Error(
        `Invalid TransactionEnvelope: expected an envelopeTypeTxV0 or envelopeTypeTx but received an ${envelopeType.name}.`
      );
    }
    const txEnvelope = envelope.value();
    const tx = txEnvelope.tx();
    const fee = tx.fee().toString();
    const signatures = (txEnvelope.signatures() || []).slice();
    super(tx, signatures, fee, networkPassphrase);
    this._envelopeType = envelopeType;
    this._memo = tx.memo();
    this._sequence = tx.seqNum().toString();
    switch (this._envelopeType) {
      case curr_generated.default.EnvelopeType.envelopeTypeTxV0():
        this._source = strkey.StrKey.encodeEd25519PublicKey(
          tx.sourceAccountEd25519()
        );
        break;
      default:
        this._source = decode_encode_muxed_account.encodeMuxedAccountToAddress(
          tx.sourceAccount()
        );
        break;
    }
    let cond = null;
    let timeBounds = null;
    switch (this._envelopeType) {
      case curr_generated.default.EnvelopeType.envelopeTypeTxV0():
        timeBounds = tx.timeBounds();
        break;
      case curr_generated.default.EnvelopeType.envelopeTypeTx():
        switch (tx.cond().switch()) {
          case curr_generated.default.PreconditionType.precondTime():
            timeBounds = tx.cond().timeBounds();
            break;
          case curr_generated.default.PreconditionType.precondV2():
            cond = tx.cond().v2();
            timeBounds = cond.timeBounds();
            break;
        }
        break;
    }
    if (timeBounds) {
      this._timeBounds = {
        minTime: timeBounds.minTime().toString(),
        maxTime: timeBounds.maxTime().toString()
      };
    }
    if (cond) {
      const ledgerBounds = cond.ledgerBounds();
      if (ledgerBounds) {
        this._ledgerBounds = {
          minLedger: ledgerBounds.minLedger(),
          maxLedger: ledgerBounds.maxLedger()
        };
      }
      const minSeq = cond.minSeqNum();
      if (minSeq) {
        this._minAccountSequence = minSeq.toString();
      }
      this._minAccountSequenceAge = cond.minSeqAge().toBigInt();
      this._minAccountSequenceLedgerGap = cond.minSeqLedgerGap();
      this._extraSigners = cond.extraSigners();
    }
    const operations = tx.operations() || [];
    this._operations = operations.map((op) => operation.Operation.fromXDRObject(op));
  }
  /**
   * The time bounds for this transaction, with `minTime` and `maxTime` as
   * 64-bit unix timestamps (strings).
   */
  get timeBounds() {
    return this._timeBounds;
  }
  set timeBounds(_value) {
    throw new Error("Transaction is immutable");
  }
  /**
   * The ledger bounds for this transaction, with `minLedger` (uint32) and
   * `maxLedger` (uint32, or 0 for no upper bound).
   */
  get ledgerBounds() {
    return this._ledgerBounds;
  }
  set ledgerBounds(_value) {
    throw new Error("Transaction is immutable");
  }
  /** The minimum account sequence (64-bit, as a string). */
  get minAccountSequence() {
    return this._minAccountSequence;
  }
  set minAccountSequence(_value) {
    throw new Error("Transaction is immutable");
  }
  /** The minimum account sequence age (64-bit number of seconds). */
  get minAccountSequenceAge() {
    return this._minAccountSequenceAge;
  }
  set minAccountSequenceAge(_value) {
    throw new Error("Transaction is immutable");
  }
  /** The minimum account sequence ledger gap (32-bit number of ledgers). */
  get minAccountSequenceLedgerGap() {
    return this._minAccountSequenceLedgerGap;
  }
  set minAccountSequenceLedgerGap(_value) {
    throw new Error("Transaction is immutable");
  }
  /**
   * Array of extra signers as XDR objects; use {@link SignerKey.encodeSignerKey}
   * to convert to StrKey strings.
   */
  get extraSigners() {
    return this._extraSigners;
  }
  set extraSigners(_value) {
    throw new Error("Transaction is immutable");
  }
  /** The sequence number for this transaction. */
  get sequence() {
    return this._sequence;
  }
  set sequence(_value) {
    throw new Error("Transaction is immutable");
  }
  /** The source account for this transaction. */
  get source() {
    return this._source;
  }
  set source(_value) {
    throw new Error("Transaction is immutable");
  }
  /** The list of operations in this transaction. */
  get operations() {
    return this._operations;
  }
  set operations(_value) {
    throw new Error("Transaction is immutable");
  }
  /** The memo attached to this transaction. */
  get memo() {
    return memo.Memo.fromXDRObject(this._memo);
  }
  set memo(_value) {
    throw new Error("Transaction is immutable");
  }
  /**
   * Returns the "signature base" of this transaction, which is the value
   * that, when hashed, should be signed to create a signature that
   * validators on the Stellar Network will accept.
   *
   * It is composed of a 4 prefix bytes followed by the xdr-encoded form
   * of this transaction.
   */
  signatureBase() {
    let tx = this.tx;
    if (this._envelopeType === curr_generated.default.EnvelopeType.envelopeTypeTxV0()) {
      tx = curr_generated.default.Transaction.fromXDR(
        buffer.Buffer.concat([
          // TransactionV0 is a transaction with the AccountID discriminant
          // stripped off, we need to put it back to build a valid transaction
          // which we can use to build a TransactionSignaturePayloadTaggedTransaction
          buffer.Buffer.alloc(4),
          // AccountID discriminant: publicKeyTypeEd25519 = 0
          tx.toXDR()
        ])
      );
    }
    const taggedTransaction = curr_generated.default.TransactionSignaturePayloadTaggedTransaction.envelopeTypeTx(
      tx
    );
    const txSignature = new curr_generated.default.TransactionSignaturePayload({
      networkId: curr_generated.default.Hash.fromXDR(hashing.hash(this.networkPassphrase)),
      taggedTransaction
    });
    return txSignature.toXDR();
  }
  /**
   * To envelope returns a xdr.TransactionEnvelope which can be submitted to the network.
   */
  toEnvelope() {
    const rawTx = this.tx.toXDR();
    const signatures = this.signatures.slice();
    let envelope;
    switch (this._envelopeType) {
      case curr_generated.default.EnvelopeType.envelopeTypeTxV0():
        envelope = curr_generated.default.TransactionEnvelope.envelopeTypeTxV0(
          new curr_generated.default.TransactionV0Envelope({
            tx: curr_generated.default.TransactionV0.fromXDR(rawTx),
            // make a copy of tx
            signatures
          })
        );
        break;
      case curr_generated.default.EnvelopeType.envelopeTypeTx():
        envelope = curr_generated.default.TransactionEnvelope.envelopeTypeTx(
          new curr_generated.default.TransactionV1Envelope({
            tx: curr_generated.default.Transaction.fromXDR(rawTx),
            // make a copy of tx
            signatures
          })
        );
        break;
      default:
        throw new Error(
          `Invalid TransactionEnvelope: expected an envelopeTypeTxV0 or envelopeTypeTx but received an ${this._envelopeType.name}.`
        );
    }
    return envelope;
  }
  /**
   * Calculate the claimable balance ID for an operation within the transaction.
   *
   * @param opIndex - the index of the CreateClaimableBalance op
   *
   * @throws for invalid `opIndex` value, if op at `opIndex` is not
   *    `CreateClaimableBalance`, or for general XDR un/marshalling failures
   *
   * @see https://github.com/stellar/go/blob/d712346e61e288d450b0c08038c158f8848cc3e4/txnbuild/transaction.go#L392-L435
   *
   */
  getClaimableBalanceId(opIndex) {
    if (!Number.isInteger(opIndex) || opIndex < 0 || opIndex >= this.operations.length) {
      throw new RangeError("invalid operation index");
    }
    const op = this.operations[opIndex];
    if (op === void 0) {
      throw new RangeError("invalid operation index");
    }
    try {
      operation.Operation.createClaimableBalance(
        op
      );
    } catch (err) {
      throw new TypeError(
        `expected createClaimableBalance, got ${op.type}: ${String(err)}`
      );
    }
    const account = strkey.StrKey.decodeEd25519PublicKey(
      decode_encode_muxed_account.extractBaseAddress(this.source)
    );
    const operationId = curr_generated.default.HashIdPreimage.envelopeTypeOpId(
      new curr_generated.default.HashIdPreimageOperationId({
        sourceAccount: curr_generated.default.PublicKey.publicKeyTypeEd25519(account),
        seqNum: curr_generated.default.Int64.fromString(this.sequence),
        opNum: opIndex
      })
    );
    const opIdHash = hashing.hash(operationId.toXDR("raw"));
    const balanceId = curr_generated.default.ClaimableBalanceId.claimableBalanceIdTypeV0(opIdHash);
    return balanceId.toXDR("hex");
  }
}

exports.Transaction = Transaction;
//# sourceMappingURL=transaction.js.map
