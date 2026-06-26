'use strict';

var buffer = require('buffer');
var curr_generated = require('./generated/curr_generated.js');
var hashing = require('./hashing.js');
var transaction = require('./transaction.js');
var transaction_base = require('./transaction_base.js');
var decode_encode_muxed_account = require('./util/decode_encode_muxed_account.js');

class FeeBumpTransaction extends transaction_base.TransactionBase {
  _feeSource;
  _innerTransaction;
  /**
   * @param envelope - transaction envelope object or base64 encoded string.
   * @param networkPassphrase - passphrase of the target Stellar network
   *     (e.g. "Public Global Stellar Network ; September 2015").
   */
  constructor(envelope, networkPassphrase) {
    if (typeof envelope === "string") {
      const buffer$1 = buffer.Buffer.from(envelope, "base64");
      envelope = curr_generated.default.TransactionEnvelope.fromXDR(buffer$1);
    }
    const envelopeType = envelope.switch();
    if (envelopeType !== curr_generated.default.EnvelopeType.envelopeTypeTxFeeBump()) {
      throw new Error(
        `Invalid TransactionEnvelope: expected an envelopeTypeTxFeeBump but received an ${envelopeType.name}.`
      );
    }
    const txEnvelope = envelope.value();
    const tx = txEnvelope.tx();
    const fee = tx.fee().toString();
    const signatures = (txEnvelope.signatures() || []).slice();
    super(tx, signatures, fee, networkPassphrase);
    const innerTxEnvelope = curr_generated.default.TransactionEnvelope.envelopeTypeTx(
      tx.innerTx().v1()
    );
    this._feeSource = decode_encode_muxed_account.encodeMuxedAccountToAddress(this.tx.feeSource());
    this._innerTransaction = new transaction.Transaction(
      innerTxEnvelope,
      networkPassphrase
    );
  }
  /**
   * The inner transaction that this fee bump wraps.
   */
  get innerTransaction() {
    return this._innerTransaction;
  }
  /**
   * The operations from the inner transaction.
   */
  get operations() {
    return this._innerTransaction.operations;
  }
  /**
   * The account paying the fee for this transaction.
   */
  get feeSource() {
    return this._feeSource;
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
    const taggedTransaction = curr_generated.default.TransactionSignaturePayloadTaggedTransaction.envelopeTypeTxFeeBump(
      this.tx
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
    const envelope = new curr_generated.default.FeeBumpTransactionEnvelope({
      tx: curr_generated.default.FeeBumpTransaction.fromXDR(this.tx.toXDR()),
      // make a copy of the tx
      signatures: this.signatures.slice()
      // make a copy of the signatures
    });
    return curr_generated.default.TransactionEnvelope.envelopeTypeTxFeeBump(envelope);
  }
}

exports.FeeBumpTransaction = FeeBumpTransaction;
//# sourceMappingURL=fee_bump_transaction.js.map
