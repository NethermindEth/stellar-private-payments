import { Buffer } from 'buffer';
import types from './generated/curr_generated.js';
import { hash } from './hashing.js';
import { Transaction } from './transaction.js';
import { TransactionBase } from './transaction_base.js';
import { encodeMuxedAccountToAddress } from './util/decode_encode_muxed_account.js';

class FeeBumpTransaction extends TransactionBase {
  _feeSource;
  _innerTransaction;
  /**
   * @param envelope - transaction envelope object or base64 encoded string.
   * @param networkPassphrase - passphrase of the target Stellar network
   *     (e.g. "Public Global Stellar Network ; September 2015").
   */
  constructor(envelope, networkPassphrase) {
    if (typeof envelope === "string") {
      const buffer = Buffer.from(envelope, "base64");
      envelope = types.TransactionEnvelope.fromXDR(buffer);
    }
    const envelopeType = envelope.switch();
    if (envelopeType !== types.EnvelopeType.envelopeTypeTxFeeBump()) {
      throw new Error(
        `Invalid TransactionEnvelope: expected an envelopeTypeTxFeeBump but received an ${envelopeType.name}.`
      );
    }
    const txEnvelope = envelope.value();
    const tx = txEnvelope.tx();
    const fee = tx.fee().toString();
    const signatures = (txEnvelope.signatures() || []).slice();
    super(tx, signatures, fee, networkPassphrase);
    const innerTxEnvelope = types.TransactionEnvelope.envelopeTypeTx(
      tx.innerTx().v1()
    );
    this._feeSource = encodeMuxedAccountToAddress(this.tx.feeSource());
    this._innerTransaction = new Transaction(
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
    const taggedTransaction = types.TransactionSignaturePayloadTaggedTransaction.envelopeTypeTxFeeBump(
      this.tx
    );
    const txSignature = new types.TransactionSignaturePayload({
      networkId: types.Hash.fromXDR(hash(this.networkPassphrase)),
      taggedTransaction
    });
    return txSignature.toXDR();
  }
  /**
   * To envelope returns a xdr.TransactionEnvelope which can be submitted to the network.
   */
  toEnvelope() {
    const envelope = new types.FeeBumpTransactionEnvelope({
      tx: types.FeeBumpTransaction.fromXDR(this.tx.toXDR()),
      // make a copy of the tx
      signatures: this.signatures.slice()
      // make a copy of the signatures
    });
    return types.TransactionEnvelope.envelopeTypeTxFeeBump(envelope);
  }
}

export { FeeBumpTransaction };
//# sourceMappingURL=fee_bump_transaction.js.map
