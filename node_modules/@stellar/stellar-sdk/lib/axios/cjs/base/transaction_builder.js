'use strict';

require('../node_modules/.pnpm/@stellar_js-xdr@4.0.0/node_modules/@stellar/js-xdr/src/int.js');
var hyper = require('../node_modules/.pnpm/@stellar_js-xdr@4.0.0/node_modules/@stellar/js-xdr/src/hyper.js');
require('../node_modules/.pnpm/@stellar_js-xdr@4.0.0/node_modules/@stellar/js-xdr/src/unsigned-int.js');
require('../node_modules/.pnpm/@stellar_js-xdr@4.0.0/node_modules/@stellar/js-xdr/src/unsigned-hyper.js');
require('../node_modules/.pnpm/@stellar_js-xdr@4.0.0/node_modules/@stellar/js-xdr/src/xdr-type.js');
require('buffer');
var bignumber = require('./util/bignumber.js');
var curr_generated = require('./generated/curr_generated.js');
var account = require('./account.js');
var muxed_account = require('./muxed_account.js');
var decode_encode_muxed_account = require('./util/decode_encode_muxed_account.js');
var transaction = require('./transaction.js');
var fee_bump_transaction = require('./fee_bump_transaction.js');
var sorobandata_builder = require('./sorobandata_builder.js');
var strkey = require('./strkey.js');
var signerkey = require('./signerkey.js');
var memo = require('./memo.js');
var scval = require('./scval.js');
var operation = require('./operation.js');
var address = require('./address.js');
var keypair = require('./keypair.js');

const HYPER_MAX_VALUE = hyper.Hyper.MAX_VALUE;
const UINT32_MAX = 4294967295;
const BASE_FEE = "100";
const TimeoutInfinite = 0;
class TransactionBuilder {
  source;
  operations;
  baseFee;
  timebounds;
  ledgerbounds;
  minAccountSequence;
  minAccountSequenceAge;
  minAccountSequenceLedgerGap;
  extraSigners;
  memo;
  networkPassphrase;
  sorobanData;
  /**
   * @param sourceAccount - source account for this transaction
   * @param opts - options object (see {@link TransactionBuilderOptions})
   */
  constructor(sourceAccount, opts = {}) {
    if (!sourceAccount) {
      throw new Error("must specify source account for the transaction");
    }
    if (opts.fee === void 0) {
      throw new Error("must specify fee for the transaction (in stroops)");
    }
    this.source = sourceAccount;
    this.operations = [];
    this.baseFee = opts.fee;
    if (opts.timebounds) {
      const minTime = toEpochSeconds(opts.timebounds.minTime);
      const maxTime = toEpochSeconds(opts.timebounds.maxTime);
      if (minTime !== void 0 && minTime < 0) {
        throw new Error("min_time cannot be negative");
      }
      if (maxTime !== void 0 && maxTime < 0) {
        throw new Error("max_time cannot be negative");
      }
      if (minTime !== void 0 && maxTime !== void 0 && maxTime > 0 && minTime > maxTime) {
        throw new Error("min_time cannot be greater than max_time");
      }
      this.timebounds = { ...opts.timebounds };
    } else {
      this.timebounds = null;
    }
    if (opts.ledgerbounds) {
      const minLedger = opts.ledgerbounds.minLedger;
      const maxLedger = opts.ledgerbounds.maxLedger;
      if (minLedger !== void 0 && minLedger < 0) {
        throw new Error("min_ledger cannot be negative");
      }
      if (maxLedger !== void 0 && maxLedger < 0) {
        throw new Error("max_ledger cannot be negative");
      }
      if (minLedger !== void 0 && maxLedger !== void 0 && maxLedger > 0 && minLedger > maxLedger) {
        throw new Error("min_ledger cannot be greater than max_ledger");
      }
      this.ledgerbounds = { ...opts.ledgerbounds };
    } else {
      this.ledgerbounds = null;
    }
    this.minAccountSequence = opts.minAccountSequence || null;
    this.minAccountSequenceAge = opts.minAccountSequenceAge !== void 0 ? opts.minAccountSequenceAge : null;
    this.minAccountSequenceLedgerGap = opts.minAccountSequenceLedgerGap !== void 0 ? opts.minAccountSequenceLedgerGap : null;
    this.extraSigners = opts.extraSigners ? [...opts.extraSigners] : null;
    this.memo = opts.memo || memo.Memo.none();
    this.networkPassphrase = opts.networkPassphrase || null;
    this.sorobanData = opts.sorobanData ? new sorobandata_builder.SorobanDataBuilder(opts.sorobanData).build() : null;
  }
  /**
   * Creates a builder instance using an existing {@link Transaction} as a
   * template, ignoring any existing envelope signatures.
   *
   * Note that the sequence number WILL be cloned, so EITHER this transaction or
   * the one it was cloned from will be valid. This is useful in situations
   * where you are constructing a transaction in pieces and need to make
   * adjustments as you go (for example, when filling out Soroban resource
   * information).
   *
   * @param tx - a "template" transaction to clone exactly
   * @param opts - additional options to override the clone, e.g.
   *    `{fee: '1000'}` will override the existing base fee derived from `tx`
   *    (see the {@link TransactionBuilder} constructor for detailed options)
   *
   * **Warning:** This does not clone the transaction's
   * {@link xdr.SorobanTransactionData} (if applicable), use
   * {@link SorobanDataBuilder} and {@link TransactionBuilder.setSorobanData}
   * as needed, instead.
   *
   * TODO: This cannot clone {@link FeeBumpTransaction}s, yet.
   */
  static cloneFrom(tx, opts = {}) {
    if (!(tx instanceof transaction.Transaction)) {
      throw new TypeError(`expected a 'Transaction', got: ${String(tx)}`);
    }
    const sequenceNum = (BigInt(tx.sequence) - 1n).toString();
    let source;
    if (strkey.StrKey.isValidMed25519PublicKey(tx.source)) {
      source = muxed_account.MuxedAccount.fromAddress(tx.source, sequenceNum);
    } else if (strkey.StrKey.isValidEd25519PublicKey(tx.source)) {
      source = new account.Account(tx.source, sequenceNum);
    } else {
      throw new TypeError(`unsupported tx source account: ${tx.source}`);
    }
    if (tx.operations.length === 0) {
      throw new Error(
        "cannot clone a transaction with no operations: per-operation base fee cannot be determined"
      );
    }
    let sorobanData;
    const envelope = tx.toEnvelope();
    if (envelope.switch() === curr_generated.default.EnvelopeType.envelopeTypeTx()) {
      sorobanData = envelope.v1().tx().ext().value() ?? void 0;
    }
    let totalFee = parseInt(tx.fee, 10);
    if (sorobanData) {
      const resourceFee = Number(sorobanData.resourceFee().toBigInt());
      if (totalFee - resourceFee > 0) {
        totalFee -= resourceFee;
      }
    }
    const unscaledFee = Math.floor(totalFee / tx.operations.length);
    const builderOpts = {
      fee: (unscaledFee || BASE_FEE).toString(),
      memo: tx.memo,
      networkPassphrase: tx.networkPassphrase
    };
    if (tx.timeBounds) {
      builderOpts.timebounds = tx.timeBounds;
    }
    if (tx.ledgerBounds) {
      builderOpts.ledgerbounds = tx.ledgerBounds;
    }
    if (tx.minAccountSequence) {
      builderOpts.minAccountSequence = tx.minAccountSequence;
    }
    if (tx.minAccountSequenceAge !== void 0) {
      builderOpts.minAccountSequenceAge = tx.minAccountSequenceAge;
    }
    if (tx.minAccountSequenceLedgerGap !== void 0) {
      builderOpts.minAccountSequenceLedgerGap = tx.minAccountSequenceLedgerGap;
    }
    if (tx.extraSigners) {
      builderOpts.extraSigners = tx.extraSigners.map(
        (s) => signerkey.SignerKey.encodeSignerKey(s)
      );
    }
    Object.assign(builderOpts, opts);
    const builder = new TransactionBuilder(source, builderOpts);
    tx.tx.operations().forEach((op) => builder.addOperation(op));
    return builder;
  }
  /**
   * Adds an operation to the transaction.
   *
   * @param operation - The xdr operation object, use {@link
   *     Operation} static methods.
   */
  addOperation(operation) {
    this.operations.push(operation);
    return this;
  }
  /**
   * Adds an operation to the transaction at a specific index.
   *
   * @param operation - The xdr operation object to add, use {@link Operation} static methods.
   * @param index - The index at which to insert the operation.
   */
  addOperationAt(operation, index) {
    this.operations.splice(index, 0, operation);
    return this;
  }
  /**
   * Removes the operations from the builder (useful when cloning).
   */
  clearOperations() {
    this.operations = [];
    return this;
  }
  /**
   * Removes the operation at the specified index from the transaction.
   *
   * @param index - The index of the operation to remove.
   */
  clearOperationAt(index) {
    this.operations.splice(index, 1);
    return this;
  }
  /**
   * Adds a memo to the transaction.
   * @param memo - {@link Memo} object
   */
  addMemo(memo) {
    this.memo = memo;
    return this;
  }
  /**
   * Sets a timeout precondition on the transaction.
   *
   *  Because of the distributed nature of the Stellar network it is possible
   *  that the status of your transaction will be determined after a long time
   *  if the network is highly congested. If you want to be sure to receive the
   *  status of the transaction within a given period you should set the
   *  time bounds with `maxTime` on the transaction (this is what `setTimeout`
   *  does internally; if there's `minTime` set but no `maxTime` it will be
   *  added).
   *
   *  A call to `TransactionBuilder.setTimeout` is **required** if Transaction
   *  does not have `max_time` set. If you don't want to set timeout, use
   *  {@link TimeoutInfinite}. In general you should set
   *  {@link TimeoutInfinite} only in smart contracts.
   *
   *  Please note that Horizon may still return <code>504 Gateway Timeout</code>
   *  error, even for short timeouts. In such case you need to resubmit the same
   *  transaction again without making any changes to receive a status. This
   *  method is using the machine system time (UTC), make sure it is set
   *  correctly.
   *
   * @param timeoutSeconds - Number of seconds the transaction is good.
   *     Can't be negative. If the value is {@link TimeoutInfinite}, the
   *     transaction is good indefinitely.
   *
   * @see {@link TimeoutInfinite}
   * @see https://developers.stellar.org/docs/tutorials/handling-errors/
   */
  setTimeout(timeoutSeconds) {
    if (this.timebounds !== null && Number(this.timebounds.maxTime) > 0) {
      throw new Error(
        "TimeBounds.max_time has been already set - setting timeout would overwrite it."
      );
    }
    if (timeoutSeconds < 0) {
      throw new Error("timeout cannot be negative");
    }
    if (timeoutSeconds > 0) {
      const timeoutTimestamp = Math.floor(Date.now() / 1e3) + timeoutSeconds;
      if (this.timebounds === null) {
        this.timebounds = { minTime: 0, maxTime: timeoutTimestamp };
      } else {
        this.timebounds = {
          minTime: this.timebounds.minTime ?? 0,
          maxTime: timeoutTimestamp
        };
      }
    } else {
      this.timebounds = {
        minTime: 0,
        maxTime: 0
      };
    }
    return this;
  }
  /**
   * If you want to prepare a transaction which will become valid at some point
   * in the future, or be invalid after some time, you can set a timebounds
   * precondition. Internally this will set the `minTime`, and `maxTime`
   * preconditions. Conflicts with `setTimeout`, so use one or the other.
   *
   * @param minEpochOrDate - Either a JS Date object, or a number
   *     of UNIX epoch seconds. The transaction is valid after this timestamp.
   *     Can't be negative. If the value is `0`, the transaction is valid
   *     immediately.
   * @param maxEpochOrDate - Either a JS Date object, or a number
   *     of UNIX epoch seconds. The transaction is valid until this timestamp.
   *     Can't be negative. If the value is `0`, the transaction is valid
   *     indefinitely.
   */
  setTimebounds(minEpochOrDate, maxEpochOrDate) {
    if (typeof minEpochOrDate === "number") {
      minEpochOrDate = new Date(minEpochOrDate * 1e3);
    }
    if (typeof maxEpochOrDate === "number") {
      maxEpochOrDate = new Date(maxEpochOrDate * 1e3);
    }
    if (this.timebounds !== null) {
      throw new Error(
        "TimeBounds has been already set - setting timebounds would overwrite it."
      );
    }
    const minTime = Math.floor(minEpochOrDate.valueOf() / 1e3);
    const maxTime = Math.floor(maxEpochOrDate.valueOf() / 1e3);
    if (minTime < 0) {
      throw new Error("min_time cannot be negative");
    }
    if (maxTime < 0) {
      throw new Error("max_time cannot be negative");
    }
    if (maxTime > 0 && minTime > maxTime) {
      throw new Error("min_time cannot be greater than max_time");
    }
    this.timebounds = { minTime, maxTime };
    return this;
  }
  /**
   * If you want to prepare a transaction which will only be valid within some
   * range of ledgers, you can set a ledgerbounds precondition.
   * Internally this will set the `minLedger` and `maxLedger` preconditions.
   *
   * @param minLedger - The minimum ledger this transaction is valid at
   *     or after. Cannot be negative. If the value is `0` (the default), the
   *     transaction is valid immediately.
   *
   * @param maxLedger - The maximum ledger this transaction is valid
   *     before. Cannot be negative. If the value is `0`, the transaction is
   *     valid indefinitely.
   */
  setLedgerbounds(minLedger, maxLedger) {
    if (this.ledgerbounds !== null) {
      throw new Error(
        "LedgerBounds has been already set - setting ledgerbounds would overwrite it."
      );
    }
    if (minLedger < 0) {
      throw new Error("min_ledger cannot be negative");
    }
    if (maxLedger < 0) {
      throw new Error("max_ledger cannot be negative");
    }
    if (maxLedger > 0 && minLedger > maxLedger) {
      throw new Error("min_ledger cannot be greater than max_ledger");
    }
    this.ledgerbounds = { minLedger, maxLedger };
    return this;
  }
  /**
   * If you want to prepare a transaction which will be valid only while the
   * account sequence number is
   *
   *     `minAccountSequence <= sourceAccountSequence < tx.seqNum`
   *
   * Note that after execution the account's sequence number is always raised to
   * `tx.seqNum`. Internally this will set the `minAccountSequence`
   * precondition.
   *
   * @param minAccountSequence - The minimum source account sequence
   *     number this transaction is valid for. If the value is `0` (the
   *     default), the transaction is valid when `sourceAccount`'s sequence
   *     number `== tx.seqNum - 1`.
   */
  setMinAccountSequence(minAccountSequence) {
    if (this.minAccountSequence !== null) {
      throw new Error(
        "min_account_sequence has been already set - setting min_account_sequence would overwrite it."
      );
    }
    this.minAccountSequence = minAccountSequence;
    return this;
  }
  /**
   * For the transaction to be valid, the current ledger time must be at least
   * `minAccountSequenceAge` greater than sourceAccount's `sequenceTime`.
   * Internally this will set the `minAccountSequenceAge` precondition.
   *
   * @param durationInSeconds - The minimum amount of time between
   *     source account sequence time and the ledger time when this transaction
   *     will become valid. If the value is `0`, the transaction is unrestricted
   *     by the account sequence age. Cannot be negative.
   */
  setMinAccountSequenceAge(durationInSeconds) {
    if (typeof durationInSeconds !== "bigint") {
      throw new Error("min_account_sequence_age must be a bigint");
    }
    if (this.minAccountSequenceAge !== null) {
      throw new Error(
        "min_account_sequence_age has been already set - setting min_account_sequence_age would overwrite it."
      );
    }
    if (durationInSeconds < 0) {
      throw new Error("min_account_sequence_age cannot be negative");
    }
    this.minAccountSequenceAge = durationInSeconds;
    return this;
  }
  /**
   * For the transaction to be valid, the current ledger number must be at least
   * `minAccountSequenceLedgerGap` greater than sourceAccount's ledger sequence.
   * Internally this will set the `minAccountSequenceLedgerGap` precondition.
   *
   * @param gap - The minimum number of ledgers between source account
   *     sequence and the ledger number when this transaction will become valid.
   *     If the value is `0`, the transaction is unrestricted by the account
   *     sequence ledger. Cannot be negative.
   */
  setMinAccountSequenceLedgerGap(gap) {
    if (this.minAccountSequenceLedgerGap !== null) {
      throw new Error(
        "min_account_sequence_ledger_gap has been already set - setting min_account_sequence_ledger_gap would overwrite it."
      );
    }
    if (gap < 0) {
      throw new Error("min_account_sequence_ledger_gap cannot be negative");
    }
    this.minAccountSequenceLedgerGap = gap;
    return this;
  }
  /**
   * For the transaction to be valid, there must be a signature corresponding to
   * every Signer in this array, even if the signature is not otherwise required
   * by the sourceAccount or operations. Internally this will set the
   * `extraSigners` precondition.
   *
   * @param extraSigners - required extra signers (as {@link StrKey}s)
   */
  setExtraSigners(extraSigners) {
    if (!Array.isArray(extraSigners)) {
      throw new Error("extra_signers must be an array of strings.");
    }
    if (this.extraSigners !== null) {
      throw new Error(
        "extra_signers has been already set - setting extra_signers would overwrite it."
      );
    }
    if (extraSigners.length > 2) {
      throw new Error("extra_signers cannot be longer than 2 elements.");
    }
    this.extraSigners = [...extraSigners];
    return this;
  }
  /**
   * Set network passphrase for the Transaction that will be built.
   *
   * @param networkPassphrase - passphrase of the target Stellar
   *     network (e.g. "Public Global Stellar Network ; September 2015").
   */
  setNetworkPassphrase(networkPassphrase) {
    this.networkPassphrase = networkPassphrase;
    return this;
  }
  /**
   * Sets the transaction's internal Soroban transaction data (resources,
   * footprint, etc.).
   *
   * For non-contract(non-Soroban) transactions, this setting has no effect. In
   * the case of Soroban transactions, this is either an instance of
   * {@link xdr.SorobanTransactionData} or a base64-encoded string of said
   * structure. This is usually obtained from the simulation response based on a
   * transaction with a Soroban operation (e.g.
   * {@link Operation.invokeHostFunction}, providing necessary resource
   * and storage footprint estimations for contract invocation.
   *
   * @param sorobanData - the {@link xdr.SorobanTransactionData} as a raw xdr
   *    object or a base64 string to be decoded
   *
   * @see {@link SorobanDataBuilder}
   */
  setSorobanData(sorobanData) {
    this.sorobanData = new sorobandata_builder.SorobanDataBuilder(sorobanData).build();
    return this;
  }
  /**
   * Creates and adds an invoke host function operation for transferring SAC tokens.
   * This method removes the need for simulation by handling the creation of the
   * appropriate authorization entries and ledger footprint for the transfer operation.
   *
   * @param destination - the address of the recipient of the SAC transfer (should be a valid Stellar address or contract ID)
   * @param asset - the SAC asset to be transferred
   * @param amount - the amount of tokens to be transferred in 7 decimals. IE 1 token with 7 decimals of precision would be represented as "1_0000000"
   * @param sorobanFees - optional Soroban fees for the transaction to override the default fees used
   */
  addSacTransferOperation(destination, asset, amount, sorobanFees) {
    if (BigInt(amount) <= 0n) {
      throw new Error("Amount must be a positive integer");
    } else if (BigInt(amount) > HYPER_MAX_VALUE) {
      throw new Error("Amount exceeds maximum value for i64");
    }
    if (sorobanFees) {
      const { instructions, readBytes, writeBytes, resourceFee } = sorobanFees;
      const U32_MAX = 4294967295;
      if (instructions <= 0 || instructions > U32_MAX) {
        throw new Error(
          `instructions must be greater than 0 and at most ${U32_MAX}`
        );
      }
      if (readBytes <= 0 || readBytes > U32_MAX) {
        throw new Error(
          `readBytes must be greater than 0 and at most ${U32_MAX}`
        );
      }
      if (writeBytes <= 0 || writeBytes > U32_MAX) {
        throw new Error(
          `writeBytes must be greater than 0 and at most ${U32_MAX}`
        );
      }
      if (resourceFee <= 0n || resourceFee > HYPER_MAX_VALUE) {
        throw new Error(
          "resourceFee must be greater than 0 and at most i64 max"
        );
      }
    }
    const isDestinationContract = strkey.StrKey.isValidContract(destination);
    if (!isDestinationContract) {
      if (!strkey.StrKey.isValidEd25519PublicKey(destination) && !strkey.StrKey.isValidMed25519PublicKey(destination)) {
        throw new Error(
          "Invalid destination address. Must be a valid Stellar address or contract ID."
        );
      }
    }
    const destinationBaseAddress = isDestinationContract ? destination : decode_encode_muxed_account.extractBaseAddress(destination);
    if (destinationBaseAddress === decode_encode_muxed_account.extractBaseAddress(this.source.accountId())) {
      throw new Error("Destination cannot be the same as the source account.");
    }
    if (this.networkPassphrase === null) {
      throw new Error(
        "networkPassphrase must be set to add a SAC transfer operation"
      );
    }
    const contractId = asset.contractId(this.networkPassphrase);
    const functionName = "transfer";
    const source = this.source.accountId();
    const sourceBaseAddress = decode_encode_muxed_account.extractBaseAddress(source);
    const args = [
      scval.nativeToScVal(source, { type: "address" }),
      scval.nativeToScVal(destination, { type: "address" }),
      scval.nativeToScVal(amount, { type: "i128" })
    ];
    const isAssetNative = asset.isNative();
    const auths = new curr_generated.default.SorobanAuthorizationEntry({
      credentials: curr_generated.default.SorobanCredentials.sorobanCredentialsSourceAccount(),
      rootInvocation: new curr_generated.default.SorobanAuthorizedInvocation({
        function: curr_generated.default.SorobanAuthorizedFunction.sorobanAuthorizedFunctionTypeContractFn(
          new curr_generated.default.InvokeContractArgs({
            contractAddress: address.Address.fromString(contractId).toScAddress(),
            functionName,
            args
          })
        ),
        subInvocations: []
      })
    });
    const footprint = new curr_generated.default.LedgerFootprint({
      readOnly: [
        curr_generated.default.LedgerKey.contractData(
          new curr_generated.default.LedgerKeyContractData({
            contract: address.Address.fromString(contractId).toScAddress(),
            key: curr_generated.default.ScVal.scvLedgerKeyContractInstance(),
            durability: curr_generated.default.ContractDataDurability.persistent()
          })
        )
      ],
      readWrite: []
    });
    if (isDestinationContract) {
      footprint.readWrite().push(
        curr_generated.default.LedgerKey.contractData(
          new curr_generated.default.LedgerKeyContractData({
            contract: address.Address.fromString(contractId).toScAddress(),
            key: curr_generated.default.ScVal.scvVec([
              scval.nativeToScVal("Balance", { type: "symbol" }),
              scval.nativeToScVal(destination, { type: "address" })
            ]),
            durability: curr_generated.default.ContractDataDurability.persistent()
          })
        )
      );
      if (!isAssetNative) {
        const assetIssuer = asset.getIssuer();
        if (!assetIssuer) {
          throw new Error("Asset issuer must be set for non-native assets.");
        }
        footprint.readOnly().push(
          curr_generated.default.LedgerKey.account(
            new curr_generated.default.LedgerKeyAccount({
              accountId: keypair.Keypair.fromPublicKey(assetIssuer).xdrPublicKey()
            })
          )
        );
      }
    } else if (isAssetNative) {
      footprint.readWrite().push(
        curr_generated.default.LedgerKey.account(
          new curr_generated.default.LedgerKeyAccount({
            accountId: keypair.Keypair.fromPublicKey(
              destinationBaseAddress
            ).xdrPublicKey()
          })
        )
      );
    } else if (asset.getIssuer() !== destinationBaseAddress) {
      footprint.readWrite().push(
        curr_generated.default.LedgerKey.trustline(
          new curr_generated.default.LedgerKeyTrustLine({
            accountId: keypair.Keypair.fromPublicKey(
              destinationBaseAddress
            ).xdrPublicKey(),
            asset: asset.toTrustLineXDRObject()
          })
        )
      );
    }
    if (asset.isNative()) {
      footprint.readWrite().push(
        curr_generated.default.LedgerKey.account(
          new curr_generated.default.LedgerKeyAccount({
            accountId: keypair.Keypair.fromPublicKey(sourceBaseAddress).xdrPublicKey()
          })
        )
      );
    } else if (asset.getIssuer() !== sourceBaseAddress) {
      footprint.readWrite().push(
        curr_generated.default.LedgerKey.trustline(
          new curr_generated.default.LedgerKeyTrustLine({
            accountId: keypair.Keypair.fromPublicKey(sourceBaseAddress).xdrPublicKey(),
            asset: asset.toTrustLineXDRObject()
          })
        )
      );
    }
    const defaultPaymentFees = {
      instructions: 4e5,
      readBytes: 1e3,
      writeBytes: 1e3,
      resourceFee: BigInt(5e6)
    };
    const sorobanData = new curr_generated.default.SorobanTransactionData({
      resources: new curr_generated.default.SorobanResources({
        footprint,
        instructions: sorobanFees ? sorobanFees.instructions : defaultPaymentFees.instructions,
        diskReadBytes: sorobanFees ? sorobanFees.readBytes : defaultPaymentFees.readBytes,
        writeBytes: sorobanFees ? sorobanFees.writeBytes : defaultPaymentFees.writeBytes
      }),
      ext: new curr_generated.default.SorobanTransactionDataExt(0),
      resourceFee: new curr_generated.default.Int64(
        sorobanFees ? sorobanFees.resourceFee : defaultPaymentFees.resourceFee
      )
    });
    const operation$1 = operation.Operation.invokeContractFunction({
      contract: contractId,
      function: functionName,
      args,
      auth: [auths]
    });
    this.setSorobanData(sorobanData);
    return this.addOperation(operation$1);
  }
  /**
   * Builds the transaction and increments the source account's sequence
   * number by 1.
   */
  build() {
    const sequenceNumber = new bignumber.default(this.source.sequenceNumber()).plus(1);
    const fee = new bignumber.default(this.baseFee).times(this.operations.length).toNumber();
    if (fee > UINT32_MAX) {
      throw new Error(
        `Total fee (baseFee * operations) exceeds the maximum uint32 value (${UINT32_MAX}). Got ${fee} from baseFee=${this.baseFee} and ${this.operations.length} operation(s).`
      );
    }
    const attrs = {
      fee,
      seqNum: curr_generated.default.Int64.fromString(sequenceNumber.toString()),
      memo: this.memo ? this.memo.toXDRObject() : null
    };
    if (this.timebounds === null || typeof this.timebounds.minTime === "undefined" || typeof this.timebounds.maxTime === "undefined") {
      throw new Error(
        "TimeBounds has to be set or you must call setTimeout(TimeoutInfinite)."
      );
    }
    if (isValidDate(this.timebounds.minTime)) {
      this.timebounds.minTime = Math.floor(
        this.timebounds.minTime.getTime() / 1e3
      );
    }
    if (isValidDate(this.timebounds.maxTime)) {
      this.timebounds.maxTime = Math.floor(
        this.timebounds.maxTime.getTime() / 1e3
      );
    }
    const minTime = curr_generated.default.Uint64.fromString(this.timebounds.minTime.toString());
    const maxTime = curr_generated.default.Uint64.fromString(this.timebounds.maxTime.toString());
    const timeBounds = new curr_generated.default.TimeBounds({ minTime, maxTime });
    if (this.hasV2Preconditions()) {
      let ledgerBounds = null;
      if (this.ledgerbounds !== null) {
        ledgerBounds = new curr_generated.default.LedgerBounds({
          minLedger: this.ledgerbounds.minLedger ?? 0,
          maxLedger: this.ledgerbounds.maxLedger ?? 0
        });
      }
      const minSeqNum = this.minAccountSequence ? curr_generated.default.Int64.fromString(this.minAccountSequence) : null;
      const minSeqAge = curr_generated.default.Uint64.fromString(
        this.minAccountSequenceAge !== null ? this.minAccountSequenceAge.toString() : "0"
      );
      const minSeqLedgerGap = this.minAccountSequenceLedgerGap || 0;
      const extraSigners = this.extraSigners !== null ? this.extraSigners.map((s) => signerkey.SignerKey.decodeAddress(s)) : [];
      attrs.cond = curr_generated.default.Preconditions.precondV2(
        new curr_generated.default.PreconditionsV2({
          timeBounds,
          ledgerBounds,
          minSeqNum,
          minSeqAge,
          minSeqLedgerGap,
          extraSigners
        })
      );
    } else {
      attrs.cond = curr_generated.default.Preconditions.precondTime(timeBounds);
    }
    attrs.sourceAccount = decode_encode_muxed_account.decodeAddressToMuxedAccount(this.source.accountId());
    if (this.sorobanData) {
      attrs.ext = new curr_generated.default.TransactionExt(1, this.sorobanData);
      attrs.fee = new bignumber.default(attrs.fee).plus(this.sorobanData.resourceFee().toString()).toNumber();
      if (attrs.fee > UINT32_MAX) {
        throw new Error(
          `Total fee (baseFee * operations + resourceFee) exceeds the maximum uint32 value (${UINT32_MAX}). Got ${attrs.fee}.`
        );
      }
    } else {
      attrs.ext = new curr_generated.default.TransactionExt(0);
    }
    const xtx = new curr_generated.default.Transaction(
      attrs
    );
    xtx.operations(this.operations);
    const txEnvelope = curr_generated.default.TransactionEnvelope.envelopeTypeTx(
      new curr_generated.default.TransactionV1Envelope({ tx: xtx, signatures: [] })
    );
    if (this.networkPassphrase === null) {
      throw new Error("networkPassphrase must be set to build a transaction");
    }
    const tx = new transaction.Transaction(txEnvelope, this.networkPassphrase);
    this.source.incrementSequenceNumber();
    return tx;
  }
  /**
   * Checks whether any v2 preconditions have been set on this builder.
   */
  hasV2Preconditions() {
    return this.ledgerbounds !== null || this.minAccountSequence !== null || this.minAccountSequenceAge !== null || this.minAccountSequenceLedgerGap !== null || this.extraSigners !== null && this.extraSigners.length > 0;
  }
  /**
   * Builds a {@link FeeBumpTransaction}, enabling you to resubmit an existing
   * transaction with a higher fee.
   *
   * @param feeSource - account paying for the transaction,
   *     in the form of either a Keypair (only the public key is used) or
   *     an account ID (in G... or M... form, but refer to `withMuxing`)
   * @param baseFee - max fee willing to pay per operation
   *     in inner transaction (**in stroops**)
   * @param innerTx - {@link Transaction} to be bumped by
   *     the fee bump transaction
   * @param networkPassphrase - passphrase of the target
   *     Stellar network (e.g. "Public Global Stellar Network ; September 2015",
   *     see {@link Networks})
   *
   * TODO: Alongside the next major version bump, this type signature can be
   *       changed to be less awkward: accept a MuxedAccount as the `feeSource`
   *       rather than a keypair or string.
   *
   * Your fee-bump amount should be `>= 10x` the original fee.
   * @see  https://developers.stellar.org/docs/glossary/fee-bumps/#replace-by-fee
   */
  static buildFeeBumpTransaction(feeSource, baseFee, innerTx, networkPassphrase) {
    const innerOps = innerTx.operations.length;
    const minBaseFee = new bignumber.default(BASE_FEE);
    let resourceFee = new bignumber.default(0);
    const env = innerTx.toEnvelope();
    switch (env.switch().value) {
      case curr_generated.default.EnvelopeType.envelopeTypeTx().value: {
        const sorobanData = env.v1().tx().ext().value();
        resourceFee = new bignumber.default(sorobanData?.resourceFee().toString() ?? 0);
        break;
      }
    }
    const innerInclusionFee = new bignumber.default(innerTx.fee).minus(resourceFee).div(innerOps);
    const base = new bignumber.default(baseFee);
    if (base.lt(innerInclusionFee)) {
      throw new Error(
        `Invalid baseFee, it should be at least ${innerInclusionFee.toString()} stroops.`
      );
    }
    if (base.lt(minBaseFee)) {
      throw new Error(
        `Invalid baseFee, it should be at least ${minBaseFee.toString()} stroops.`
      );
    }
    let innerTxEnvelope = innerTx.toEnvelope();
    if (innerTxEnvelope.switch() === curr_generated.default.EnvelopeType.envelopeTypeTxV0()) {
      const v0Tx = innerTxEnvelope.v0().tx();
      const v0TimeBounds = v0Tx.timeBounds();
      if (v0TimeBounds === null) {
        throw new Error("Inner transaction must have time bounds");
      }
      const v1Tx = new curr_generated.default.Transaction({
        sourceAccount: curr_generated.default.MuxedAccount.keyTypeEd25519(
          v0Tx.sourceAccountEd25519()
        ),
        fee: v0Tx.fee(),
        seqNum: v0Tx.seqNum(),
        cond: curr_generated.default.Preconditions.precondTime(v0TimeBounds),
        memo: v0Tx.memo(),
        operations: v0Tx.operations(),
        ext: new curr_generated.default.TransactionExt(0)
      });
      innerTxEnvelope = curr_generated.default.TransactionEnvelope.envelopeTypeTx(
        new curr_generated.default.TransactionV1Envelope({
          tx: v1Tx,
          signatures: innerTxEnvelope.v0().signatures()
        })
      );
    }
    let feeSourceAccount;
    if (typeof feeSource === "string") {
      feeSourceAccount = decode_encode_muxed_account.decodeAddressToMuxedAccount(feeSource);
    } else {
      feeSourceAccount = feeSource.xdrMuxedAccount();
    }
    const tx = new curr_generated.default.FeeBumpTransaction({
      feeSource: feeSourceAccount,
      fee: curr_generated.default.Int64.fromString(
        base.times(innerOps + 1).plus(resourceFee).toString()
      ),
      innerTx: curr_generated.default.FeeBumpTransactionInnerTx.envelopeTypeTx(
        innerTxEnvelope.v1()
      ),
      ext: new curr_generated.default.FeeBumpTransactionExt(0)
    });
    const feeBumpTxEnvelope = new curr_generated.default.FeeBumpTransactionEnvelope({
      tx,
      signatures: []
    });
    const envelope = curr_generated.default.TransactionEnvelope.envelopeTypeTxFeeBump(feeBumpTxEnvelope);
    return new fee_bump_transaction.FeeBumpTransaction(envelope, networkPassphrase);
  }
  /**
   * Build a {@link Transaction} or {@link FeeBumpTransaction} from an
   * xdr.TransactionEnvelope.
   *
   * @param envelope - The transaction envelope
   *     object or base64 encoded string.
   * @param networkPassphrase - The network passphrase of the target
   *     Stellar network (e.g. "Public Global Stellar Network ; September
   *     2015"), see {@link Networks}.
   */
  static fromXDR(envelope, networkPassphrase) {
    if (typeof envelope === "string") {
      envelope = curr_generated.default.TransactionEnvelope.fromXDR(envelope, "base64");
    }
    if (envelope.switch() === curr_generated.default.EnvelopeType.envelopeTypeTxFeeBump()) {
      return new fee_bump_transaction.FeeBumpTransaction(envelope, networkPassphrase);
    }
    return new transaction.Transaction(envelope, networkPassphrase);
  }
}
function isValidDate(d) {
  return d instanceof Date && !Number.isNaN(d.getTime());
}
function toEpochSeconds(value) {
  if (value === void 0) {
    return void 0;
  }
  const num = value instanceof Date ? Math.floor(value.getTime() / 1e3) : Number(value);
  if (!Number.isFinite(num) || num % 1 !== 0) {
    throw new Error("timebounds value must be a finite integer or Date");
  }
  return num;
}

exports.BASE_FEE = BASE_FEE;
exports.TimeoutInfinite = TimeoutInfinite;
exports.TransactionBuilder = TransactionBuilder;
exports.isValidDate = isValidDate;
//# sourceMappingURL=transaction_builder.js.map
