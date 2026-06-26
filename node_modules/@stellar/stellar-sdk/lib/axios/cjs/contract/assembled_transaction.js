'use strict';

var buffer = require('buffer');
require('../node_modules/.pnpm/@stellar_js-xdr@4.0.0/node_modules/@stellar/js-xdr/src/int.js');
require('../node_modules/.pnpm/@stellar_js-xdr@4.0.0/node_modules/@stellar/js-xdr/src/hyper.js');
require('../node_modules/.pnpm/@stellar_js-xdr@4.0.0/node_modules/@stellar/js-xdr/src/unsigned-int.js');
require('../node_modules/.pnpm/@stellar_js-xdr@4.0.0/node_modules/@stellar/js-xdr/src/unsigned-hyper.js');
require('../node_modules/.pnpm/@stellar_js-xdr@4.0.0/node_modules/@stellar/js-xdr/src/xdr-type.js');
var curr_generated = require('../base/generated/curr_generated.js');
require('@noble/hashes/sha2.js');
require('../base/signing.js');
require('../base/keypair.js');
require('base32.js');
var operation = require('../base/operation.js');
require('../base/util/bignumber.js');
var transaction_builder = require('../base/transaction_builder.js');
require('../base/muxed_account.js');
var contract = require('../base/contract.js');
var address = require('../base/address.js');
require('../base/scval.js');
var sorobandata_builder = require('../base/sorobandata_builder.js');
var auth = require('../base/auth.js');
require('../base/numbers/uint128.js');
require('../base/numbers/uint256.js');
require('../base/numbers/int128.js');
require('../base/numbers/int256.js');
var api = require('../rpc/api.js');
var server = require('../rpc/server.js');
var transaction = require('../rpc/transaction.js');
var rust_result = require('./rust_result.js');
var utils = require('./utils.js');
var types = require('./types.js');
var sent_transaction = require('./sent_transaction.js');
var errors = require('./errors.js');

class AssembledTransaction {
  constructor(options) {
    this.options = options;
    this.options.simulate = this.options.simulate ?? true;
    const { server: server$1, allowHttp, headers, rpcUrl } = this.options;
    this.server = server$1 ?? new server.RpcServer(rpcUrl, { allowHttp, headers });
  }
  options;
  /**
   * The TransactionBuilder as constructed in
   * {@link AssembledTransaction}.build. Feel free set `simulate: false` to modify
   * this object before calling `tx.simulate()` manually. Example:
   *
   * ```ts
   * const tx = await myContract.myMethod(
   *   { args: 'for', my: 'method', ... },
   *   { simulate: false }
   * );
   * tx.raw.addMemo(Memo.text('Nice memo, friend!'))
   * await tx.simulate();
   * ```
   */
  raw;
  /**
   * Stores the original operation from `buildWithOp` for reuse during
   * automatic state restoration rebuilds.
   */
  originalOp;
  /**
   * The Transaction as it was built with `raw.build()` right before
   * simulation. Once this is set, modifying `raw` will have no effect unless
   * you call `tx.simulate()` again.
   */
  built;
  /**
   * The result of the transaction simulation. This is set after the first call
   * to `simulate`. It is difficult to serialize and deserialize, so it is not
   * included in the `toJSON` and `fromJSON` methods. See `simulationData`
   * cached, serializable access to the data needed by AssembledTransaction
   * logic.
   */
  simulation;
  /**
   * Cached simulation result. This is set after the first call to
   * {@link AssembledTransaction.simulationData}, and is used to facilitate
   * serialization and deserialization of the AssembledTransaction.
   *
   * Most of the time, if you need this data, you can call
   * `tx.simulation.result`.
   *
   * If you need access to this data after a transaction has been serialized
   * and then deserialized, you can call `simulationData.result`.
   */
  simulationResult;
  /**
   * Cached simulation transaction data. This is set after the first call to
   * {@link AssembledTransaction.simulationData}, and is used to facilitate
   * serialization and deserialization of the AssembledTransaction.
   *
   * Most of the time, if you need this data, you can call
   * `simulation.transactionData`.
   *
   * If you need access to this data after a transaction has been serialized
   * and then deserialized, you can call `simulationData.transactionData`.
   */
  simulationTransactionData;
  /**
   * The Soroban server to use for all RPC calls. This is constructed from the
   * `rpcUrl` in the options.
   */
  server;
  /**
   * The signed transaction.
   */
  signed;
  /**
   * A list of the most important errors that various AssembledTransaction
   * methods can throw. Feel free to catch specific errors in your application
   * logic.
   */
  static Errors = {
    ExpiredState: errors.ExpiredStateError,
    RestorationFailure: errors.RestoreFailureError,
    NeedsMoreSignatures: errors.NeedsMoreSignaturesError,
    NoSignatureNeeded: errors.NoSignatureNeededError,
    NoUnsignedNonInvokerAuthEntries: errors.NoUnsignedNonInvokerAuthEntriesError,
    NoSigner: errors.NoSignerError,
    NotYetSimulated: errors.NotYetSimulatedError,
    FakeAccount: errors.FakeAccountError,
    SimulationFailed: errors.SimulationFailedError,
    InternalWalletError: errors.InternalWalletError,
    ExternalServiceError: errors.ExternalServiceError,
    InvalidClientRequest: errors.InvalidClientRequestError,
    UserRejected: errors.UserRejectedError
  };
  /**
   * Serialize the AssembledTransaction to a JSON string. This is useful for
   * saving the transaction to a database or sending it over the wire for
   * multi-auth workflows. `fromJSON` can be used to deserialize the
   * transaction. This only works with transactions that have been simulated.
   */
  toJSON() {
    return JSON.stringify({
      method: this.options.method,
      tx: this.built?.toXDR(),
      simulationResult: {
        auth: this.simulationData.result.auth.map((a) => a.toXDR("base64")),
        retval: this.simulationData.result.retval.toXDR("base64")
      },
      simulationTransactionData: this.simulationData.transactionData.toXDR("base64")
    });
  }
  /**
   * Validate that a built transaction is a single invokeContract operation
   * targeting the expected contract, and return the parsed InvokeContractArgs.
   */
  static validateInvokeContractOp(built, expectedContractId) {
    if (built.operations.length !== 1) {
      throw new Error(
        "Transaction envelope must contain exactly one operation."
      );
    }
    const operation = built.operations[0];
    if (operation.type !== "invokeHostFunction") {
      throw new Error(
        "Transaction envelope does not contain an invokeHostFunction operation."
      );
    }
    const invokeOp = operation;
    if (invokeOp.func.switch().name !== "hostFunctionTypeInvokeContract") {
      throw new Error(
        "Transaction envelope does not contain an invokeContract host function."
      );
    }
    const invokeContractArgs = invokeOp.func.value();
    let contractAddress;
    let functionName;
    try {
      contractAddress = invokeContractArgs.contractAddress();
      functionName = invokeContractArgs.functionName().toString("utf-8");
    } catch {
      throw new Error(
        "Could not extract contract address or method name from the transaction envelope."
      );
    }
    if (!contractAddress || !functionName) {
      throw new Error(
        "Could not extract contract address or method name from the transaction envelope."
      );
    }
    const xdrContractId = address.Address.fromScAddress(contractAddress).toString();
    if (xdrContractId !== expectedContractId) {
      throw new Error(
        `Transaction envelope targets contract ${xdrContractId}, but this Client is configured for ${expectedContractId}.`
      );
    }
    return invokeContractArgs;
  }
  static fromJSON(options, {
    tx,
    simulationResult,
    simulationTransactionData
  }) {
    const txn = new AssembledTransaction(options);
    txn.built = transaction_builder.TransactionBuilder.fromXDR(tx, options.networkPassphrase);
    const invokeContractArgs = AssembledTransaction.validateInvokeContractOp(
      txn.built,
      options.contractId
    );
    const xdrMethod = invokeContractArgs.functionName().toString("utf-8");
    if (xdrMethod !== options.method) {
      throw new Error(
        `Transaction envelope calls method '${xdrMethod}', but the provided method is '${options.method}'.`
      );
    }
    txn.simulationResult = {
      auth: simulationResult.auth.map(
        (a) => curr_generated.default.SorobanAuthorizationEntry.fromXDR(a, "base64")
      ),
      retval: curr_generated.default.ScVal.fromXDR(simulationResult.retval, "base64")
    };
    txn.simulationTransactionData = curr_generated.default.SorobanTransactionData.fromXDR(
      simulationTransactionData,
      "base64"
    );
    return txn;
  }
  /**
   * Serialize the AssembledTransaction to a base64-encoded XDR string.
   */
  toXDR() {
    if (!this.built)
      throw new Error(
        "Transaction has not yet been simulated; call `AssembledTransaction.simulate` first."
      );
    return this.built?.toEnvelope().toXDR("base64");
  }
  /**
   * Deserialize the AssembledTransaction from a base64-encoded XDR string.
   */
  static fromXDR(options, encodedXDR, spec) {
    const envelope = curr_generated.default.TransactionEnvelope.fromXDR(encodedXDR, "base64");
    const built = transaction_builder.TransactionBuilder.fromXDR(
      envelope,
      options.networkPassphrase
    );
    const invokeContractArgs = AssembledTransaction.validateInvokeContractOp(
      built,
      options.contractId
    );
    const method = invokeContractArgs.functionName().toString("utf-8");
    const txn = new AssembledTransaction({
      ...options,
      method,
      parseResultXdr: (result) => spec.funcResToNative(method, result)
    });
    txn.built = built;
    return txn;
  }
  handleWalletError(error) {
    if (!error) return;
    const { message, code } = error;
    const fullMessage = `${message}${error.ext ? ` (${error.ext.join(", ")})` : ""}`;
    switch (code) {
      case -1:
        throw new AssembledTransaction.Errors.InternalWalletError(fullMessage);
      case -2:
        throw new AssembledTransaction.Errors.ExternalServiceError(fullMessage);
      case -3:
        throw new AssembledTransaction.Errors.InvalidClientRequest(fullMessage);
      case -4:
        throw new AssembledTransaction.Errors.UserRejected(fullMessage);
      default:
        throw new Error(`Unhandled error: ${fullMessage}`);
    }
  }
  /**
   * Construct a new AssembledTransaction. This is the main way to create a new
   * AssembledTransaction; the constructor is private.
   *
   * This is an asynchronous constructor for two reasons:
   *
   * 1. It needs to fetch the account from the network to get the current
   *   sequence number.
   * 2. It needs to simulate the transaction to get the expected fee.
   *
   * If you don't want to simulate the transaction, you can set `simulate` to
   * `false` in the options.
   *
   * If you need to create an operation other than `invokeHostFunction`, you
   * can use {@link AssembledTransaction.buildWithOp} instead.
   *
   * @example
   * ```ts
   * const tx = await AssembledTransaction.build({
   *   ...,
   *   simulate: false,
   * })
   * ```
   */
  static build(options) {
    const contract$1 = new contract.Contract(options.contractId);
    return AssembledTransaction.buildWithOp(
      contract$1.call(options.method, ...options.args ?? []),
      options
    );
  }
  /**
   * Construct a new AssembledTransaction, specifying an Operation other than
   * `invokeHostFunction` (the default used by {@link AssembledTransaction.build}).
   *
   * Note: `AssembledTransaction` currently assumes these operations can be
   * simulated. This is not true for classic operations; only for those used by
   * Soroban Smart Contracts like `invokeHostFunction` and `createCustomContract`.
   *
   * @example
   * ```ts
   * const tx = await AssembledTransaction.buildWithOp(
   *   Operation.createCustomContract({ ... });
   *   {
   *     ...,
   *     simulate: false,
   *   }
   * )
   * ```
   */
  static async buildWithOp(operation, options) {
    const tx = new AssembledTransaction(options);
    tx.originalOp = operation;
    const account = await utils.getAccount(options, tx.server);
    tx.raw = new transaction_builder.TransactionBuilder(account, {
      fee: options.fee ?? transaction_builder.BASE_FEE,
      networkPassphrase: options.networkPassphrase
    }).setTimeout(options.timeoutInSeconds ?? types.DEFAULT_TIMEOUT).addOperation(operation);
    if (options.simulate) await tx.simulate();
    return tx;
  }
  static async buildFootprintRestoreTransaction(options, sorobanData, account, fee) {
    const tx = new AssembledTransaction(options);
    tx.raw = new transaction_builder.TransactionBuilder(account, {
      fee,
      networkPassphrase: options.networkPassphrase
    }).setSorobanData(
      sorobanData instanceof sorobandata_builder.SorobanDataBuilder ? sorobanData.build() : sorobanData
    ).addOperation(operation.Operation.restoreFootprint({})).setTimeout(options.timeoutInSeconds ?? types.DEFAULT_TIMEOUT);
    await tx.simulate({ restore: false });
    return tx;
  }
  simulate = async ({ restore } = {}) => {
    if (!this.built) {
      if (!this.raw) {
        throw new Error(
          "Transaction has not yet been assembled; call `AssembledTransaction.build` first."
        );
      }
      this.built = this.raw.build();
    }
    restore = restore ?? this.options.restore;
    delete this.simulationResult;
    delete this.simulationTransactionData;
    this.simulation = await this.server.simulateTransaction(this.built);
    if (restore && api.Api.isSimulationRestore(this.simulation)) {
      const account = await utils.getAccount(this.options, this.server);
      const result = await this.restoreFootprint(
        this.simulation.restorePreamble,
        account
      );
      if (result.status === api.Api.GetTransactionStatus.SUCCESS) {
        const op = this.originalOp ? this.originalOp : new contract.Contract(this.options.contractId).call(
          this.options.method,
          ...this.options.args ?? []
        );
        this.raw = new transaction_builder.TransactionBuilder(account, {
          fee: this.options.fee ?? transaction_builder.BASE_FEE,
          networkPassphrase: this.options.networkPassphrase
        }).addOperation(op).setTimeout(this.options.timeoutInSeconds ?? types.DEFAULT_TIMEOUT);
        delete this.built;
        await this.simulate();
        return this;
      }
      throw new AssembledTransaction.Errors.RestorationFailure(
        `Automatic restore failed! You set 'restore: true' but the attempted restore did not work. Result:
${JSON.stringify(result)}`
      );
    }
    if (api.Api.isSimulationSuccess(this.simulation)) {
      this.built = transaction.assembleTransaction(this.built, this.simulation).build();
    }
    return this;
  };
  get simulationData() {
    if (this.simulationResult && this.simulationTransactionData) {
      return {
        result: this.simulationResult,
        transactionData: this.simulationTransactionData
      };
    }
    const simulation = this.simulation;
    if (!simulation) {
      throw new AssembledTransaction.Errors.NotYetSimulated(
        "Transaction has not yet been simulated"
      );
    }
    if (api.Api.isSimulationError(simulation)) {
      throw new AssembledTransaction.Errors.SimulationFailed(
        `Transaction simulation failed: "${simulation.error}"`
      );
    }
    if (api.Api.isSimulationRestore(simulation)) {
      throw new AssembledTransaction.Errors.ExpiredState(
        `You need to restore some contract state before you can invoke this method.
You can set \`restore\` to true in the method options in order to automatically restore the contract state when needed.`
      );
    }
    this.simulationResult = simulation.result ?? {
      auth: [],
      retval: curr_generated.default.ScVal.scvVoid()
    };
    this.simulationTransactionData = simulation.transactionData.build();
    return {
      result: this.simulationResult,
      transactionData: this.simulationTransactionData
    };
  }
  get result() {
    try {
      if (!this.simulationData.result) {
        throw new Error("No simulation result!");
      }
      return this.options.parseResultXdr(this.simulationData.result.retval);
    } catch (e) {
      if (!utils.implementsToString(e)) throw e;
      const err = this.parseError(e.toString());
      if (err) return err;
      throw e;
    }
  }
  parseError(errorMessage) {
    if (!this.options.errorTypes) return void 0;
    const match = errorMessage.match(utils.contractErrorPattern);
    if (!match) return void 0;
    const i = parseInt(match[1], 10);
    const err = this.options.errorTypes[i];
    if (!err) return void 0;
    return new rust_result.Err(err);
  }
  /**
   * Sign the transaction with the signTransaction function included previously.
   * If you did not previously include one, you need to include one now.
   */
  sign = async ({
    force = false,
    signTransaction = this.options.signTransaction
  } = {}) => {
    if (!this.built) {
      throw new Error("Transaction has not yet been simulated");
    }
    if (!force && this.isReadCall) {
      throw new AssembledTransaction.Errors.NoSignatureNeeded(
        "This is a read call. It requires no signature or sending. Use `force: true` to sign and send anyway."
      );
    }
    if (!signTransaction) {
      throw new AssembledTransaction.Errors.NoSigner(
        "You must provide a signTransaction function, either when calling `signAndSend` or when initializing your Client"
      );
    }
    if (!this.options.publicKey) {
      throw new AssembledTransaction.Errors.FakeAccount(
        "This transaction was constructed using a default account. Provide a valid publicKey in the AssembledTransactionOptions."
      );
    }
    const sigsNeeded = this.needsNonInvokerSigningBy().filter(
      (id) => !id.startsWith("C")
    );
    if (sigsNeeded.length) {
      throw new AssembledTransaction.Errors.NeedsMoreSignatures(
        `Transaction requires signatures from ${sigsNeeded}. See \`needsNonInvokerSigningBy\` for details.`
      );
    }
    const timeoutInSeconds = this.options.timeoutInSeconds ?? types.DEFAULT_TIMEOUT;
    this.built = transaction_builder.TransactionBuilder.cloneFrom(this.built, {
      fee: this.built.fee,
      timebounds: void 0,
      sorobanData: this.simulationData.transactionData
    }).setTimeout(timeoutInSeconds).build();
    const signOpts = {
      networkPassphrase: this.options.networkPassphrase
    };
    if (this.options.address) signOpts.address = this.options.address;
    if (this.options.submit !== void 0)
      signOpts.submit = this.options.submit;
    if (this.options.submitUrl) signOpts.submitUrl = this.options.submitUrl;
    const { signedTxXdr: signature, error } = await signTransaction(
      this.built.toXDR(),
      signOpts
    );
    this.handleWalletError(error);
    this.signed = transaction_builder.TransactionBuilder.fromXDR(
      signature,
      this.options.networkPassphrase
    );
  };
  /**
   * Sends the transaction to the network to return a `SentTransaction` that
   * keeps track of all the attempts to fetch the transaction. Optionally pass
   * a {@link Watcher} that allows you to keep track of the progress as the
   * transaction is sent and processed.
   */
  async send(watcher) {
    if (!this.signed) {
      throw new Error(
        "The transaction has not yet been signed. Run `sign` first, or use `signAndSend` instead."
      );
    }
    const sent = await sent_transaction.SentTransaction.init(this, watcher);
    return sent;
  }
  /**
   * Sign the transaction with the `signTransaction` function included previously.
   * If you did not previously include one, you need to include one now.
   * After signing, this method will send the transaction to the network and
   * return a `SentTransaction` that keeps track of all the attempts to fetch
   * the transaction. You may pass a {@link Watcher} to keep
   * track of this progress.
   */
  signAndSend = async ({
    force = false,
    signTransaction = this.options.signTransaction,
    watcher
  } = {}) => {
    if (!this.signed) {
      const signer = signTransaction || this.options.signTransaction;
      const wrappedSignTransaction = this.options.submit && signer ? (tx, opts) => signer(tx, { ...opts, submit: false }) : signTransaction;
      await this.sign({ force, signTransaction: wrappedSignTransaction });
    }
    return this.send(watcher);
  };
  /**
   * Get a list of accounts, other than the invoker of the simulation, that
   * need to sign auth entries in this transaction.
   *
   * Soroban allows multiple people to sign a transaction. Someone needs to
   * sign the final transaction envelope; this person/account is called the
   * _invoker_, or _source_. Other accounts might need to sign individual auth
   * entries in the transaction, if they're not also the invoker.
   *
   * This function returns a list of accounts that need to sign auth entries,
   * assuming that the same invoker/source account will sign the final
   * transaction envelope as signed the initial simulation.
   *
   * One at a time, for each public key in this array, you will need to
   * serialize this transaction with `toJSON`, send to the owner of that key,
   * deserialize the transaction with `txFromJson`, and call
   * {@link AssembledTransaction.signAuthEntries}. Then re-serialize and send to
   * the next account in this list.
   */
  needsNonInvokerSigningBy = ({
    includeAlreadySigned = false
  } = {}) => {
    if (!this.built) {
      throw new Error("Transaction has not yet been simulated");
    }
    if (!("operations" in this.built)) {
      throw new Error(
        `Unexpected Transaction type; no operations: ${JSON.stringify(
          this.built
        )}`
      );
    }
    const rawInvokeHostFunctionOp = this.built.operations[0];
    return [
      ...new Set(
        (rawInvokeHostFunctionOp.auth ?? []).map((entry) => auth.getAddressCredentials(entry.credentials())).filter(
          (addrAuth) => (
            // skip source-account credentials (no address payload), which
            // are covered by the envelope signature on the source account
            addrAuth !== null && (includeAlreadySigned || addrAuth.signature().switch().name === "scvVoid")
          )
        ).map(
          (addrAuth) => address.Address.fromScAddress(addrAuth.address()).toString()
        )
      )
    ];
  };
  /**
   * If {@link AssembledTransaction.needsNonInvokerSigningBy} returns a
   * non-empty list, you can serialize the transaction with `toJSON`, send it to
   * the owner of one of the public keys in the map, deserialize with
   * `txFromJSON`, and call this method on their machine. Internally, this will
   * use `signAuthEntry` function from connected `wallet` for each.
   *
   * Then, re-serialize the transaction and either send to the next
   * `needsNonInvokerSigningBy` owner, or send it back to the original account
   * who simulated the transaction so they can {@link AssembledTransaction.sign}
   * the transaction envelope and {@link AssembledTransaction.send} it to the
   * network.
   *
   * Sending to all `needsNonInvokerSigningBy` owners in parallel is not
   * currently supported!
   */
  signAuthEntries = async ({
    expiration = (async () => (await this.server.getLatestLedger()).sequence + 100)(),
    signAuthEntry = this.options.signAuthEntry,
    address: address$1 = this.options.publicKey,
    authorizeEntry = auth.authorizeEntry
  } = {}) => {
    if (!this.built)
      throw new Error("Transaction has not yet been assembled or simulated");
    if (authorizeEntry === auth.authorizeEntry) {
      const needsNonInvokerSigningBy = this.needsNonInvokerSigningBy();
      if (needsNonInvokerSigningBy.length === 0) {
        throw new AssembledTransaction.Errors.NoUnsignedNonInvokerAuthEntries(
          "No unsigned non-invoker auth entries; maybe you already signed?"
        );
      }
      if (needsNonInvokerSigningBy.indexOf(address$1 ?? "") === -1) {
        throw new AssembledTransaction.Errors.NoSignatureNeeded(
          `No auth entries for public key "${address$1}"`
        );
      }
      if (!signAuthEntry) {
        throw new AssembledTransaction.Errors.NoSigner(
          "You must provide `signAuthEntry` or a custom `authorizeEntry`"
        );
      }
    }
    const rawInvokeHostFunctionOp = this.built.operations[0];
    const authEntries = rawInvokeHostFunctionOp.auth ?? [];
    for (const [i, entry] of authEntries.entries()) {
      const credentials = curr_generated.default.SorobanCredentials.fromXDR(
        entry.credentials().toXDR()
      );
      const addrAuth = auth.getAddressCredentials(credentials);
      if (addrAuth === null) {
        continue;
      }
      const authEntryAddress = address.Address.fromScAddress(
        addrAuth.address()
      ).toString();
      if (authEntryAddress !== address$1) continue;
      const sign = signAuthEntry ?? Promise.resolve;
      authEntries[i] = await authorizeEntry(
        entry,
        async (preimage) => {
          const { signedAuthEntry, error } = await sign(
            preimage.toXDR("base64"),
            {
              address: address$1
            }
          );
          this.handleWalletError(error);
          return buffer.Buffer.from(signedAuthEntry, "base64");
        },
        await expiration,
        this.options.networkPassphrase
      );
    }
  };
  /**
   * Whether this transaction is a read call. This is determined by the
   * simulation result and the transaction data. If the transaction is a read
   * call, it will not need to be signed and sent to the network. If this
   * returns `false`, then you need to call `signAndSend` on this transaction.
   */
  get isReadCall() {
    const authsCount = this.simulationData.result.auth.length;
    const writeLength = this.simulationData.transactionData.resources().footprint().readWrite().length;
    return authsCount === 0 && writeLength === 0;
  }
  /**
   * Restores the footprint (resource ledger entries that can be read or written)
   * of an expired transaction.
   *
   * The method will:
   * 1. Build a new transaction aimed at restoring the necessary resources.
   * 2. Sign this new transaction if a `signTransaction` handler is provided.
   * 3. Send the signed transaction to the network.
   * 4. Await and return the response from the network.
   *
   * Preconditions:
   * - A `signTransaction` function must be provided during the Client initialization.
   * - The provided `restorePreamble` should include a minimum resource fee and valid
   *   transaction data.
   *
   * @throws - Throws an error if no `signTransaction` function is provided during
   * Client initialization.
   * @throws - Throws a custom error if the
   * restore transaction fails, providing the details of the failure.
   */
  async restoreFootprint(restorePreamble, account) {
    if (!this.options.signTransaction) {
      throw new Error(
        "For automatic restore to work you must provide a signTransaction function when initializing your Client"
      );
    }
    account = account ?? await utils.getAccount(this.options, this.server);
    const restoreTx = await AssembledTransaction.buildFootprintRestoreTransaction(
      { ...this.options },
      restorePreamble.transactionData,
      account,
      restorePreamble.minResourceFee
    );
    const sentTransaction = await restoreTx.signAndSend();
    if (!sentTransaction.getTransactionResponse) {
      throw new AssembledTransaction.Errors.RestorationFailure(
        `The attempt at automatic restore failed. 
${JSON.stringify(sentTransaction)}`
      );
    }
    return sentTransaction.getTransactionResponse;
  }
}

exports.AssembledTransaction = AssembledTransaction;
//# sourceMappingURL=assembled_transaction.js.map
