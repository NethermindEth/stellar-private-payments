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
var keypair = require('../base/keypair.js');
var strkey = require('../base/strkey.js');
require('../base/util/continued_fraction.js');
require('../base/util/bignumber.js');
var address = require('../base/address.js');
require('../base/transaction_builder.js');
var account = require('../base/account.js');
require('../base/muxed_account.js');
var contract = require('../base/contract.js');
var scval = require('../base/scval.js');
require('../base/numbers/uint128.js');
require('../base/numbers/uint256.js');
require('../base/numbers/int128.js');
require('../base/numbers/int256.js');
var axios = require('./axios.js');
var jsonrpc = require('./jsonrpc.js');
var api = require('./api.js');
var transaction = require('./transaction.js');
var parsers = require('./parsers.js');
var utils = require('../utils.js');

var Durability = /* @__PURE__ */ ((Durability2) => {
  Durability2["Temporary"] = "temporary";
  Durability2["Persistent"] = "persistent";
  return Durability2;
})(Durability || {});
const DEFAULT_GET_TRANSACTION_TIMEOUT = 30;
const BasicSleepStrategy = (_iter) => 1e3;
const LinearSleepStrategy = (iter) => 1e3 * iter;
function findCreatedAccountSequenceInTransactionMeta(meta) {
  let operations = [];
  switch (meta.switch()) {
    case 0:
      operations = meta.operations();
      break;
    case 1:
    case 2:
    case 3:
    case 4:
      operations = meta.value().operations();
      break;
    default:
      throw new Error("Unexpected transaction meta switch value");
  }
  const sequenceNumber = operations.flatMap((op) => op.changes()).find(
    (c) => c.switch() === curr_generated.default.LedgerEntryChangeType.ledgerEntryCreated() && c.created().data().switch() === curr_generated.default.LedgerEntryType.account()
  )?.created()?.data()?.account()?.seqNum()?.toString();
  if (sequenceNumber) {
    return sequenceNumber;
  }
  throw new Error("No account created in transaction");
}
class RpcServer {
  serverURL;
  /**
   * HTTP client instance for making requests to Horizon.
   * Exposes interceptors, defaults, and other configuration options.
   *
   * @example
   * ```ts
   * // Add authentication header
   * server.httpClient.defaults.headers['Authorization'] = 'Bearer token';
   *
   * // Add request interceptor
   * server.httpClient.interceptors.request.use((config) => {
   *   console.log('Request:', config.url);
   *   return config;
   * });
   * ```
   */
  httpClient;
  constructor(serverURL, opts = {}) {
    this.serverURL = new URL(serverURL);
    this.httpClient = axios.createHttpClient(opts.headers);
    if (this.serverURL.protocol !== "https:" && !opts.allowHttp) {
      throw new Error(
        "Cannot connect to insecure Soroban RPC server if `allowHttp` isn't set"
      );
    }
  }
  /**
   * Fetch a minimal set of current info about a Stellar account.
   *
   * Needed to get the current sequence number for the account so you can build
   * a successful transaction with {@link TransactionBuilder}.
   *
   * @param address - The public address of the account to load.
   * @returns A promise which resolves to the {@link Account}
   * object with a populated sequence number
   *
   * @see {@link https://developers.stellar.org/docs/data/rpc/api-reference/methods/getLedgerEntries | getLedgerEntries docs}
   *
   * @example
   * ```ts
   * const accountId = "GBZC6Y2Y7Q3ZQ2Y4QZJ2XZ3Z5YXZ6Z7Z2Y4QZJ2XZ3Z5YXZ6Z7Z2Y4";
   * server.getAccount(accountId).then((account) => {
   *   console.log("sequence:", account.sequence);
   * });
   * ```
   */
  async getAccount(address) {
    const entry = await this.getAccountEntry(address);
    return new account.Account(address, entry.seqNum().toString());
  }
  /**
   * Fetch the full account entry for a Stellar account.
   *
   * @param address - The public address of the account to load.
   * @returns Resolves to the full on-chain account
   *    entry
   *
   * @see
   * {@link https://developers.stellar.org/docs/data/rpc/api-reference/methods/getLedgerEntries | getLedgerEntries docs}
   *
   * @example
   * ```ts
   * const accountId = "GBZC6Y2Y7Q3ZQ2Y4QZJ2XZ3Z5YXZ6Z7Z2Y4QZJ2XZ3Z5YXZ6Z7Z2Y4";
   * server.getAccountEntry(accountId).then((account) => {
   *   console.log("sequence:", account.balance().toString());
   * });
   * ```
   */
  async getAccountEntry(address) {
    const ledgerKey = curr_generated.default.LedgerKey.account(
      new curr_generated.default.LedgerKeyAccount({
        accountId: keypair.Keypair.fromPublicKey(address).xdrPublicKey()
      })
    );
    try {
      const resp = await this.getLedgerEntry(ledgerKey);
      return resp.val.account();
    } catch {
      throw new Error(`Account not found: ${address}`);
    }
  }
  /**
   * Fetch the full trustline entry for a Stellar account.
   *
   * @param account - The public address of the account whose trustline it is
   * @param asset - The trustline's asset
   * @returns Resolves to the full on-chain trustline
   *    entry
   *
   * @see
   * {@link https://developers.stellar.org/docs/data/rpc/api-reference/methods/getLedgerEntries | getLedgerEntries docs}
   *
   * @deprecated Use {@link getAssetBalance}, instead
   * @example
   * ```ts
   * const accountId = "GBZC6Y2Y7Q3ZQ2Y4QZJ2XZ3Z5YXZ6Z7Z2Y4QZJ2XZ3Z5YXZ6Z7Z2Y4";
   * const asset = new Asset(
   *  "USDC",
   *  "GBBD47IF6LWK7P7MDEVSCWR7DPUWV3NY3DTQEVFL4NAT4AQH3ZLLFLA5"
   * );
   * server.getTrustline(accountId, asset).then((entry) => {
   *   console.log(`{asset.toString()} balance for ${accountId}:", entry.balance().toString());
   * });
   * ```
   */
  async getTrustline(account, asset) {
    const trustlineLedgerKey = curr_generated.default.LedgerKey.trustline(
      new curr_generated.default.LedgerKeyTrustLine({
        accountId: keypair.Keypair.fromPublicKey(account).xdrAccountId(),
        asset: asset.toTrustLineXDRObject()
      })
    );
    try {
      const entry = await this.getLedgerEntry(trustlineLedgerKey);
      return entry.val.trustLine();
    } catch {
      throw new Error(
        `Trustline for ${asset.getCode()}:${asset.getIssuer()} not found for ${account}`
      );
    }
  }
  /**
   * Fetch the full claimable balance entry for a Stellar account.
   *
   * @param id - The strkey (`B...`) or hex (`00000000abcde...`) (both
   *    IDs with and without the 000... version prefix are accepted) of the
   *    claimable balance to load
   * @returns Resolves to the full on-chain
   *    claimable balance entry
   *
   * @see
   * {@link https://developers.stellar.org/docs/data/rpc/api-reference/methods/getLedgerEntries | getLedgerEntries docs}
   *
   * @example
   * ```ts
   * const id = "00000000178826fbfe339e1f5c53417c6fedfe2c05e8bec14303143ec46b38981b09c3f9";
   * server.getClaimableBalance(id).then((entry) => {
   *   console.log(`Claimable balance {id.substr(0, 12)} has:`);
   *   console.log(`  asset:  ${Asset.fromXDRObject(entry.asset()).toString()}`;
   *   console.log(`  amount: ${entry.amount().toString()}`;
   * });
   * ```
   */
  async getClaimableBalance(id) {
    let balanceId;
    if (strkey.StrKey.isValidClaimableBalance(id)) {
      const buffer$1 = strkey.StrKey.decodeClaimableBalance(id);
      const v = buffer.Buffer.concat([
        buffer.Buffer.from("\0\0\0"),
        buffer$1.subarray(0, 1)
      ]);
      balanceId = curr_generated.default.ClaimableBalanceId.fromXDR(
        buffer.Buffer.concat([v, buffer$1.subarray(1)])
      );
    } else if (id.match(/[a-f0-9]{72}/i)) {
      balanceId = curr_generated.default.ClaimableBalanceId.fromXDR(id, "hex");
    } else if (id.match(/[a-f0-9]{64}/i)) {
      balanceId = curr_generated.default.ClaimableBalanceId.fromXDR(id.padStart(72, "0"), "hex");
    } else {
      throw new TypeError(`expected 72-char hex ID or strkey, not ${id}`);
    }
    const trustlineLedgerKey = curr_generated.default.LedgerKey.claimableBalance(
      new curr_generated.default.LedgerKeyClaimableBalance({ balanceId })
    );
    try {
      const entry = await this.getLedgerEntry(trustlineLedgerKey);
      return entry.val.claimableBalance();
    } catch {
      throw new Error(`Claimable balance ${id} not found`);
    }
  }
  /**
   * Fetch the balance of an asset held by an account or contract.
   *
   * The `address` argument may be provided as a string (as a {@link StrKey}),
   * {@link Address}, or {@link Contract}.
   *
   * @param address - The account or contract whose
   *    balance should be fetched.
   * @param asset - The asset whose balance you want to inspect.
   * @param networkPassphrase - (optional) optionally, when requesting the
   *    balance of a contract, the network passphrase to which this token
   *    applies. If omitted and necessary, a request about network information
   *    will be made (see {@link getNetwork}), since contract IDs for assets are
   *    specific to a network. You can refer to {@link Networks} for a list of
   *    built-in passphrases, e.g., `Networks.TESTNET`.
   * @returns Resolves with balance entry details
   *    when available.
   *
   * @throws If the supplied `address` is not a valid account or
   *    contract strkey.
   *
   * @example
   * ```ts
   * const usdc = new Asset(
   *   "USDC",
   *   "GBBD47IF6LWK7P7MDEVSCWR7DPUWV3NY3DTQEVFL4NAT4AQH3ZLLFLA5"
   * );
   * const balance = await server.getAssetBalance("GD...", usdc);
   * console.log(balance.balanceEntry?.amount);
   * ```
   */
  async getAssetBalance(address$1, asset, networkPassphrase) {
    let addr = address$1;
    if (typeof address$1 === "string") {
      addr = address$1;
    } else if (address$1 instanceof address.Address) {
      addr = address$1.toString();
    } else if (address$1 instanceof contract.Contract) {
      addr = address$1.toString();
    } else {
      throw new TypeError(`invalid address: ${address$1}`);
    }
    if (strkey.StrKey.isValidEd25519PublicKey(addr)) {
      const [tl, ll] = await Promise.all([
        this.getTrustline(addr, asset),
        this.getLatestLedger()
      ]);
      return {
        latestLedger: ll.sequence,
        balanceEntry: {
          amount: tl.balance().toString(),
          // Extract actual flags from the coalesced value.
          authorized: Boolean(tl.flags() & 1),
          // AUTHORIZED_FLAG
          clawback: Boolean(tl.flags() & 4),
          // TRUSTLINE_CLAWBACK_ENABLED_FLAG
          authorizedToMaintainLiabilities: Boolean(tl.flags() & 2),
          // AUTHORIZED_TO_MAINTAIN_LIABILITIES_FLAG
          revocable: Boolean(tl.flags() & 2)
          // AUTHORIZED_TO_MAINTAIN_LIABILITIES_FLAG (deprecated, will be removed in a future major release)
        }
      };
    } else if (strkey.StrKey.isValidContract(addr)) {
      return this.getSACBalance(addr, asset, networkPassphrase);
    }
    throw new Error(`invalid address: ${address$1}`);
  }
  /**
   * General node health check.
   *
   * @returns A promise which resolves to the
   * {@link Api.GetHealthResponse} object with the status of the
   * server (e.g. "healthy").
   *
   * @see {@link https://developers.stellar.org/docs/data/rpc/api-reference/methods/getHealth | getLedgerEntries docs}
   *
   * @example
   * ```ts
   * server.getHealth().then((health) => {
   *   console.log("status:", health.status);
   * });
   * ```
   */
  async getHealth() {
    return jsonrpc.postObject(
      this.httpClient,
      this.serverURL.toString(),
      "getHealth"
    );
  }
  /**
   * Reads the current value of contract data ledger entries directly.
   *
   * Allows you to directly inspect the current state of a contract. This is a
   * backup way to access your contract data which may not be available via
   * events or {@link rpc.Server.simulateTransaction}.
   *
   * @param contract - The contract ID containing the
   *    data to load as a strkey (`C...` form), a {@link Contract}, or an
   *    {@link Address} instance
   * @param key - The key of the contract data to load
   * @param durability - (optional) The "durability
   *    keyspace" that this ledger key belongs to, which is either 'temporary'
   *    or 'persistent' (the default), see {@link rpc.Durability}.
   * @returns The current data value
   *
   * **Warning:** If the data entry in question is a 'temporary' entry, it's
   * entirely possible that it has expired out of existence.
   *
   * @see {@link https://developers.stellar.org/docs/data/rpc/api-reference/methods/getLedgerEntries | getLedgerEntries docs}
   *
   * @example
   * ```ts
   * const contractId = "CCJZ5DGASBWQXR5MPFCJXMBI333XE5U3FSJTNQU7RIKE3P5GN2K2WYD5";
   * const key = xdr.ScVal.scvSymbol("counter");
   * server.getContractData(contractId, key, Durability.Temporary).then(data => {
   *   console.log("value:", data.val);
   *   console.log("liveUntilLedgerSeq:", data.liveUntilLedgerSeq);
   *   console.log("lastModified:", data.lastModifiedLedgerSeq);
   *   console.log("latestLedger:", data.latestLedger);
   * });
   * ```
   */
  async getContractData(contract$1, key, durability = "persistent" /* Persistent */) {
    let scAddress;
    if (typeof contract$1 === "string") {
      scAddress = new contract.Contract(contract$1).address().toScAddress();
    } else if (contract$1 instanceof address.Address) {
      scAddress = contract$1.toScAddress();
    } else if (contract$1 instanceof contract.Contract) {
      scAddress = contract$1.address().toScAddress();
    } else {
      throw new TypeError(`unknown contract type: ${contract$1}`);
    }
    let xdrDurability;
    switch (durability) {
      case "temporary" /* Temporary */:
        xdrDurability = curr_generated.default.ContractDataDurability.temporary();
        break;
      case "persistent" /* Persistent */:
        xdrDurability = curr_generated.default.ContractDataDurability.persistent();
        break;
      default:
        throw new TypeError(`invalid durability: ${durability}`);
    }
    const contractKey = curr_generated.default.LedgerKey.contractData(
      new curr_generated.default.LedgerKeyContractData({
        key,
        contract: scAddress,
        durability: xdrDurability
      })
    );
    try {
      return await this.getLedgerEntry(contractKey);
    } catch {
      throw {
        code: 404,
        message: `Contract data not found for ${address.Address.fromScAddress(
          scAddress
        ).toString()} with key ${key.toXDR("base64")} and durability: ${durability}`
      };
    }
  }
  /**
   * Retrieves the WASM bytecode for a given contract.
   *
   * This method allows you to fetch the WASM bytecode associated with a contract
   * deployed on the Soroban network. The WASM bytecode represents the executable
   * code of the contract.
   *
   * @param contractId - The contract ID containing the WASM bytecode to retrieve
   * @returns A Buffer containing the WASM bytecode
   * @throws If the contract or its associated WASM bytecode cannot be
   * found on the network.
   *
   * @example
   * ```ts
   * const contractId = "CCJZ5DGASBWQXR5MPFCJXMBI333XE5U3FSJTNQU7RIKE3P5GN2K2WYD5";
   * server.getContractWasmByContractId(contractId).then(wasmBuffer => {
   *   console.log("WASM bytecode length:", wasmBuffer.length);
   *   // ... do something with the WASM bytecode ...
   * }).catch(err => {
   *   console.error("Error fetching WASM bytecode:", err);
   * });
   * ```
   */
  async getContractWasmByContractId(contractId) {
    const contractLedgerKey = new contract.Contract(contractId).getFootprint();
    const response = await this.getLedgerEntries(contractLedgerKey);
    if (!response.entries.length || !response.entries[0]?.val) {
      return Promise.reject({
        code: 404,
        message: `Could not obtain contract hash from server`
      });
    }
    const wasmHash = response.entries[0].val.contractData().val().instance().executable().wasmHash();
    return this.getContractWasmByHash(wasmHash);
  }
  /**
   * Retrieves the WASM bytecode for a given contract hash.
   *
   * This method allows you to fetch the WASM bytecode associated with a contract
   * deployed on the Soroban network using the contract's WASM hash. The WASM bytecode
   * represents the executable code of the contract.
   *
   * @param wasmHash - The WASM hash of the contract
   * @returns A Buffer containing the WASM bytecode
   * @throws If the contract or its associated WASM bytecode cannot be
   * found on the network.
   *
   * @example
   * ```ts
   * const wasmHash = Buffer.from("...");
   * server.getContractWasmByHash(wasmHash).then(wasmBuffer => {
   *   console.log("WASM bytecode length:", wasmBuffer.length);
   *   // ... do something with the WASM bytecode ...
   * }).catch(err => {
   *   console.error("Error fetching WASM bytecode:", err);
   * });
   * ```
   */
  async getContractWasmByHash(wasmHash, format = void 0) {
    const wasmHashBuffer = typeof wasmHash === "string" ? buffer.Buffer.from(wasmHash, format) : wasmHash;
    const ledgerKeyWasmHash = curr_generated.default.LedgerKey.contractCode(
      new curr_generated.default.LedgerKeyContractCode({
        hash: wasmHashBuffer
      })
    );
    const responseWasm = await this.getLedgerEntries(ledgerKeyWasmHash);
    if (!responseWasm.entries.length || !responseWasm.entries[0]?.val) {
      return Promise.reject({
        code: 404,
        message: "Could not obtain contract wasm from server"
      });
    }
    const wasmBuffer = responseWasm.entries[0].val.contractCode().code();
    return wasmBuffer;
  }
  /**
   * Reads the current value of arbitrary ledger entries directly.
   *
   * Allows you to directly inspect the current state of contracts, contract's
   * code, accounts, or any other ledger entries.
   *
   * To fetch a contract's WASM byte-code, built the appropriate
   * {@link xdr.LedgerKeyContractCode} ledger entry key (or see
   * {@link Contract.getFootprint}).
   *
   * @param keys - One or more ledger entry keys to load
   * @returns The current on-chain
   * values for the given ledger keys
   *
   * @see {@link https://developers.stellar.org/docs/data/rpc/api-reference/methods/getLedgerEntries | getLedgerEntries docs}
   * @see RpcServer._getLedgerEntries
   * @example
   * ```ts
   * const contractId = "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM";
   * const key = xdr.LedgerKey.contractData(new xdr.LedgerKeyContractData({
   *   contractId: StrKey.decodeContract(contractId),
   *   key: xdr.ScVal.scvSymbol("counter"),
   * }));
   *
   * server.getLedgerEntries([key]).then(response => {
   *   const ledgerData = response.entries[0];
   *   console.log("key:", ledgerData.key);
   *   console.log("value:", ledgerData.val);
   *   console.log("liveUntilLedgerSeq:", ledgerData.liveUntilLedgerSeq);
   *   console.log("lastModified:", ledgerData.lastModifiedLedgerSeq);
   *   console.log("latestLedger:", response.latestLedger);
   * });
   * ```
   */
  getLedgerEntries(...keys) {
    return this._getLedgerEntries(...keys).then(parsers.parseRawLedgerEntries);
  }
  _getLedgerEntries(...keys) {
    return jsonrpc.postObject(
      this.httpClient,
      this.serverURL.toString(),
      "getLedgerEntries",
      {
        keys: keys.map((k) => k.toXDR("base64"))
      }
    );
  }
  async getLedgerEntry(key) {
    const results = await this._getLedgerEntries(key).then(
      parsers.parseRawLedgerEntries
    );
    if (results.entries.length !== 1) {
      throw new Error(`failed to find an entry for key ${key.toXDR("base64")}`);
    }
    return results.entries[0];
  }
  /**
   * Poll for a particular transaction with certain parameters.
   *
   * After submitting a transaction, clients can use this to poll for
   * transaction completion and return a definitive state of success or failure.
   *
   * @param hash - the transaction you're polling for
   * @param opts - (optional) polling options
   *   - `attempts` (optional): (optional) the number of attempts to make
   *    before returning the last-seen status. By default or on invalid inputs,
   *    try 5 times.
   *   - `sleepStrategy` (optional): (optional) the amount of time
   *    to wait for between each attempt. By default, sleep for 1 second between
   *    each attempt.
   *
   * @returns the response after a "found"
   *    response (which may be success or failure) or the last response obtained
   *    after polling the maximum number of specified attempts.
   *
   * @example
   * ```ts
   * const h = "c4515e3bdc0897f21cc5dbec8c82cf0a936d4741cb74a8e158eb51b9fb00411a";
   * const txStatus = await server.pollTransaction(h, {
   *    attempts: 100, // I'm a maniac
   *    sleepStrategy: rpc.LinearSleepStrategy
   * }); // this will take 5,050 seconds to complete
   * ```
   */
  async pollTransaction(hash, opts) {
    const maxAttempts = (opts?.attempts ?? 0) < 1 ? DEFAULT_GET_TRANSACTION_TIMEOUT : opts?.attempts ?? DEFAULT_GET_TRANSACTION_TIMEOUT;
    let foundInfo;
    for (let attempt = 1; attempt <= maxAttempts; attempt++) {
      foundInfo = await this.getTransaction(hash);
      if (foundInfo.status !== api.Api.GetTransactionStatus.NOT_FOUND) {
        return foundInfo;
      }
      await utils.Utils.sleep((opts?.sleepStrategy ?? BasicSleepStrategy)(attempt));
    }
    return foundInfo;
  }
  /**
   * Fetch the details of a submitted transaction.
   *
   * After submitting a transaction, clients should poll this to tell when the
   * transaction has completed.
   *
   * @param hash - Hex-encoded hash of the transaction to check
   * @returns The status, result, and
   *    other details about the transaction
   *
   * @see
   * {@link https://developers.stellar.org/docs/data/rpc/api-reference/methods/getTransaction | getTransaction docs}
   *
   * @example
   * ```ts
   * const transactionHash = "c4515e3bdc0897f21cc5dbec8c82cf0a936d4741cb74a8e158eb51b9fb00411a";
   * server.getTransaction(transactionHash).then((tx) => {
   *   console.log("status:", tx.status);
   *   console.log("envelopeXdr:", tx.envelopeXdr);
   *   console.log("resultMetaXdr:", tx.resultMetaXdr);
   *   console.log("resultXdr:", tx.resultXdr);
   * });
   * ```
   */
  async getTransaction(hash) {
    return this._getTransaction(hash).then((raw) => {
      const foundInfo = {};
      if (raw.status !== api.Api.GetTransactionStatus.NOT_FOUND) {
        Object.assign(foundInfo, parsers.parseTransactionInfo(raw));
      }
      const result = {
        status: raw.status,
        txHash: hash,
        latestLedger: raw.latestLedger,
        latestLedgerCloseTime: raw.latestLedgerCloseTime,
        oldestLedger: raw.oldestLedger,
        oldestLedgerCloseTime: raw.oldestLedgerCloseTime,
        ...foundInfo
      };
      return result;
    });
  }
  async _getTransaction(hash) {
    return jsonrpc.postObject(
      this.httpClient,
      this.serverURL.toString(),
      "getTransaction",
      {
        hash
      }
    );
  }
  /**
   * Fetch transactions starting from a given start ledger or a cursor. The end ledger is the latest ledger
   * in that RPC instance.
   *
   * @param request - The request parameters.
   * @returns - A promise that resolves to the transactions response.
   *
   * @see https://developers.stellar.org/docs/data/rpc/api-reference/methods/getTransactions
   * @example
   * ```ts
   * server.getTransactions({
   *   startLedger: 10000,
   *   limit: 10,
   * }).then((response) => {
   *   console.log("Transactions:", response.transactions);
   *   console.log("Latest Ledger:", response.latestLedger);
   *   console.log("Cursor:", response.cursor);
   * });
   * ```
   */
  async getTransactions(request) {
    return this._getTransactions(request).then(
      (raw) => {
        const result = {
          transactions: (raw.transactions || []).map(parsers.parseRawTransactions),
          latestLedger: raw.latestLedger,
          latestLedgerCloseTimestamp: raw.latestLedgerCloseTimestamp,
          oldestLedger: raw.oldestLedger,
          oldestLedgerCloseTimestamp: raw.oldestLedgerCloseTimestamp,
          cursor: raw.cursor
        };
        return result;
      }
    );
  }
  async _getTransactions(request) {
    return jsonrpc.postObject(
      this.httpClient,
      this.serverURL.toString(),
      "getTransactions",
      request
    );
  }
  /**
   * Fetch all events that match a given set of filters.
   *
   * The given filters (see {@link Api.EventFilter}
   * for detailed fields) are combined only in a logical OR fashion, and all of
   * the fields in each filter are optional.
   *
   * To page through events, use the `pagingToken` field on the relevant
   * {@link Api.EventResponse} object to set the `cursor` parameter.
   *
   * @param request - Event filters {@link Api.GetEventsRequest},
   * @returns A paginatable set of the events
   * matching the given event filters
   *
   * @see {@link https://developers.stellar.org/docs/data/rpc/api-reference/methods/getEvents | getEvents docs}
   *
   * @example
   * ```ts
   *
   * server.getEvents({
   *    startLedger: 1000,
   *    endLedger: 2000,
   *    filters: [
   *     {
   *      type: "contract",
   *      contractIds: [ "deadb33f..." ],
   *      topics: [[ "AAAABQAAAAh0cmFuc2Zlcg==", "AAAAAQB6Mcc=", "*" ]]
   *     }, {
   *      type: "system",
   *      contractIds: [ "...c4f3b4b3..." ],
   *      topics: [[ "*" ], [ "*", "AAAAAQB6Mcc=" ]]
   *     }, {
   *      contractIds: [ "...c4f3b4b3..." ],
   *      topics: [[ "AAAABQAAAAh0cmFuc2Zlcg==" ]]
   *     }, {
   *      type: "diagnostic",
   *      topics: [[ "AAAAAQB6Mcc=" ]]
   *     }
   *    ],
   *    limit: 10,
   * });
   * ```
   */
  async getEvents(request) {
    return this._getEvents(request).then(parsers.parseRawEvents);
  }
  async _getEvents(request) {
    return jsonrpc.postObject(
      this.httpClient,
      this.serverURL.toString(),
      "getEvents",
      {
        filters: request.filters ?? [],
        pagination: {
          ...request.cursor && { cursor: request.cursor },
          // add if defined
          ...request.limit && { limit: request.limit }
        },
        ...request.startLedger && {
          startLedger: request.startLedger
        },
        ...request.endLedger && {
          endLedger: request.endLedger
        }
      }
    );
  }
  /**
   * Fetch metadata about the network this Soroban RPC server is connected to.
   *
   * @returns Metadata about the current
   * network this RPC server is connected to
   *
   * @see {@link https://developers.stellar.org/docs/data/rpc/api-reference/methods/getNetwork | getNetwork docs}
   *
   * @example
   * ```ts
   * server.getNetwork().then((network) => {
   *   console.log("friendbotUrl:", network.friendbotUrl);
   *   console.log("passphrase:", network.passphrase);
   *   console.log("protocolVersion:", network.protocolVersion);
   * });
   * ```
   */
  async getNetwork() {
    return jsonrpc.postObject(
      this.httpClient,
      this.serverURL.toString(),
      "getNetwork"
    );
  }
  /**
   * Fetch the latest ledger meta info from network which this Soroban RPC
   * server is connected to.
   *
   * @returns metadata about the
   *    latest ledger on the network that this RPC server is connected to
   *
   * @see {@link https://developers.stellar.org/docs/data/rpc/api-reference/methods/getLatestLedger | getLatestLedger docs}
   *
   * @example
   * ```ts
   * server.getLatestLedger().then((response) => {
   *   console.log("hash:", response.id);
   *   console.log("sequence:", response.sequence);
   *   console.log("protocolVersion:", response.protocolVersion);
   * });
   * ```
   */
  async getLatestLedger() {
    return this._getLatestLedger().then(parsers.parseRawLatestLedger);
  }
  async _getLatestLedger() {
    return jsonrpc.postObject(
      this.httpClient,
      this.serverURL.toString(),
      "getLatestLedger"
    );
  }
  /**
   * Submit a trial contract invocation to get back return values, expected
   * ledger footprint, expected authorizations, and expected costs.
   *
   * @param tx - the transaction to simulate,
   *    which should include exactly one operation (one of
   *    {@link xdr.InvokeHostFunctionOp}, {@link xdr.ExtendFootprintTtlOp}, or
   *    {@link xdr.RestoreFootprintOp}). Any provided footprint or auth
   *    information will be ignored.
   * @param addlResources - (optional) any additional resources
   *    to add to the simulation-provided ones, for example if you know you will
   *    need extra CPU instructions
   * @param authMode - (optional) optionally, specify the type of
   *    auth mode to use for simulation: `enforce` for enforcement mode,
   *    `record` for recording mode, or `record_allow_nonroot` for recording
   *    mode that allows non-root authorization
   *
   * @returns An object with the
   *    cost, footprint, result/auth requirements (if applicable), and error of
   *    the transaction
   *
   * @see
   * {@link https://developers.stellar.org/docs/learn/fundamentals/stellar-data-structures/operations-and-transactions | transaction docs}
   * @see
   * {@link https://developers.stellar.org/docs/data/rpc/api-reference/methods/simulateTransaction | simulateTransaction docs}
   * @see
   * {@link https://developers.stellar.org/docs/learn/fundamentals/contract-development/contract-interactions/transaction-simulation#authorization | authorization modes}
   * @see module:rpc.Server#prepareTransaction
   * @see module:rpc.assembleTransaction
   *
   * @example
   * ```ts
   * const contractId = 'CA3D5KRYM6CB7OWQ6TWYRR3Z4T7GNZLKERYNZGGA5SOAOPIFY6YQGAXE';
   * const contract = new StellarSdk.Contract(contractId);
   *
   * // Right now, this is just the default fee for this example.
   * const fee = StellarSdk.BASE_FEE;
   * const transaction = new StellarSdk.TransactionBuilder(account, { fee })
   *   // Uncomment the following line to build transactions for the live network. Be
   *   // sure to also change the horizon hostname.
   *   //.setNetworkPassphrase(StellarSdk.Networks.PUBLIC)
   *   .setNetworkPassphrase(StellarSdk.Networks.FUTURENET)
   *   .setTimeout(30) // valid for the next 30s
   *   // Add an operation to call increment() on the contract
   *   .addOperation(contract.call("increment"))
   *   .build();
   *
   * server.simulateTransaction(transaction).then((sim) => {
   *   console.log("cost:", sim.cost);
   *   console.log("result:", sim.result);
   *   console.log("error:", sim.error);
   *   console.log("latestLedger:", sim.latestLedger);
   * });
   * ```
   */
  async simulateTransaction(tx, addlResources, authMode) {
    return this._simulateTransaction(tx, addlResources, authMode).then(
      parsers.parseRawSimulation
    );
  }
  async _simulateTransaction(transaction, addlResources, authMode) {
    return jsonrpc.postObject(
      this.httpClient,
      this.serverURL.toString(),
      "simulateTransaction",
      {
        transaction: transaction.toXDR(),
        authMode,
        ...addlResources !== void 0 && {
          resourceConfig: {
            instructionLeeway: addlResources.cpuInstructions
          }
        }
      }
    );
  }
  /**
   * Submit a trial contract invocation, first run a simulation of the contract
   * invocation as defined on the incoming transaction, and apply the results to
   * a new copy of the transaction which is then returned. Setting the ledger
   * footprint and authorization, so the resulting transaction is ready for
   * signing & sending.
   *
   * The returned transaction will also have an updated fee that is the sum of
   * fee set on incoming transaction with the contract resource fees estimated
   * from simulation. It is advisable to check the fee on returned transaction
   * and validate or take appropriate measures for interaction with user to
   * confirm it is acceptable.
   *
   * You can call the {@link rpc.Server.simulateTransaction} method
   * directly first if you want to inspect estimated fees for a given
   * transaction in detail first, then re-assemble it manually or via
   * {@link rpc.assembleTransaction}.
   *
   * @param tx - the transaction to
   *    prepare. It should include exactly one operation, which must be one of
   *    {@link xdr.InvokeHostFunctionOp}, {@link xdr.ExtendFootprintTtlOp},
   *    or {@link xdr.RestoreFootprintOp}.
   *
   *    Any provided footprint will be overwritten. However, if your operation
   *    has existing auth entries, they will be preferred over ALL auth entries
   *    from the simulation. In other words, if you include auth entries, you
   *    don't care about the auth returned from the simulation. Other fields
   *    (footprint, etc.) will be filled as normal.
   * @returns A copy of the
   *    transaction with the expected authorizations (in the case of
   *    invocation), resources, and ledger footprints added. The transaction fee
   *    will also automatically be padded with the contract's minimum resource
   *    fees discovered from the simulation.
   * @throws    *    If simulation fails
   *
   * @see module:rpc.assembleTransaction
   * @see {@link https://developers.stellar.org/docs/data/rpc/api-reference/methods/simulateTransaction | simulateTransaction docs}
   *
   * @example
   * ```ts
   * const contractId = 'CA3D5KRYM6CB7OWQ6TWYRR3Z4T7GNZLKERYNZGGA5SOAOPIFY6YQGAXE';
   * const contract = new StellarSdk.Contract(contractId);
   *
   * // Right now, this is just the default fee for this example.
   * const fee = StellarSdk.BASE_FEE;
   * const transaction = new StellarSdk.TransactionBuilder(account, { fee })
   *   // Uncomment the following line to build transactions for the live network. Be
   *   // sure to also change the horizon hostname.
   *   //.setNetworkPassphrase(StellarSdk.Networks.PUBLIC)
   *   .setNetworkPassphrase(StellarSdk.Networks.FUTURENET)
   *   .setTimeout(30) // valid for the next 30s
   *   // Add an operation to call increment() on the contract
   *   .addOperation(contract.call("increment"))
   *   .build();
   *
   * const preparedTransaction = await server.prepareTransaction(transaction);
   *
   * // Sign this transaction with the secret key
   * // NOTE: signing is transaction is network specific. Test network transactions
   * // won't work in the public network. To switch networks, use the Network object
   * // as explained above (look for StellarSdk.Network).
   * const sourceKeypair = StellarSdk.Keypair.fromSecret(sourceSecretKey);
   * preparedTransaction.sign(sourceKeypair);
   *
   * server.sendTransaction(transaction).then(result => {
   *   console.log("hash:", result.hash);
   *   console.log("status:", result.status);
   *   console.log("errorResultXdr:", result.errorResultXdr);
   * });
   * ```
   */
  async prepareTransaction(tx) {
    const simResponse = await this.simulateTransaction(tx);
    if (api.Api.isSimulationError(simResponse)) {
      throw new Error(simResponse.error);
    }
    return transaction.assembleTransaction(tx, simResponse).build();
  }
  /**
   * Submit a real transaction to the Stellar network.
   *
   * Unlike Horizon, RPC does not wait for transaction completion. It
   * simply validates the transaction and enqueues it. Clients should call
   * {@link rpc.Server.getTransaction} to learn about transaction
   * success/failure.
   *
   * @param transaction - to submit
   * @returns the
   *    transaction id, status, and any error if available
   *
   * @see {@link https://developers.stellar.org/docs/learn/fundamentals/stellar-data-structures/operations-and-transactions | transaction docs}
   * @see {@link https://developers.stellar.org/docs/data/rpc/api-reference/methods/sendTransaction | sendTransaction docs}
   *
   * @example
   * ```ts
   * const contractId = 'CA3D5KRYM6CB7OWQ6TWYRR3Z4T7GNZLKERYNZGGA5SOAOPIFY6YQGAXE';
   * const contract = new StellarSdk.Contract(contractId);
   *
   * // Right now, this is just the default fee for this example.
   * const fee = StellarSdk.BASE_FEE;
   * const transaction = new StellarSdk.TransactionBuilder(account, { fee })
   *   // Uncomment the following line to build transactions for the live network. Be
   *   // sure to also change the horizon hostname.
   *   //.setNetworkPassphrase(StellarSdk.Networks.PUBLIC)
   *   .setNetworkPassphrase(StellarSdk.Networks.FUTURENET)
   *   .setTimeout(30) // valid for the next 30s
   *   // Add an operation to call increment() on the contract
   *   .addOperation(contract.call("increment"))
   *   .build();
   *
   * // Sign this transaction with the secret key
   * // NOTE: signing is transaction is network specific. Test network transactions
   * // won't work in the public network. To switch networks, use the Network object
   * // as explained above (look for StellarSdk.Network).
   * const sourceKeypair = StellarSdk.Keypair.fromSecret(sourceSecretKey);
   * transaction.sign(sourceKeypair);
   *
   * server.sendTransaction(transaction).then((result) => {
   *   console.log("hash:", result.hash);
   *   console.log("status:", result.status);
   *   console.log("errorResultXdr:", result.errorResultXdr);
   * });
   * ```
   */
  async sendTransaction(transaction) {
    return this._sendTransaction(transaction).then(parsers.parseRawSendTransaction);
  }
  async _sendTransaction(transaction) {
    return jsonrpc.postObject(
      this.httpClient,
      this.serverURL.toString(),
      "sendTransaction",
      {
        transaction: transaction.toXDR()
      }
    );
  }
  /**
   * Fund a new account using the network's Friendbot faucet, if any.
   *
   * @param address - The address or account instance that we
   *    want to create and fund with Friendbot
   * @param friendbotUrl - (optional) Optionally, an explicit address for
   *    friendbot (by default: this calls the Soroban RPC
   *    {@link rpc.Server.getNetwork | getNetwork} method to try to
   *    discover this network's Friendbot url).
   * @returns An {@link Account} object for the created
   *    account, or the existing account if it's already funded with the
   *    populated sequence number (note that the account will not be "topped
   *    off" if it already exists)
   * @throws If Friendbot is not configured on this network or request failure
   *
   * @see {@link https://developers.stellar.org/docs/learn/fundamentals/networks#friendbot | Friendbot docs}
   * @see {@link Friendbot.Api.Response}
   *
   * @deprecated Use {@link Server.fundAddress} instead, which supports both
   *    account (G...) and contract (C...) addresses.
   *
   * @example
   * ```ts
   * server
   *    .requestAirdrop("GBZC6Y2Y7Q3ZQ2Y4QZJ2XZ3Z5YXZ6Z7Z2Y4QZJ2XZ3Z5YXZ6Z7Z2Y4")
   *    .then((accountCreated) => {
   *      console.log("accountCreated:", accountCreated);
   *    }).catch((error) => {
   *      console.error("error:", error);
   *    });
   * ```
   */
  async requestAirdrop(address, friendbotUrl) {
    const account$1 = typeof address === "string" ? address : address.accountId();
    friendbotUrl = friendbotUrl || (await this.getNetwork()).friendbotUrl;
    if (!friendbotUrl) {
      throw new Error("No friendbot URL configured for current network");
    }
    try {
      const response = await this.httpClient.post(
        `${friendbotUrl}?addr=${encodeURIComponent(account$1)}`
      );
      let meta;
      if (!response.data.result_meta_xdr) {
        const txMeta = await this.getTransaction(response.data.hash);
        if (txMeta.status !== api.Api.GetTransactionStatus.SUCCESS) {
          throw new Error(`Funding account ${address} failed`);
        }
        meta = txMeta.resultMetaXdr;
      } else {
        meta = curr_generated.default.TransactionMeta.fromXDR(
          response.data.result_meta_xdr,
          "base64"
        );
      }
      const sequence = findCreatedAccountSequenceInTransactionMeta(meta);
      return new account.Account(account$1, sequence);
    } catch (error) {
      if (error.response?.status === 400) {
        if (error.response.data?.detail?.includes("createAccountAlreadyExist")) {
          return this.getAccount(account$1);
        }
      }
      throw error;
    }
  }
  /**
   * Fund an address using the network's Friendbot faucet, if any.
   *
   * This method supports both account (G...) and contract (C...) addresses.
   *
   * @param address - The address to fund. Can be either a Stellar
   *    account (G...) or contract (C...) address.
   * @param friendbotUrl - (optional) Optionally, an explicit Friendbot URL
   *    (by default: this calls the Stellar RPC
   *    {@link rpc.Server.getNetwork | getNetwork} method to try to
   *    discover this network's Friendbot url).
   * @returns The transaction
   *    response from the Friendbot funding transaction.
   * @throws If Friendbot is not configured on this network or the
   *    funding transaction fails.
   *
   * @see {@link https://developers.stellar.org/docs/learn/fundamentals/networks#friendbot | Friendbot docs}
   *
   * @example
   * ```ts
   * // Funding an account (G... address)
   * const tx = await server.fundAddress("GBZC6Y2Y7...");
   * console.log("Funded! Hash:", tx.txHash);
   * // If you need the Account object:
   * const account = await server.getAccount("GBZC6Y2Y7...");
   * ```
   *
   * @example
   * ```ts
   * // Funding a contract (C... address)
   * const tx = await server.fundAddress("CBZC6Y2Y7...");
   * console.log("Contract funded! Hash:", tx.txHash);
   * ```
   */
  async fundAddress(address, friendbotUrl) {
    if (!strkey.StrKey.isValidEd25519PublicKey(address) && !strkey.StrKey.isValidContract(address)) {
      throw new Error(
        `Invalid address: ${address}. Expected a Stellar account (G...) or contract (C...) address.`
      );
    }
    friendbotUrl = friendbotUrl || (await this.getNetwork()).friendbotUrl;
    if (!friendbotUrl) {
      throw new Error("No friendbot URL configured for current network");
    }
    try {
      const response = await this.httpClient.post(
        `${friendbotUrl}?addr=${encodeURIComponent(address)}`
      );
      const txResponse = await this.getTransaction(response.data.hash);
      if (txResponse.status !== api.Api.GetTransactionStatus.SUCCESS) {
        throw new Error(
          `Funding address ${address} failed: transaction status ${txResponse.status}`
        );
      }
      return txResponse;
    } catch (error) {
      if (error.response?.status === 400) {
        throw new Error(error.response.data?.detail ?? "Bad Request");
      }
      throw error;
    }
  }
  /**
   * Provides an analysis of the recent fee stats for regular and smart
   * contract operations.
   *
   * @returns the fee stats
   * @see https://developers.stellar.org/docs/data/rpc/api-reference/methods/getFeeStats
   */
  async getFeeStats() {
    return jsonrpc.postObject(
      this.httpClient,
      this.serverURL.toString(),
      "getFeeStats"
    );
  }
  /**
   * Provides information about the current version details of the Soroban RPC and captive-core
   *
   * @returns the version info
   * @see https://developers.stellar.org/docs/data/rpc/api-reference/methods/getVersionInfo
   */
  async getVersionInfo() {
    return jsonrpc.postObject(
      this.httpClient,
      this.serverURL.toString(),
      "getVersionInfo"
    );
  }
  /**
   * Returns a contract's balance of a particular SAC asset, if any.
   *
   * This is a convenience wrapper around {@link Server.getLedgerEntries}.
   *
   * @param address - the contract (string `C...`) whose balance of
   *    `sac` you want to know
   * @param sac - the built-in SAC token (e.g. `USDC:GABC...`) that
   *    you are querying from the given `contract`.
   * @param networkPassphrase - (optional) optionally, the network passphrase to
   *    which this token applies. If omitted, a request about network
   *    information will be made (see {@link getNetwork}), since contract IDs
   *    for assets are specific to a network. You can refer to {@link Networks}
   *    for a list of built-in passphrases, e.g., `Networks.TESTNET`.
   *
   * @returns , which will contain the balance
   *    entry details if and only if the request returned a valid balance ledger
   *    entry. If it doesn't, the `balanceEntry` field will not exist.
   *
   * @throws If `address` is not a valid contract ID (C...).
   *
   * @see getLedgerEntries
   * @see https://developers.stellar.org/docs/tokens/stellar-asset-contract
   *
   * @deprecated Use {@link getAssetBalance}, instead
   * @example
   * ```ts
   * // assume `address` is some contract or account with an XLM balance
   * // assume server is an instantiated `Server` instance.
   * const entry = (await server.getSACBalance(
   *   new Address(address),
   *   Asset.native(),
   *   Networks.PUBLIC
   * ));
   *
   * // assumes BigInt support:
   * console.log(
   *   entry.balanceEntry ?
   *   BigInt(entry.balanceEntry.amount) :
   *   "Address has no XLM");
   * ```
   */
  async getSACBalance(address$1, sac, networkPassphrase) {
    const addressString = address$1 instanceof address.Address ? address$1.toString() : address$1;
    if (!strkey.StrKey.isValidContract(addressString)) {
      throw new TypeError(`expected contract ID, got ${addressString}`);
    }
    const passphrase = networkPassphrase ?? await this.getNetwork().then((n) => n.passphrase);
    const sacId = sac.contractId(passphrase);
    const key = scval.nativeToScVal(["Balance", addressString], {
      type: ["symbol", "address"]
    });
    const ledgerKey = curr_generated.default.LedgerKey.contractData(
      new curr_generated.default.LedgerKeyContractData({
        contract: new address.Address(sacId).toScAddress(),
        durability: curr_generated.default.ContractDataDurability.persistent(),
        key
      })
    );
    const response = await this.getLedgerEntries(ledgerKey);
    if (response.entries.length === 0) {
      return { latestLedger: response.latestLedger };
    }
    const { lastModifiedLedgerSeq, liveUntilLedgerSeq, val } = response.entries[0];
    if (val.switch().value !== curr_generated.default.LedgerEntryType.contractData().value) {
      return { latestLedger: response.latestLedger };
    }
    const entry = scval.scValToNative(val.contractData().val());
    return {
      latestLedger: response.latestLedger,
      balanceEntry: {
        liveUntilLedgerSeq,
        lastModifiedLedgerSeq,
        amount: entry.amount.toString(),
        authorized: entry.authorized,
        clawback: entry.clawback
      }
    };
  }
  /**
   * Fetch a detailed list of ledgers starting from a specified point.
   *
   * Returns ledger data with support for pagination as long as the requested
   * pages fall within the history retention of the RPC provider.
   *
   * @param request - The request parameters for fetching ledgers. {@link Api.GetLedgersRequest}
   * @returns A promise that resolves to the
   *    ledgers response containing an array of ledger data and pagination info. {@link Api.GetLedgersResponse}
   *
   * @throws If startLedger is less than the oldest ledger stored in this
   *    node, or greater than the latest ledger seen by this node.
   *
   * @see {@link https://developers.stellar.org/docs/data/rpc/api-reference/methods/getLedgers | getLedgers docs}
   *
   * @example
   * ```ts
   * // Fetch ledgers starting from a specific sequence number
   * server.getLedgers({
   *   startLedger: 36233,
   *   pagination: {
   *     limit: 10
   *   }
   * }).then((response) => {
   *   console.log("Ledgers:", response.ledgers);
   *   console.log("Latest Ledger:", response.latestLedger);
   *   console.log("Cursor:", response.cursor);
   * });
   * ```
   *
   * @example
   * ```ts
   * // Paginate through ledgers using cursor
   * const firstPage = await server.getLedgers({
   *   startLedger: 36233,
   *   pagination: {
   *     limit: 5
   *   }
   * });
   *
   * const nextPage = await server.getLedgers({
   *   pagination: {
   *     cursor: firstPage.cursor,
   *     limit: 5
   *   }
   * });
   * ```
   */
  async getLedgers(request) {
    return this._getLedgers(request).then((raw) => {
      const result = {
        ledgers: (raw.ledgers || []).map(parsers.parseRawLedger),
        latestLedger: raw.latestLedger,
        latestLedgerCloseTime: raw.latestLedgerCloseTime,
        oldestLedger: raw.oldestLedger,
        oldestLedgerCloseTime: raw.oldestLedgerCloseTime,
        cursor: raw.cursor
      };
      return result;
    });
  }
  async _getLedgers(request) {
    return jsonrpc.postObject(
      this.httpClient,
      this.serverURL.toString(),
      "getLedgers",
      request
    );
  }
}

exports.BasicSleepStrategy = BasicSleepStrategy;
exports.Durability = Durability;
exports.LinearSleepStrategy = LinearSleepStrategy;
exports.RpcServer = RpcServer;
//# sourceMappingURL=server.js.map
