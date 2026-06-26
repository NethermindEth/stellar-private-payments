import { FeeBumpTransaction, Transaction, TransactionBuilder } from "../base/index.js";
import { Api } from "./api.js";
/**
 * Combines the given raw transaction alongside the simulation results.
 * If the given transaction already has authorization entries in a host
 * function invocation (see {@link Operation.invokeHostFunction}), **the
 * simulation entries are ignored**.
 *
 * If the given transaction already has authorization entries in a host function
 * invocation (see {@link Operation.invokeHostFunction}), **the simulation
 * entries are ignored**.
 *
 * @param raw - the initial transaction, w/o simulation applied
 * @param simulation - the Soroban RPC simulation result (see {@link rpc.Server.simulateTransaction})
 * @returns a new, cloned transaction with the proper auth and resource (fee, footprint) simulation data applied
 *
 * @see {@link rpc.Server.simulateTransaction}
 * @see {@link rpc.Server.prepareTransaction}
 */
export declare function assembleTransaction(raw: Transaction | FeeBumpTransaction, simulation: Api.SimulateTransactionResponse | Api.RawSimulateTransactionResponse): TransactionBuilder;
