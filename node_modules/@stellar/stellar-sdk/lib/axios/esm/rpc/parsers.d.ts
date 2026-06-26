import { Api } from "./api.js";
/**
 * Parse the response from invoking the `submitTransaction` method of a RPC server.
 * @hidden
 *
 * @param raw - the raw `submitTransaction` response from the RPC server to parse
 * @returns transaction response parsed from the RPC server's response
 */
export declare function parseRawSendTransaction(raw: Api.RawSendTransactionResponse): Api.SendTransactionResponse;
export declare function parseTransactionInfo(raw: Api.RawTransactionInfo | Api.RawGetTransactionResponse): Omit<Api.TransactionInfo, "status" | "txHash">;
export declare function parseRawTransactions(r: Api.RawTransactionInfo): Api.TransactionInfo;
/**
 * Parse and return the retrieved events, if any, from a raw response from a
 * RPC server.
 *
 * @param raw - the raw `getEvents` response from the
 *    RPC server to parse
 * @returns events parsed from the RPC server's
 *    response
 */
export declare function parseRawEvents(raw: Api.RawGetEventsResponse): Api.GetEventsResponse;
/**
 * Parse and return the retrieved ledger entries, if any, from a raw response
 * from a RPC server.
 * @hidden
 *
 * @param raw - the raw `getLedgerEntries`
 *    response from the RPC server to parse
 * @returns ledger entries parsed from the
 *    RPC server's response
 */
export declare function parseRawLedgerEntries(raw: Api.RawGetLedgerEntriesResponse): Api.GetLedgerEntriesResponse;
/**
 * Converts a raw response schema into one with parsed XDR fields and a simplified interface.
 *
 * **Warning:** This API is only exported for testing purposes and should not be relied on or considered "stable".
 *
 * @param sim - the raw response schema (parsed ones are allowed, best-effort
 *    detected, and returned untouched)
 * @returns the original parameter (if already parsed), parsed otherwise
 */
export declare function parseRawSimulation(sim: Api.SimulateTransactionResponse | Api.RawSimulateTransactionResponse): Api.SimulateTransactionResponse;
export declare function parseRawLedger(raw: Api.RawLedgerResponse): Api.LedgerResponse;
export declare function parseRawLatestLedger(raw: Api.RawGetLatestLedgerResponse): Api.GetLatestLedgerResponse;
