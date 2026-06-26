/**
 * AccountRequiresMemoError is raised when a transaction is trying to submit an
 * operation to an account which requires a memo. See
 * [SEP0029](https://github.com/stellar/stellar-protocol/blob/master/ecosystem/sep-0029.md)
 * for more information.
 *
 * This error contains two attributes to help you identify the account requiring
 * the memo and the operation where the account is the destination
 *
 * @param message - Human-readable error message
 * @param accountId - The account which requires a memo
 * @param operationIndex - The index of the operation where `accountId` is the destination
 *
 * @example
 * ```ts
 * console.log('The following account requires a memo ', err.accountId)
 * console.log('The account is used in operation: ', err.operationIndex)
 * ```
 */
export declare class AccountRequiresMemoError extends Error {
    accountId: string;
    operationIndex: number;
    constructor(message: string, accountId: string, operationIndex: number);
}
