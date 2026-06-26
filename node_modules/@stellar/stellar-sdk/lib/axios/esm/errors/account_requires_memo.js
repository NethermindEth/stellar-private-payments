class AccountRequiresMemoError extends Error {
  accountId;
  operationIndex;
  constructor(message, accountId, operationIndex) {
    super(message);
    this.accountId = accountId;
    this.operationIndex = operationIndex;
  }
}

export { AccountRequiresMemoError };
//# sourceMappingURL=account_requires_memo.js.map
