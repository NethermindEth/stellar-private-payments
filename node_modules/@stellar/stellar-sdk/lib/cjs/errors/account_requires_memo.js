'use strict';

class AccountRequiresMemoError extends Error {
  accountId;
  operationIndex;
  constructor(message, accountId, operationIndex) {
    super(message);
    this.accountId = accountId;
    this.operationIndex = operationIndex;
  }
}

exports.AccountRequiresMemoError = AccountRequiresMemoError;
//# sourceMappingURL=account_requires_memo.js.map
