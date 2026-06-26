'use strict';

class CancelToken {
  promise;
  reason;
  throwIfRequested() {
    if (this.reason) {
      throw new Error(this.reason);
    }
  }
  constructor(executor) {
    let resolvePromise;
    this.promise = new Promise((resolve) => {
      resolvePromise = resolve;
    });
    executor((reason) => {
      this.reason = reason;
      resolvePromise();
    });
  }
}

exports.CancelToken = CancelToken;
//# sourceMappingURL=types.js.map
