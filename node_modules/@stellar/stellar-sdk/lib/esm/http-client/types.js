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

export { CancelToken };
//# sourceMappingURL=types.js.map
