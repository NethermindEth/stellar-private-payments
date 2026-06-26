'use strict';

class Ok {
  constructor(value) {
    this.value = value;
  }
  value;
  unwrapErr() {
    throw new Error("No error");
  }
  unwrap() {
    return this.value;
  }
  isOk() {
    return true;
  }
  isErr() {
    return false;
  }
}
class Err {
  constructor(error) {
    this.error = error;
  }
  error;
  unwrapErr() {
    return this.error;
  }
  unwrap() {
    throw new Error(this.error.message);
  }
  isOk() {
    return false;
  }
  isErr() {
    return true;
  }
}

exports.Err = Err;
exports.Ok = Ok;
//# sourceMappingURL=rust_result.js.map
