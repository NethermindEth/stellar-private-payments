import types from '../generated/curr_generated.js';
import { best_r } from './continued_fraction.js';
import { decodeAddressToMuxedAccount } from './decode_encode_muxed_account.js';
import BigNumber from './bignumber.js';

const ONE = 1e7;
const MAX_INT64 = "9223372036854775807";
function setSourceAccount(opAttributes, opts) {
  if (opts.source) {
    try {
      opAttributes.sourceAccount = decodeAddressToMuxedAccount(opts.source);
    } catch {
      throw new Error("Source address is invalid");
    }
  }
}
function checkUnsignedIntValue(name, value, isValidFunction = null) {
  if (typeof value === "undefined") {
    return void 0;
  }
  const numValue = typeof value === "string" ? value.trim() === "" ? NaN : Number(value) : value;
  if (typeof numValue !== "number" || !Number.isFinite(numValue) || numValue % 1 !== 0) {
    throw new Error(`${name} value is invalid`);
  }
  if (numValue < 0) {
    throw new Error(`${name} value must be unsigned`);
  }
  if (!isValidFunction || isValidFunction(numValue, name)) {
    return numValue;
  }
  throw new Error(`${name} value is invalid`);
}
function toXDRAmount(value) {
  const amount = new BigNumber(value).times(ONE);
  return types.Int64.fromString(amount.toString());
}
function fromXDRAmount(value) {
  return new BigNumber(value.toString()).div(ONE).toFixed(7);
}
function fromXDRPrice(price) {
  const n = new BigNumber(price.n());
  return n.div(new BigNumber(price.d())).toString();
}
function toXDRPrice(price) {
  let xdrObject;
  if (typeof price === "object" && "n" in price && "d" in price) {
    xdrObject = new types.Price(price);
  } else {
    const priceBN = new BigNumber(price);
    if (!priceBN.gt(0) || !priceBN.isFinite()) {
      throw new Error("price must be positive");
    }
    const approx = best_r(price);
    xdrObject = new types.Price({
      n: parseInt(String(approx[0]), 10),
      d: parseInt(String(approx[1]), 10)
    });
  }
  if (xdrObject.n() < 0 || xdrObject.d() <= 0) {
    throw new Error("price must be positive");
  }
  return xdrObject;
}
function isValidAmount(value, allowZero = false) {
  if (typeof value !== "string") {
    return false;
  }
  let amount;
  try {
    amount = new BigNumber(value);
  } catch {
    return false;
  }
  if (
    // == 0
    !allowZero && amount.isZero() || // < 0
    amount.isNegative() || // > Max value
    amount.times(ONE).gt(new BigNumber(MAX_INT64).toString()) || // Decimal places (max 7)
    (amount.decimalPlaces() ?? 0) > 7 || // NaN or Infinity
    amount.isNaN() || !amount.isFinite()
  ) {
    return false;
  }
  return true;
}
function constructAmountRequirementsError(arg) {
  return `${arg} argument must be of type String, represent a positive number and have at most 7 digits after the decimal`;
}

export { ONE, checkUnsignedIntValue, constructAmountRequirementsError, fromXDRAmount, fromXDRPrice, isValidAmount, setSourceAccount, toXDRAmount, toXDRPrice };
//# sourceMappingURL=operations.js.map
