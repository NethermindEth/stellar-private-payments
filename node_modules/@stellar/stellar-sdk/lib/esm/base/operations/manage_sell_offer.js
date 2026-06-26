import { isValidAmount, constructAmountRequirementsError, toXDRAmount, toXDRPrice, setSourceAccount } from '../util/operations.js';
import types from '../generated/curr_generated.js';

function manageSellOffer(opts) {
  const selling = opts.selling.toXDRObject();
  const buying = opts.buying.toXDRObject();
  if (!isValidAmount(opts.amount, true)) {
    throw new TypeError(constructAmountRequirementsError("amount"));
  }
  const amount = toXDRAmount(opts.amount);
  if (opts.price === void 0) {
    throw new TypeError("price argument is required");
  }
  const price = toXDRPrice(opts.price);
  const offerIdStr = opts.offerId !== void 0 ? opts.offerId.toString() : "0";
  const offerId = types.Int64.fromString(offerIdStr);
  const manageSellOfferOp = new types.ManageSellOfferOp({
    selling,
    buying,
    amount,
    price,
    offerId
  });
  const opAttributes = {
    sourceAccount: null,
    body: types.OperationBody.manageSellOffer(manageSellOfferOp)
  };
  setSourceAccount(opAttributes, opts);
  return new types.Operation(opAttributes);
}

export { manageSellOffer };
//# sourceMappingURL=manage_sell_offer.js.map
