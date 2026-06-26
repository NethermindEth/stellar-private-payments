import { isValidAmount, constructAmountRequirementsError, toXDRAmount, toXDRPrice, setSourceAccount } from '../util/operations.js';
import types from '../generated/curr_generated.js';

function manageBuyOffer(opts) {
  const selling = opts.selling.toXDRObject();
  const buying = opts.buying.toXDRObject();
  if (!isValidAmount(opts.buyAmount, true)) {
    throw new TypeError(constructAmountRequirementsError("buyAmount"));
  }
  const buyAmount = toXDRAmount(opts.buyAmount);
  if (opts.price === void 0) {
    throw new TypeError("price argument is required");
  }
  const price = toXDRPrice(opts.price);
  const offerIdStr = opts.offerId !== void 0 ? opts.offerId.toString() : "0";
  const offerId = types.Int64.fromString(offerIdStr);
  const manageBuyOfferOp = new types.ManageBuyOfferOp({
    selling,
    buying,
    buyAmount,
    price,
    offerId
  });
  const opAttributes = {
    sourceAccount: null,
    body: types.OperationBody.manageBuyOffer(manageBuyOfferOp)
  };
  setSourceAccount(opAttributes, opts);
  return new types.Operation(opAttributes);
}

export { manageBuyOffer };
//# sourceMappingURL=manage_buy_offer.js.map
