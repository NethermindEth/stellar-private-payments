import { isValidAmount, constructAmountRequirementsError, toXDRAmount, toXDRPrice, setSourceAccount } from '../util/operations.js';
import types from '../generated/curr_generated.js';

function createPassiveSellOffer(opts) {
  const selling = opts.selling.toXDRObject();
  const buying = opts.buying.toXDRObject();
  if (!isValidAmount(opts.amount)) {
    throw new TypeError(constructAmountRequirementsError("amount"));
  }
  const amount = toXDRAmount(opts.amount);
  if (opts.price === void 0) {
    throw new TypeError("price argument is required");
  }
  const price = toXDRPrice(opts.price);
  const createPassiveSellOfferOp = new types.CreatePassiveSellOfferOp({
    selling,
    buying,
    amount,
    price
  });
  const opAttributes = {
    sourceAccount: null,
    body: types.OperationBody.createPassiveSellOffer(createPassiveSellOfferOp)
  };
  setSourceAccount(opAttributes, opts);
  return new types.Operation(opAttributes);
}

export { createPassiveSellOffer };
//# sourceMappingURL=create_passive_sell_offer.js.map
