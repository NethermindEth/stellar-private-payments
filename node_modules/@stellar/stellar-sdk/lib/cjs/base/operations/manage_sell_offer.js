'use strict';

var operations = require('../util/operations.js');
var curr_generated = require('../generated/curr_generated.js');

function manageSellOffer(opts) {
  const selling = opts.selling.toXDRObject();
  const buying = opts.buying.toXDRObject();
  if (!operations.isValidAmount(opts.amount, true)) {
    throw new TypeError(operations.constructAmountRequirementsError("amount"));
  }
  const amount = operations.toXDRAmount(opts.amount);
  if (opts.price === void 0) {
    throw new TypeError("price argument is required");
  }
  const price = operations.toXDRPrice(opts.price);
  const offerIdStr = opts.offerId !== void 0 ? opts.offerId.toString() : "0";
  const offerId = curr_generated.default.Int64.fromString(offerIdStr);
  const manageSellOfferOp = new curr_generated.default.ManageSellOfferOp({
    selling,
    buying,
    amount,
    price,
    offerId
  });
  const opAttributes = {
    sourceAccount: null,
    body: curr_generated.default.OperationBody.manageSellOffer(manageSellOfferOp)
  };
  operations.setSourceAccount(opAttributes, opts);
  return new curr_generated.default.Operation(opAttributes);
}

exports.manageSellOffer = manageSellOffer;
//# sourceMappingURL=manage_sell_offer.js.map
