'use strict';

var operations = require('../util/operations.js');
var curr_generated = require('../generated/curr_generated.js');

function manageBuyOffer(opts) {
  const selling = opts.selling.toXDRObject();
  const buying = opts.buying.toXDRObject();
  if (!operations.isValidAmount(opts.buyAmount, true)) {
    throw new TypeError(operations.constructAmountRequirementsError("buyAmount"));
  }
  const buyAmount = operations.toXDRAmount(opts.buyAmount);
  if (opts.price === void 0) {
    throw new TypeError("price argument is required");
  }
  const price = operations.toXDRPrice(opts.price);
  const offerIdStr = opts.offerId !== void 0 ? opts.offerId.toString() : "0";
  const offerId = curr_generated.default.Int64.fromString(offerIdStr);
  const manageBuyOfferOp = new curr_generated.default.ManageBuyOfferOp({
    selling,
    buying,
    buyAmount,
    price,
    offerId
  });
  const opAttributes = {
    sourceAccount: null,
    body: curr_generated.default.OperationBody.manageBuyOffer(manageBuyOfferOp)
  };
  operations.setSourceAccount(opAttributes, opts);
  return new curr_generated.default.Operation(opAttributes);
}

exports.manageBuyOffer = manageBuyOffer;
//# sourceMappingURL=manage_buy_offer.js.map
