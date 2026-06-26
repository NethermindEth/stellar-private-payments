'use strict';

var operations = require('../util/operations.js');
var curr_generated = require('../generated/curr_generated.js');

function createPassiveSellOffer(opts) {
  const selling = opts.selling.toXDRObject();
  const buying = opts.buying.toXDRObject();
  if (!operations.isValidAmount(opts.amount)) {
    throw new TypeError(operations.constructAmountRequirementsError("amount"));
  }
  const amount = operations.toXDRAmount(opts.amount);
  if (opts.price === void 0) {
    throw new TypeError("price argument is required");
  }
  const price = operations.toXDRPrice(opts.price);
  const createPassiveSellOfferOp = new curr_generated.default.CreatePassiveSellOfferOp({
    selling,
    buying,
    amount,
    price
  });
  const opAttributes = {
    sourceAccount: null,
    body: curr_generated.default.OperationBody.createPassiveSellOffer(createPassiveSellOfferOp)
  };
  operations.setSourceAccount(opAttributes, opts);
  return new curr_generated.default.Operation(opAttributes);
}

exports.createPassiveSellOffer = createPassiveSellOffer;
//# sourceMappingURL=create_passive_sell_offer.js.map
