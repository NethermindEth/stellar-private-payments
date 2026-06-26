'use strict';

var horizon_api = require('./horizon_api.js');
var effects = require('./types/effects.js');

exports.ServerApi = void 0;
((ServerApi2) => {
  ServerApi2.EffectType = effects.EffectType;
  ((TradeType2) => {
    TradeType2["all"] = "all";
    TradeType2["liquidityPools"] = "liquidity_pool";
    TradeType2["orderbook"] = "orderbook";
  })(ServerApi2.TradeType || (ServerApi2.TradeType = {}));
  horizon_api.HorizonApi.OperationResponseType;
  horizon_api.HorizonApi.OperationResponseTypeI;
})(exports.ServerApi || (exports.ServerApi = {}));
//# sourceMappingURL=server_api.js.map
