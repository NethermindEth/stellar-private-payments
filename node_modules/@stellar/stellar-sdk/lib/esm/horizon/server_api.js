import { HorizonApi } from './horizon_api.js';
import { EffectType } from './types/effects.js';

var ServerApi;
((ServerApi2) => {
  ServerApi2.EffectType = EffectType;
  ((TradeType2) => {
    TradeType2["all"] = "all";
    TradeType2["liquidityPools"] = "liquidity_pool";
    TradeType2["orderbook"] = "orderbook";
  })(ServerApi2.TradeType || (ServerApi2.TradeType = {}));
  HorizonApi.OperationResponseType;
  HorizonApi.OperationResponseTypeI;
})(ServerApi || (ServerApi = {}));

export { ServerApi };
//# sourceMappingURL=server_api.js.map
