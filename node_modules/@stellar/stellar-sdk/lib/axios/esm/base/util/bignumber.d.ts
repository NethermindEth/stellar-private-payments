import OriginBigNumber from "bignumber.js";
import type { BigNumber as BigNumberInstance } from "bignumber.js";
declare const BigNumber: typeof OriginBigNumber;
export default BigNumber;
export type BigNumber = BigNumberInstance;
