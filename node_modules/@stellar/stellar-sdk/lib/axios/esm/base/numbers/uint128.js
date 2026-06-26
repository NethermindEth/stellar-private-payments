import '../../node_modules/.pnpm/@stellar_js-xdr@4.0.0/node_modules/@stellar/js-xdr/src/int.js';
import '../../node_modules/.pnpm/@stellar_js-xdr@4.0.0/node_modules/@stellar/js-xdr/src/hyper.js';
import '../../node_modules/.pnpm/@stellar_js-xdr@4.0.0/node_modules/@stellar/js-xdr/src/unsigned-int.js';
import '../../node_modules/.pnpm/@stellar_js-xdr@4.0.0/node_modules/@stellar/js-xdr/src/unsigned-hyper.js';
import { LargeInt } from '../../node_modules/.pnpm/@stellar_js-xdr@4.0.0/node_modules/@stellar/js-xdr/src/large-int.js';
import '../../node_modules/.pnpm/@stellar_js-xdr@4.0.0/node_modules/@stellar/js-xdr/src/xdr-type.js';
import 'buffer';

class Uint128 extends LargeInt {
  /**
   * Construct an unsigned 128-bit integer that can be XDR-encoded.
   *
   * @param args - one or more slices to encode
   *     in big-endian format (i.e. earlier elements are higher bits)
   */
  constructor(...args) {
    super(args);
  }
  get unsigned() {
    return true;
  }
  get size() {
    return 128;
  }
}
Uint128.defineIntBoundaries();

export { Uint128 };
//# sourceMappingURL=uint128.js.map
