import '../../node_modules/.pnpm/@stellar_js-xdr@4.0.0/node_modules/@stellar/js-xdr/src/int.js';
import '../../node_modules/.pnpm/@stellar_js-xdr@4.0.0/node_modules/@stellar/js-xdr/src/hyper.js';
import '../../node_modules/.pnpm/@stellar_js-xdr@4.0.0/node_modules/@stellar/js-xdr/src/unsigned-int.js';
import '../../node_modules/.pnpm/@stellar_js-xdr@4.0.0/node_modules/@stellar/js-xdr/src/unsigned-hyper.js';
import { LargeInt } from '../../node_modules/.pnpm/@stellar_js-xdr@4.0.0/node_modules/@stellar/js-xdr/src/large-int.js';
import '../../node_modules/.pnpm/@stellar_js-xdr@4.0.0/node_modules/@stellar/js-xdr/src/xdr-type.js';
import 'buffer';

class Uint256 extends LargeInt {
  /**
   * Construct an unsigned 256-bit integer that can be XDR-encoded.
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
    return 256;
  }
}
Uint256.defineIntBoundaries();

export { Uint256 };
//# sourceMappingURL=uint256.js.map
