import '../../node_modules/.pnpm/@stellar_js-xdr@4.0.0/node_modules/@stellar/js-xdr/src/int.js';
import '../../node_modules/.pnpm/@stellar_js-xdr@4.0.0/node_modules/@stellar/js-xdr/src/hyper.js';
import '../../node_modules/.pnpm/@stellar_js-xdr@4.0.0/node_modules/@stellar/js-xdr/src/unsigned-int.js';
import '../../node_modules/.pnpm/@stellar_js-xdr@4.0.0/node_modules/@stellar/js-xdr/src/unsigned-hyper.js';
import { LargeInt } from '../../node_modules/.pnpm/@stellar_js-xdr@4.0.0/node_modules/@stellar/js-xdr/src/large-int.js';
import '../../node_modules/.pnpm/@stellar_js-xdr@4.0.0/node_modules/@stellar/js-xdr/src/xdr-type.js';
import 'buffer';

class Int128 extends LargeInt {
  /**
   * Construct a signed 128-bit integer that can be XDR-encoded.
   *
   * @param  args - one or more slices to encode
   *     in big-endian format (i.e. earlier elements are higher bits)
   */
  constructor(...args) {
    super(args);
  }
  get unsigned() {
    return false;
  }
  get size() {
    return 128;
  }
}
Int128.defineIntBoundaries();

export { Int128 };
//# sourceMappingURL=int128.js.map
