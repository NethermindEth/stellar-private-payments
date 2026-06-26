'use strict';

var buffer = require('buffer');
require('../node_modules/.pnpm/@stellar_js-xdr@4.0.0/node_modules/@stellar/js-xdr/src/int.js');
require('../node_modules/.pnpm/@stellar_js-xdr@4.0.0/node_modules/@stellar/js-xdr/src/hyper.js');
require('../node_modules/.pnpm/@stellar_js-xdr@4.0.0/node_modules/@stellar/js-xdr/src/unsigned-int.js');
require('../node_modules/.pnpm/@stellar_js-xdr@4.0.0/node_modules/@stellar/js-xdr/src/unsigned-hyper.js');
require('../node_modules/.pnpm/@stellar_js-xdr@4.0.0/node_modules/@stellar/js-xdr/src/xdr-type.js');
require('../base/generated/curr_generated.js');
var hashing = require('../base/hashing.js');
require('../base/signing.js');
require('../base/keypair.js');
require('base32.js');
require('../base/util/continued_fraction.js');
require('../base/util/bignumber.js');
var transaction_builder = require('../base/transaction_builder.js');
require('../base/muxed_account.js');
require('../base/scval.js');
require('../base/numbers/uint128.js');
require('../base/numbers/uint256.js');
require('../base/numbers/int128.js');
require('../base/numbers/int256.js');

const basicNodeSigner = (keypair, networkPassphrase) => ({
  // eslint-disable-next-line @typescript-eslint/require-await
  signTransaction: async (xdr, opts) => {
    const t = transaction_builder.TransactionBuilder.fromXDR(
      xdr,
      opts?.networkPassphrase || networkPassphrase
    );
    t.sign(keypair);
    return {
      signedTxXdr: t.toXDR(),
      signerAddress: keypair.publicKey()
    };
  },
  // eslint-disable-next-line @typescript-eslint/require-await
  signAuthEntry: async (authEntry) => {
    const signedAuthEntry = keypair.sign(hashing.hash(buffer.Buffer.from(authEntry, "base64"))).toString("base64");
    return {
      signedAuthEntry,
      signerAddress: keypair.publicKey()
    };
  }
});

exports.basicNodeSigner = basicNodeSigner;
//# sourceMappingURL=basic_node_signer.js.map
