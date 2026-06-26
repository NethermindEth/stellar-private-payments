import { Buffer } from 'buffer';
import '../node_modules/.pnpm/@stellar_js-xdr@4.0.0/node_modules/@stellar/js-xdr/src/int.js';
import '../node_modules/.pnpm/@stellar_js-xdr@4.0.0/node_modules/@stellar/js-xdr/src/hyper.js';
import '../node_modules/.pnpm/@stellar_js-xdr@4.0.0/node_modules/@stellar/js-xdr/src/unsigned-int.js';
import '../node_modules/.pnpm/@stellar_js-xdr@4.0.0/node_modules/@stellar/js-xdr/src/unsigned-hyper.js';
import '../node_modules/.pnpm/@stellar_js-xdr@4.0.0/node_modules/@stellar/js-xdr/src/xdr-type.js';
import '../base/generated/curr_generated.js';
import { hash } from '../base/hashing.js';
import '../base/signing.js';
import '../base/keypair.js';
import 'base32.js';
import '../base/util/continued_fraction.js';
import '../base/util/bignumber.js';
import { TransactionBuilder } from '../base/transaction_builder.js';
import '../base/muxed_account.js';
import '../base/scval.js';
import '../base/numbers/uint128.js';
import '../base/numbers/uint256.js';
import '../base/numbers/int128.js';
import '../base/numbers/int256.js';

const basicNodeSigner = (keypair, networkPassphrase) => ({
  // eslint-disable-next-line @typescript-eslint/require-await
  signTransaction: async (xdr, opts) => {
    const t = TransactionBuilder.fromXDR(
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
    const signedAuthEntry = keypair.sign(hash(Buffer.from(authEntry, "base64"))).toString("base64");
    return {
      signedAuthEntry,
      signerAddress: keypair.publicKey()
    };
  }
});

export { basicNodeSigner };
//# sourceMappingURL=basic_node_signer.js.map
