import '../node_modules/.pnpm/@stellar_js-xdr@4.0.0/node_modules/@stellar/js-xdr/src/int.js';
import '../node_modules/.pnpm/@stellar_js-xdr@4.0.0/node_modules/@stellar/js-xdr/src/hyper.js';
import '../node_modules/.pnpm/@stellar_js-xdr@4.0.0/node_modules/@stellar/js-xdr/src/unsigned-int.js';
import '../node_modules/.pnpm/@stellar_js-xdr@4.0.0/node_modules/@stellar/js-xdr/src/unsigned-hyper.js';
import '../node_modules/.pnpm/@stellar_js-xdr@4.0.0/node_modules/@stellar/js-xdr/src/xdr-type.js';
import 'buffer';
import '../base/generated/curr_generated.js';
import '@noble/hashes/sha2.js';
import '../base/signing.js';
import { Keypair } from '../base/keypair.js';
import 'base32.js';
import '../base/util/continued_fraction.js';
import '../base/util/bignumber.js';
import '../base/transaction_builder.js';
import '../base/muxed_account.js';
import '../base/scval.js';
import '../base/numbers/uint128.js';
import '../base/numbers/uint256.js';
import '../base/numbers/int128.js';
import '../base/numbers/int256.js';
import { InvalidChallengeError } from './errors.js';

function gatherTxSigners(transaction, signers) {
  const hashedSignatureBase = transaction.hash();
  const txSignatures = [...transaction.signatures];
  const signersFound = /* @__PURE__ */ new Set();
  for (const signer of signers) {
    if (txSignatures.length === 0) {
      break;
    }
    let keypair;
    try {
      keypair = Keypair.fromPublicKey(signer);
    } catch (err) {
      throw new InvalidChallengeError(
        `Signer is not a valid address: ${err.message}`
      );
    }
    for (let i = 0; i < txSignatures.length; i++) {
      const decSig = txSignatures[i];
      if (!decSig.hint().equals(keypair.signatureHint())) {
        continue;
      }
      if (keypair.verify(hashedSignatureBase, decSig.signature())) {
        signersFound.add(signer);
        txSignatures.splice(i, 1);
        break;
      }
    }
  }
  return Array.from(signersFound);
}
function verifyTxSignedBy(transaction, accountID) {
  return gatherTxSigners(transaction, [accountID]).length !== 0;
}

export { gatherTxSigners, verifyTxSignedBy };
//# sourceMappingURL=utils.js.map
