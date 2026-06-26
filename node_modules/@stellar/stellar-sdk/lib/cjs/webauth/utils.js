'use strict';

require('../node_modules/.pnpm/@stellar_js-xdr@4.0.0/node_modules/@stellar/js-xdr/src/int.js');
require('../node_modules/.pnpm/@stellar_js-xdr@4.0.0/node_modules/@stellar/js-xdr/src/hyper.js');
require('../node_modules/.pnpm/@stellar_js-xdr@4.0.0/node_modules/@stellar/js-xdr/src/unsigned-int.js');
require('../node_modules/.pnpm/@stellar_js-xdr@4.0.0/node_modules/@stellar/js-xdr/src/unsigned-hyper.js');
require('../node_modules/.pnpm/@stellar_js-xdr@4.0.0/node_modules/@stellar/js-xdr/src/xdr-type.js');
require('buffer');
require('../base/generated/curr_generated.js');
require('@noble/hashes/sha2.js');
require('../base/signing.js');
var keypair = require('../base/keypair.js');
require('base32.js');
require('../base/util/continued_fraction.js');
require('../base/util/bignumber.js');
require('../base/transaction_builder.js');
require('../base/muxed_account.js');
require('../base/scval.js');
require('../base/numbers/uint128.js');
require('../base/numbers/uint256.js');
require('../base/numbers/int128.js');
require('../base/numbers/int256.js');
var errors = require('./errors.js');

function gatherTxSigners(transaction, signers) {
  const hashedSignatureBase = transaction.hash();
  const txSignatures = [...transaction.signatures];
  const signersFound = /* @__PURE__ */ new Set();
  for (const signer of signers) {
    if (txSignatures.length === 0) {
      break;
    }
    let keypair$1;
    try {
      keypair$1 = keypair.Keypair.fromPublicKey(signer);
    } catch (err) {
      throw new errors.InvalidChallengeError(
        `Signer is not a valid address: ${err.message}`
      );
    }
    for (let i = 0; i < txSignatures.length; i++) {
      const decSig = txSignatures[i];
      if (!decSig.hint().equals(keypair$1.signatureHint())) {
        continue;
      }
      if (keypair$1.verify(hashedSignatureBase, decSig.signature())) {
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

exports.gatherTxSigners = gatherTxSigners;
exports.verifyTxSignedBy = verifyTxSignedBy;
//# sourceMappingURL=utils.js.map
