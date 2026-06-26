'use strict';

var buffer = require('buffer');
require('../node_modules/.pnpm/@stellar_js-xdr@4.0.0/node_modules/@stellar/js-xdr/src/int.js');
require('../node_modules/.pnpm/@stellar_js-xdr@4.0.0/node_modules/@stellar/js-xdr/src/hyper.js');
require('../node_modules/.pnpm/@stellar_js-xdr@4.0.0/node_modules/@stellar/js-xdr/src/unsigned-int.js');
require('../node_modules/.pnpm/@stellar_js-xdr@4.0.0/node_modules/@stellar/js-xdr/src/unsigned-hyper.js');
require('../node_modules/.pnpm/@stellar_js-xdr@4.0.0/node_modules/@stellar/js-xdr/src/xdr-type.js');
require('../base/generated/curr_generated.js');
require('@noble/hashes/sha2.js');
require('../base/signing.js');
var keypair = require('../base/keypair.js');
require('base32.js');
var transaction = require('../base/transaction.js');
var fee_bump_transaction = require('../base/fee_bump_transaction.js');
var transaction_builder = require('../base/transaction_builder.js');
var operation = require('../base/operation.js');
var memo = require('../base/memo.js');
var account = require('../base/account.js');
require('../base/muxed_account.js');
require('../base/scval.js');
require('../base/numbers/uint128.js');
require('../base/numbers/uint256.js');
require('../base/numbers/int128.js');
require('../base/numbers/int256.js');
var errors = require('./errors.js');
var utils$1 = require('./utils.js');
var utils = require('../utils.js');
var uint8arrayExtras = require('uint8array-extras');

function buildChallengeTx(serverKeypair, clientAccountID, homeDomain, timeout = 300, networkPassphrase, webAuthDomain, memo$1 = null, clientDomain = null, clientSigningKey = null) {
  if (clientAccountID.startsWith("M") && memo$1) {
    throw Error("memo cannot be used if clientAccountID is a muxed account");
  }
  const account$1 = new account.Account(serverKeypair.publicKey(), "-1");
  const now = Math.floor(Date.now() / 1e3);
  const value = uint8arrayExtras.uint8ArrayToBase64(crypto.getRandomValues(new Uint8Array(48)));
  const builder = new transaction_builder.TransactionBuilder(account$1, {
    fee: transaction_builder.BASE_FEE,
    networkPassphrase,
    timebounds: {
      minTime: now,
      maxTime: now + timeout
    }
  }).addOperation(
    operation.Operation.manageData({
      name: `${homeDomain} auth`,
      value,
      source: clientAccountID
    })
  ).addOperation(
    operation.Operation.manageData({
      name: "web_auth_domain",
      value: webAuthDomain,
      source: account$1.accountId()
    })
  );
  if (clientDomain) {
    if (!clientSigningKey) {
      throw Error("clientSigningKey is required if clientDomain is provided");
    }
    builder.addOperation(
      operation.Operation.manageData({
        name: `client_domain`,
        value: clientDomain,
        source: clientSigningKey
      })
    );
  }
  if (memo$1) {
    builder.addMemo(memo.Memo.id(memo$1));
  }
  const transaction = builder.build();
  transaction.sign(serverKeypair);
  return transaction.toEnvelope().toXDR("base64").toString();
}
function readChallengeTx(challengeTx, serverAccountID, networkPassphrase, homeDomains, webAuthDomain) {
  if (serverAccountID.startsWith("M")) {
    throw Error(
      "Invalid serverAccountID: multiplexed accounts are not supported."
    );
  }
  let transaction$1;
  try {
    transaction$1 = new transaction.Transaction(challengeTx, networkPassphrase);
  } catch {
    try {
      transaction$1 = new fee_bump_transaction.FeeBumpTransaction(challengeTx, networkPassphrase);
    } catch {
      throw new errors.InvalidChallengeError(
        "Invalid challenge: unable to deserialize challengeTx transaction string"
      );
    }
    throw new errors.InvalidChallengeError(
      "Invalid challenge: expected a Transaction but received a FeeBumpTransaction"
    );
  }
  const sequence = Number.parseInt(transaction$1.sequence, 10);
  if (sequence !== 0) {
    throw new errors.InvalidChallengeError(
      "The transaction sequence number should be zero"
    );
  }
  if (transaction$1.source !== serverAccountID) {
    throw new errors.InvalidChallengeError(
      "The transaction source account is not equal to the server's account"
    );
  }
  if (transaction$1.operations.length < 1) {
    throw new errors.InvalidChallengeError(
      "The transaction should contain at least one operation"
    );
  }
  const [operation, ...subsequentOperations] = transaction$1.operations;
  if (!operation.source) {
    throw new errors.InvalidChallengeError(
      "The transaction's operation should contain a source account"
    );
  }
  const clientAccountID = operation.source;
  let memo$1 = null;
  if (transaction$1.memo.type !== memo.MemoNone) {
    if (clientAccountID.startsWith("M")) {
      throw new errors.InvalidChallengeError(
        "The transaction has a memo but the client account ID is a muxed account"
      );
    }
    if (transaction$1.memo.type !== memo.MemoID) {
      throw new errors.InvalidChallengeError(
        "The transaction's memo must be of type `id`"
      );
    }
    memo$1 = transaction$1.memo.value;
  }
  if (operation.type !== "manageData") {
    throw new errors.InvalidChallengeError(
      "The transaction's operation type should be 'manageData'"
    );
  }
  if (transaction$1.timeBounds && Number.parseInt(transaction$1.timeBounds?.maxTime, 10) === transaction_builder.TimeoutInfinite) {
    throw new errors.InvalidChallengeError(
      "The transaction requires non-infinite timebounds"
    );
  }
  if (!utils.Utils.validateTimebounds(transaction$1, 60 * 5)) {
    throw new errors.InvalidChallengeError("The transaction has expired");
  }
  if (operation.value === void 0) {
    throw new errors.InvalidChallengeError(
      "The transaction's operation values should not be null"
    );
  }
  if (!operation.value) {
    throw new errors.InvalidChallengeError(
      "The transaction's operation value should not be null"
    );
  }
  if (buffer.Buffer.from(operation.value.toString(), "base64").length !== 48) {
    throw new errors.InvalidChallengeError(
      "The transaction's operation value should be a 64 bytes base64 random string"
    );
  }
  if (!homeDomains) {
    throw new errors.InvalidChallengeError(
      "Invalid homeDomains: a home domain must be provided for verification"
    );
  }
  let matchedHomeDomain;
  if (typeof homeDomains === "string") {
    if (`${homeDomains} auth` === operation.name) {
      matchedHomeDomain = homeDomains;
    }
  } else if (Array.isArray(homeDomains)) {
    matchedHomeDomain = homeDomains.find(
      (domain) => `${domain} auth` === operation.name
    );
  } else {
    throw new errors.InvalidChallengeError(
      `Invalid homeDomains: homeDomains type is ${typeof homeDomains} but should be a string or an array`
    );
  }
  if (!matchedHomeDomain) {
    throw new errors.InvalidChallengeError(
      "Invalid homeDomains: the transaction's operation key name does not match the expected home domain"
    );
  }
  for (const op of subsequentOperations) {
    if (op.type !== "manageData") {
      throw new errors.InvalidChallengeError(
        "The transaction has operations that are not of type 'manageData'"
      );
    }
    if (op.source !== serverAccountID && op.name !== "client_domain") {
      throw new errors.InvalidChallengeError(
        "The transaction has operations that are unrecognized"
      );
    }
    if (op.name === "web_auth_domain") {
      if (op.value === void 0) {
        throw new errors.InvalidChallengeError(
          "'web_auth_domain' operation value should not be null"
        );
      }
      if (op.value.compare(buffer.Buffer.from(webAuthDomain))) {
        throw new errors.InvalidChallengeError(
          `'web_auth_domain' operation value does not match ${webAuthDomain}`
        );
      }
    }
  }
  if (!utils$1.verifyTxSignedBy(transaction$1, serverAccountID)) {
    throw new errors.InvalidChallengeError(
      `Transaction not signed by server: '${serverAccountID}'`
    );
  }
  return { tx: transaction$1, clientAccountID, matchedHomeDomain, memo: memo$1 };
}
function verifyChallengeTxSigners(challengeTx, serverAccountID, networkPassphrase, signers, homeDomains, webAuthDomain) {
  const { tx } = readChallengeTx(
    challengeTx,
    serverAccountID,
    networkPassphrase,
    homeDomains,
    webAuthDomain
  );
  let serverKP;
  try {
    serverKP = keypair.Keypair.fromPublicKey(serverAccountID);
  } catch (err) {
    throw new Error(
      `Couldn't infer keypair from the provided 'serverAccountID': ${err.message}`
    );
  }
  const clientSigners = /* @__PURE__ */ new Set();
  for (const signer of signers) {
    if (signer === serverKP.publicKey()) {
      continue;
    }
    if (signer.charAt(0) !== "G") {
      continue;
    }
    clientSigners.add(signer);
  }
  if (clientSigners.size === 0) {
    throw new errors.InvalidChallengeError(
      "No verifiable client signers provided, at least one G... address must be provided"
    );
  }
  let clientSigningKey;
  for (const op of tx.operations) {
    if (op.type === "manageData" && op.name === "client_domain") {
      if (clientSigningKey) {
        throw new errors.InvalidChallengeError(
          "Found more than one client_domain operation"
        );
      }
      clientSigningKey = op.source;
    }
  }
  const allSigners = [
    serverKP.publicKey(),
    ...Array.from(clientSigners)
  ];
  if (clientSigningKey) {
    allSigners.push(clientSigningKey);
  }
  const signersFound = utils$1.gatherTxSigners(tx, allSigners);
  let serverSignatureFound = false;
  let clientSigningKeySignatureFound = false;
  for (const signer of signersFound) {
    if (signer === serverKP.publicKey()) {
      serverSignatureFound = true;
    }
    if (signer === clientSigningKey) {
      clientSigningKeySignatureFound = true;
    }
  }
  if (!serverSignatureFound) {
    throw new errors.InvalidChallengeError(
      `Transaction not signed by server: '${serverKP.publicKey()}'`
    );
  }
  if (clientSigningKey && !clientSigningKeySignatureFound) {
    throw new errors.InvalidChallengeError(
      "Transaction not signed by the source account of the 'client_domain' ManageData operation"
    );
  }
  if (signersFound.length === 1) {
    throw new errors.InvalidChallengeError(
      "None of the given signers match the transaction signatures"
    );
  }
  if (signersFound.length !== tx.signatures.length) {
    throw new errors.InvalidChallengeError("Transaction has unrecognized signatures");
  }
  signersFound.splice(signersFound.indexOf(serverKP.publicKey()), 1);
  if (clientSigningKey) {
    signersFound.splice(signersFound.indexOf(clientSigningKey), 1);
  }
  if (signersFound.length === 0) {
    throw new errors.InvalidChallengeError(
      "None of the given signers match the transaction signatures"
    );
  }
  return signersFound;
}
function verifyChallengeTxThreshold(challengeTx, serverAccountID, networkPassphrase, threshold, signerSummary, homeDomains, webAuthDomain) {
  const signers = signerSummary.map((signer) => signer.key);
  const signersFound = verifyChallengeTxSigners(
    challengeTx,
    serverAccountID,
    networkPassphrase,
    signers,
    homeDomains,
    webAuthDomain
  );
  let weight = 0;
  for (const signer of signersFound) {
    const sigWeight = signerSummary.find((s) => s.key === signer)?.weight || 0;
    weight += sigWeight;
  }
  if (weight < threshold) {
    throw new errors.InvalidChallengeError(
      `signers with weight ${weight} do not meet threshold ${threshold}"`
    );
  }
  return signersFound;
}

exports.buildChallengeTx = buildChallengeTx;
exports.readChallengeTx = readChallengeTx;
exports.verifyChallengeTxSigners = verifyChallengeTxSigners;
exports.verifyChallengeTxThreshold = verifyChallengeTxThreshold;
//# sourceMappingURL=challenge_transaction.js.map
