import { Buffer } from 'buffer';
import '../node_modules/.pnpm/@stellar_js-xdr@4.0.0/node_modules/@stellar/js-xdr/src/int.js';
import '../node_modules/.pnpm/@stellar_js-xdr@4.0.0/node_modules/@stellar/js-xdr/src/hyper.js';
import '../node_modules/.pnpm/@stellar_js-xdr@4.0.0/node_modules/@stellar/js-xdr/src/unsigned-int.js';
import '../node_modules/.pnpm/@stellar_js-xdr@4.0.0/node_modules/@stellar/js-xdr/src/unsigned-hyper.js';
import '../node_modules/.pnpm/@stellar_js-xdr@4.0.0/node_modules/@stellar/js-xdr/src/xdr-type.js';
import '../base/generated/curr_generated.js';
import '@noble/hashes/sha2.js';
import '../base/signing.js';
import { Keypair } from '../base/keypair.js';
import 'base32.js';
import { Transaction } from '../base/transaction.js';
import { FeeBumpTransaction } from '../base/fee_bump_transaction.js';
import { TransactionBuilder, BASE_FEE, TimeoutInfinite } from '../base/transaction_builder.js';
import { Operation } from '../base/operation.js';
import { Memo, MemoNone, MemoID } from '../base/memo.js';
import { Account } from '../base/account.js';
import '../base/muxed_account.js';
import '../base/scval.js';
import '../base/numbers/uint128.js';
import '../base/numbers/uint256.js';
import '../base/numbers/int128.js';
import '../base/numbers/int256.js';
import { InvalidChallengeError } from './errors.js';
import { verifyTxSignedBy, gatherTxSigners } from './utils.js';
import { Utils } from '../utils.js';
import { uint8ArrayToBase64 } from 'uint8array-extras';

function buildChallengeTx(serverKeypair, clientAccountID, homeDomain, timeout = 300, networkPassphrase, webAuthDomain, memo = null, clientDomain = null, clientSigningKey = null) {
  if (clientAccountID.startsWith("M") && memo) {
    throw Error("memo cannot be used if clientAccountID is a muxed account");
  }
  const account = new Account(serverKeypair.publicKey(), "-1");
  const now = Math.floor(Date.now() / 1e3);
  const value = uint8ArrayToBase64(crypto.getRandomValues(new Uint8Array(48)));
  const builder = new TransactionBuilder(account, {
    fee: BASE_FEE,
    networkPassphrase,
    timebounds: {
      minTime: now,
      maxTime: now + timeout
    }
  }).addOperation(
    Operation.manageData({
      name: `${homeDomain} auth`,
      value,
      source: clientAccountID
    })
  ).addOperation(
    Operation.manageData({
      name: "web_auth_domain",
      value: webAuthDomain,
      source: account.accountId()
    })
  );
  if (clientDomain) {
    if (!clientSigningKey) {
      throw Error("clientSigningKey is required if clientDomain is provided");
    }
    builder.addOperation(
      Operation.manageData({
        name: `client_domain`,
        value: clientDomain,
        source: clientSigningKey
      })
    );
  }
  if (memo) {
    builder.addMemo(Memo.id(memo));
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
  let transaction;
  try {
    transaction = new Transaction(challengeTx, networkPassphrase);
  } catch {
    try {
      transaction = new FeeBumpTransaction(challengeTx, networkPassphrase);
    } catch {
      throw new InvalidChallengeError(
        "Invalid challenge: unable to deserialize challengeTx transaction string"
      );
    }
    throw new InvalidChallengeError(
      "Invalid challenge: expected a Transaction but received a FeeBumpTransaction"
    );
  }
  const sequence = Number.parseInt(transaction.sequence, 10);
  if (sequence !== 0) {
    throw new InvalidChallengeError(
      "The transaction sequence number should be zero"
    );
  }
  if (transaction.source !== serverAccountID) {
    throw new InvalidChallengeError(
      "The transaction source account is not equal to the server's account"
    );
  }
  if (transaction.operations.length < 1) {
    throw new InvalidChallengeError(
      "The transaction should contain at least one operation"
    );
  }
  const [operation, ...subsequentOperations] = transaction.operations;
  if (!operation.source) {
    throw new InvalidChallengeError(
      "The transaction's operation should contain a source account"
    );
  }
  const clientAccountID = operation.source;
  let memo = null;
  if (transaction.memo.type !== MemoNone) {
    if (clientAccountID.startsWith("M")) {
      throw new InvalidChallengeError(
        "The transaction has a memo but the client account ID is a muxed account"
      );
    }
    if (transaction.memo.type !== MemoID) {
      throw new InvalidChallengeError(
        "The transaction's memo must be of type `id`"
      );
    }
    memo = transaction.memo.value;
  }
  if (operation.type !== "manageData") {
    throw new InvalidChallengeError(
      "The transaction's operation type should be 'manageData'"
    );
  }
  if (transaction.timeBounds && Number.parseInt(transaction.timeBounds?.maxTime, 10) === TimeoutInfinite) {
    throw new InvalidChallengeError(
      "The transaction requires non-infinite timebounds"
    );
  }
  if (!Utils.validateTimebounds(transaction, 60 * 5)) {
    throw new InvalidChallengeError("The transaction has expired");
  }
  if (operation.value === void 0) {
    throw new InvalidChallengeError(
      "The transaction's operation values should not be null"
    );
  }
  if (!operation.value) {
    throw new InvalidChallengeError(
      "The transaction's operation value should not be null"
    );
  }
  if (Buffer.from(operation.value.toString(), "base64").length !== 48) {
    throw new InvalidChallengeError(
      "The transaction's operation value should be a 64 bytes base64 random string"
    );
  }
  if (!homeDomains) {
    throw new InvalidChallengeError(
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
    throw new InvalidChallengeError(
      `Invalid homeDomains: homeDomains type is ${typeof homeDomains} but should be a string or an array`
    );
  }
  if (!matchedHomeDomain) {
    throw new InvalidChallengeError(
      "Invalid homeDomains: the transaction's operation key name does not match the expected home domain"
    );
  }
  for (const op of subsequentOperations) {
    if (op.type !== "manageData") {
      throw new InvalidChallengeError(
        "The transaction has operations that are not of type 'manageData'"
      );
    }
    if (op.source !== serverAccountID && op.name !== "client_domain") {
      throw new InvalidChallengeError(
        "The transaction has operations that are unrecognized"
      );
    }
    if (op.name === "web_auth_domain") {
      if (op.value === void 0) {
        throw new InvalidChallengeError(
          "'web_auth_domain' operation value should not be null"
        );
      }
      if (op.value.compare(Buffer.from(webAuthDomain))) {
        throw new InvalidChallengeError(
          `'web_auth_domain' operation value does not match ${webAuthDomain}`
        );
      }
    }
  }
  if (!verifyTxSignedBy(transaction, serverAccountID)) {
    throw new InvalidChallengeError(
      `Transaction not signed by server: '${serverAccountID}'`
    );
  }
  return { tx: transaction, clientAccountID, matchedHomeDomain, memo };
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
    serverKP = Keypair.fromPublicKey(serverAccountID);
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
    throw new InvalidChallengeError(
      "No verifiable client signers provided, at least one G... address must be provided"
    );
  }
  let clientSigningKey;
  for (const op of tx.operations) {
    if (op.type === "manageData" && op.name === "client_domain") {
      if (clientSigningKey) {
        throw new InvalidChallengeError(
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
  const signersFound = gatherTxSigners(tx, allSigners);
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
    throw new InvalidChallengeError(
      `Transaction not signed by server: '${serverKP.publicKey()}'`
    );
  }
  if (clientSigningKey && !clientSigningKeySignatureFound) {
    throw new InvalidChallengeError(
      "Transaction not signed by the source account of the 'client_domain' ManageData operation"
    );
  }
  if (signersFound.length === 1) {
    throw new InvalidChallengeError(
      "None of the given signers match the transaction signatures"
    );
  }
  if (signersFound.length !== tx.signatures.length) {
    throw new InvalidChallengeError("Transaction has unrecognized signatures");
  }
  signersFound.splice(signersFound.indexOf(serverKP.publicKey()), 1);
  if (clientSigningKey) {
    signersFound.splice(signersFound.indexOf(clientSigningKey), 1);
  }
  if (signersFound.length === 0) {
    throw new InvalidChallengeError(
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
    throw new InvalidChallengeError(
      `signers with weight ${weight} do not meet threshold ${threshold}"`
    );
  }
  return signersFound;
}

export { buildChallengeTx, readChallengeTx, verifyChallengeTxSigners, verifyChallengeTxThreshold };
//# sourceMappingURL=challenge_transaction.js.map
