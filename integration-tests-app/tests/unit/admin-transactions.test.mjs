import assert from 'node:assert/strict';
import test from 'node:test';

import {
  Account,
  Address,
  Contract,
  Keypair,
  MuxedAccount,
  Networks,
  Operation,
  SorobanDataBuilder,
  StrKey,
  TransactionBuilder,
  nativeToScVal,
  xdr,
} from '@stellar/stellar-sdk';

import {
  adminTxFromHash,
  adminTxLink,
  custodyProblems,
  deadCall,
  describeAdminCall,
  extendCommand,
  explainFailure,
  finishAdminCall,
  hex,
  hostError,
  liveFootprintKeys,
  newAdminRefusal,
  NoAnswer,
  repointsTo,
  rpcServer,
  shortLivedEntries,
  signatureCount,
  signedBy,
  signedWeight,
  signerStatus,
  signingRule,
  signRefusal,
  submitAdminCall,
  withRentMargin,
} from '../../../app/js/admin-transactions.js';
import { CONTRACT_ERRORS } from '../../../app/js/ui/errors.js';

const ADMIN = Keypair.random().publicKey();
const TREE = 'CBZAWV3AKKKIIO3LEIF7DHODHHHTTL47M7WQSZYTU3ZYSBMM32MUM5H4';

// An insert_leaf call from the admin account, before its conditions are set.
function insertLeafBuilder() {
  return new TransactionBuilder(new Account(ADMIN, '41'), {
    fee: '100',
    networkPassphrase: Networks.TESTNET,
  }).addOperation(new Contract(TREE).call('insert_leaf', nativeToScVal(42n, { type: 'u256' })));
}

function insertLeafEnvelope(...extraOperations) {
  const builder = insertLeafBuilder();
  extraOperations.forEach((operation) => builder.addOperation(operation));
  return builder.setTimeout(86_400).build();
}

test('describeAdminCall reads the contract, function, and arguments of an insert_leaf call', () => {
  const call = describeAdminCall(insertLeafEnvelope().toXdr(), Networks.TESTNET);
  assert.equal(call.source, ADMIN);
  assert.equal(call.sequence, '42');
  assert.equal(call.contract, TREE);
  assert.equal(call.method, 'insert_leaf');
  assert.deepEqual(call.args, [42n]);
});

test('describeAdminCall refuses an envelope that holds a second operation', () => {
  const envelope = insertLeafEnvelope(Operation.setOptions({ masterWeight: 0 }));
  assert.throws(
    () => describeAdminCall(envelope.toXdr(), Networks.TESTNET),
    /something other than one contract call/,
  );
});

test('describeAdminCall refuses a minimum sequence and a time bound with no end', () => {
  for (const envelope of [
    insertLeafBuilder().setMinAccountSequence('1').setTimeout(86_400).build(),
    insertLeafBuilder().setTimeout(0).build(),
  ]) {
    assert.throws(() => describeAdminCall(envelope.toXdr(), Networks.TESTNET), /conditions other than a time bound/);
  }
});

test('describeAdminCall refuses a fee bump around a call', () => {
  const envelope = TransactionBuilder.buildFeeBumpTransaction(Keypair.random(), '1000', insertLeafEnvelope(), Networks.TESTNET);
  assert.throws(() => describeAdminCall(envelope.toXdr(), Networks.TESTNET), /fee bump/);
});

// An insert_leaf call carrying one authorization entry for `invocation` and its
// `subInvocations`, from an operation whose own source is `source`.
function authorizedInsertLeaf(credentials, { invocation, subInvocations = [], source } = {}) {
  const insertLeaf = new xdr.InvokeContractArgs({
    contractAddress: new Address(TREE).toScAddress(),
    functionName: 'insert_leaf',
    args: [nativeToScVal(42n, { type: 'u256' })],
  });
  const entry = new xdr.SorobanAuthorizationEntry({
    credentials,
    rootInvocation: new xdr.SorobanAuthorizedInvocation({
      function: xdr.SorobanAuthorizedFunction.sorobanAuthorizedFunctionTypeContractFn(invocation ?? insertLeaf),
      subInvocations,
    }),
  });
  return new TransactionBuilder(new Account(ADMIN, '41'), { fee: '100', networkPassphrase: Networks.TESTNET })
    .addOperation(Operation.invokeHostFunction({ func: xdr.HostFunction.hostFunctionTypeInvokeContract(insertLeaf), auth: [entry], source }))
    .setTimeout(86_400)
    .build()
    .toXdr();
}

test('describeAdminCall reads a call its source authorizes', () => {
  const envelope = authorizedInsertLeaf(xdr.SorobanCredentials.sorobanCredentialsSourceAccount());
  assert.equal(describeAdminCall(envelope, Networks.TESTNET).method, 'insert_leaf');
});

test('describeAdminCall refuses an authorization from another account or for another call', () => {
  const otherAccount = xdr.SorobanCredentials.sorobanCredentialsAddress(new xdr.SorobanAddressCredentials({
    address: new Address(Keypair.random().publicKey()).toScAddress(),
    nonce: 1n,
    signatureExpirationLedger: 100,
    signature: xdr.ScVal.scvVoid(),
  }));
  assert.throws(
    () => describeAdminCall(authorizedInsertLeaf(otherAccount), Networks.TESTNET),
    /authorizes something other than this call/,
  );
  const deleteLeaf = new xdr.InvokeContractArgs({
    contractAddress: new Address(TREE).toScAddress(),
    functionName: 'delete_leaf',
    args: [nativeToScVal(7n, { type: 'u256' })],
  });
  const sourceAccount = xdr.SorobanCredentials.sorobanCredentialsSourceAccount();
  assert.throws(
    () => describeAdminCall(authorizedInsertLeaf(sourceAccount, { invocation: deleteLeaf }), Networks.TESTNET),
    /authorizes something other than this call/,
  );
  const nested = new xdr.SorobanAuthorizedInvocation({
    function: xdr.SorobanAuthorizedFunction.sorobanAuthorizedFunctionTypeContractFn(deleteLeaf),
    subInvocations: [],
  });
  assert.throws(
    () => describeAdminCall(authorizedInsertLeaf(sourceAccount, { subInvocations: [nested] }), Networks.TESTNET),
    /authorizes something other than this call/,
  );
});

test('describeAdminCall refuses an operation whose source is not the transaction\'s', () => {
  const sourceAccount = xdr.SorobanCredentials.sorobanCredentialsSourceAccount();
  assert.throws(
    () => describeAdminCall(authorizedInsertLeaf(sourceAccount, { source: Keypair.random().publicKey() }), Networks.TESTNET),
    /authorizes something other than this call/,
  );
  assert.equal(describeAdminCall(authorizedInsertLeaf(sourceAccount, { source: ADMIN }), Networks.TESTNET).method, 'insert_leaf');
});

test('withRentMargin raises the refundable fee and the fee by the same margin and keeps the call', () => {
  const built = insertLeafBuilder().setSorobanData(new SorobanDataBuilder().setResourceFee(1_213n).build()).setTimeout(86_400).build();
  const padded = TransactionBuilder.fromXdr(withRentMargin(built.toXdr(), Networks.TESTNET), Networks.TESTNET);
  const resourceFee = (tx) => tx.toEnvelope().value.tx.ext.value.resourceFee;
  assert.equal(resourceFee(padded) - resourceFee(built), 100_000n);
  assert.equal(Number(padded.fee) - Number(built.fee), 100_000);
  assert.deepEqual(describeAdminCall(padded.toXdr(), Networks.TESTNET), {
    ...describeAdminCall(built.toXdr(), Networks.TESTNET),
    fee: padded.fee,
  });
});

const treeKey = (name) => xdr.LedgerKey.contractData(new xdr.LedgerKeyContractData({
  contract: new Address(TREE).toScAddress(),
  key: xdr.ScVal.scvVec([xdr.ScVal.scvSymbol(name)]),
  durability: name === 'Temp' ? xdr.ContractDataDurability.temporary : xdr.ContractDataDurability.persistent,
}));

test('liveFootprintKeys keeps persistent entries and code but not temporary entries or ones the call restores', () => {
  const code = xdr.LedgerKey.contractCode(new xdr.LedgerKeyContractCode({ hash: Buffer.alloc(32) }));
  const data = new SorobanDataBuilder().setFootprint([code, treeKey('Temp')], [treeKey('Admin'), treeKey('Root')]).build();
  data.ext = xdr.SorobanTransactionDataExt.resourceExt(new xdr.SorobanResourcesExtV0({ archivedSorobanEntries: [1] }));
  const built = insertLeafBuilder().setSorobanData(data).setTimeout(86_400).build();
  const keys = liveFootprintKeys(built.toXdr(), Networks.TESTNET).map((key) => key.toXdr('base64'));
  assert.deepEqual(keys, [code, treeKey('Admin')].map((key) => key.toXdr('base64')));
});

test('shortLivedEntries keeps the entries that archive within the call\'s 24 hours, and only those', () => {
  const entries = [{ key: treeKey('Admin'), liveUntilLedgerSeq: 1_000 + 18_000 }, { key: treeKey('Root'), liveUntilLedgerSeq: 1_000 + 17_999 }];
  assert.deepEqual(shortLivedEntries(entries, 1_000), [treeKey('Root')]);
});

test('extendCommand names a data entry by its key, an instance by its contract, and code by its hash', () => {
  const args = [99_999, 'https://rpc.example.com', Networks.TESTNET];
  const tail = ` --ledgers-to-extend 99999 --source-account ACCOUNT --rpc-url https://rpc.example.com --network-passphrase '${Networks.TESTNET}'`;
  assert.equal(extendCommand(treeKey('Admin'), ...args), `stellar contract extend --id ${TREE} --key-xdr AAAAEAAAAAEAAAABAAAADwAAAAVBZG1pbgAAAA==${tail}`);
  assert.equal(extendCommand(new Contract(TREE).getFootprint(), ...args), `stellar contract extend --id ${TREE}${tail}`);
  const code = xdr.LedgerKey.contractCode(new xdr.LedgerKeyContractCode({ hash: new Uint8Array(32).fill(0xab) }));
  assert.equal(extendCommand(code, ...args), `stellar contract extend --wasm-hash ${'ab'.repeat(32)}${tail}`);
});

// A simulated insert_leaf reading the tree's `Admin` and `Root`, with an RPC
// stub whose entries live until `liveUntil` past ledger 1,000. Only a refused
// call reads `maxEntryTtl`.
function finishInsertLeaf(liveUntil, maxEntryTtl) {
  const data = new SorobanDataBuilder().setFootprint([treeKey('Admin')], [treeKey('Root')]).setResourceFee(1_213n).build();
  const simulated = insertLeafBuilder().setSorobanData(data).setTimeout(86_400).build();
  const server = {
    getLedgerEntries: async (...keys) => ({ latestLedger: 1_000, entries: keys.map((key) => ({ key, liveUntilLedgerSeq: 1_000 + liveUntil })) }),
    getLedgerEntry: async (key) => {
      assert.equal(key.value.configSettingId.name, 'configSettingStateArchival');
      assert.ok(maxEntryTtl);
      return { val: { configSetting: { stateArchivalSettings: { maxEntryTtl } } } };
    },
  };
  return finishAdminCall({ server, rpcUrl: 'https://rpc.example.com', networkPassphrase: Networks.TESTNET, xdr: simulated.toXdr() });
}

test('finishAdminCall pads the fee of a call whose entries outlive its 24 hours', async () => {
  const { xdr: padded } = await finishInsertLeaf(18_000);
  assert.equal(TransactionBuilder.fromXdr(padded, Networks.TESTNET).toEnvelope().value.tx.ext.value.resourceFee, 101_213n);
});

test('finishAdminCall refuses a call whose entries archive within its 24 hours, with a command for each', async () => {
  await assert.rejects(finishInsertLeaf(17_999, 100_000), (err) => {
    assert.match(err.message, /archive within its 24 hours/);
    assert.equal(err.extendCommands.length, 2);
    assert.match(err.extendCommands[0], / --ledgers-to-extend 99999 /);
    return true;
  });
});

test('signatureCount counts the signatures added to an envelope', () => {
  const envelope = insertLeafEnvelope();
  envelope.sign(Keypair.random());
  envelope.sign(Keypair.random());
  assert.equal(signatureCount(envelope.toXdr(), Networks.TESTNET), 2);
});

test('signedBy finds the signature of a key that signed and no other', () => {
  const envelope = insertLeafEnvelope();
  const signer = Keypair.random();
  envelope.sign(signer);
  assert.equal(signedBy(envelope.toXdr(), Networks.TESTNET, signer.publicKey()), true);
  assert.equal(signedBy(envelope.toXdr(), Networks.TESTNET, Keypair.random().publicKey()), false);
});

// The ledger entry of the admin account with `thresholds` and `signers`.
function adminAccount(thresholds, signers) {
  return new xdr.AccountEntry({
    accountId: Keypair.fromPublicKey(ADMIN).xdrAccountId(),
    balance: xdr.Int64.fromString('0'),
    seqNum: xdr.Int64.fromString('0'),
    numSubEntries: signers.length,
    inflationDest: null,
    flags: 0,
    homeDomain: '',
    thresholds: Buffer.from(thresholds),
    signers,
    ext: xdr.AccountEntryExt.v0(),
  });
}

test('signingRule reads the medium threshold and the weight of each key', () => {
  const signer = Keypair.random();
  const multisig = signingRule(adminAccount([0, 1, 2, 3], [
    new xdr.Signer({ key: xdr.SignerKey.signerKeyTypeEd25519(signer.rawPublicKey()), weight: 1 }),
  ]));
  assert.equal(multisig.threshold, 2);
  assert.equal(multisig.weights.get(signer.publicKey()), 1);
  assert.equal(multisig.weights.get(ADMIN), 0);
  assert.equal(multisig.weights.get(Keypair.random().publicKey()), undefined);
  const singleKey = signingRule(adminAccount([1, 0, 0, 0], []));
  assert.equal(singleKey.threshold, 1);
  assert.equal(singleKey.weights.get(ADMIN), 1);
});

// The signing rule of a 2-of-3 admin account whose own key has weight 0.
const [first, second, third] = [Keypair.random(), Keypair.random(), Keypair.random()];
const twoOfThree = {
  threshold: 2,
  weights: new Map([[ADMIN, 0], [first.publicKey(), 1], [second.publicKey(), 1], [third.publicKey(), 1]]),
};

// A signer key that is not ed25519: the hash-x key of 32 zero bytes.
const hashKey = StrKey.encodeSha256Hash(Buffer.alloc(32));

// An insert_leaf envelope carrying a signature by each of `signers`.
function envelopeSignedBy(...signers) {
  const envelope = insertLeafEnvelope();
  signers.forEach((signer) => envelope.sign(signer));
  return envelope.toXdr();
}

test('signRefusal refuses a key of weight 0, a signature past the threshold, and a second signature by one key', () => {
  assert.equal(
    signRefusal({ ...twoOfThree, weights: new Map([...twoOfThree.weights, [third.publicKey(), 0]]) }, envelopeSignedBy(), Networks.TESTNET, third.publicKey()),
    `${third.publicKey()} does not sign for ${ADMIN}`,
  );
  assert.equal(
    signRefusal(twoOfThree, envelopeSignedBy(first, second), Networks.TESTNET, third.publicKey()),
    'The envelope already carries the signatures it needs. Submit it.',
  );
  assert.equal(
    signRefusal(twoOfThree, envelopeSignedBy(first), Networks.TESTNET, first.publicKey()),
    'This account has already signed the envelope',
  );
});

test('signRefusal lets a signer who has not signed add a signature below the threshold', () => {
  assert.equal(signRefusal(twoOfThree, envelopeSignedBy(first), Networks.TESTNET, second.publicKey()), null);
});

test('signerStatus marks the signer who signed and the two who have not, gives null for a hash key, and leaves out the key of weight 0', () => {
  const rule = { ...twoOfThree, weights: new Map([...twoOfThree.weights, [hashKey, 1]]) };
  assert.deepEqual(signerStatus(rule, envelopeSignedBy(first), Networks.TESTNET), [
    { key: first.publicKey(), signed: true },
    { key: second.publicKey(), signed: false },
    { key: third.publicKey(), signed: false },
    { key: hashKey, signed: null },
  ]);
});

test('signedWeight sums the weights of the keys that signed, so one signature of weight 2 meets a threshold of 2, and counts nothing for a hash key', () => {
  const weighted = { ...twoOfThree, weights: new Map([...twoOfThree.weights, [first.publicKey(), 2], [hashKey, 1]]) };
  const envelope = envelopeSignedBy(first);
  assert.equal(signedWeight(weighted, envelope, Networks.TESTNET), 2);
  assert.equal(
    signRefusal(weighted, envelope, Networks.TESTNET, second.publicKey()),
    'The envelope already carries the signatures it needs. Submit it.',
  );
});

test('adminTxLink carries base64 holding +, /, and = through a URL to adminTxFromHash', () => {
  const envelope = 'AAAAAgAA+/8AAA==';
  const link = new URL(adminTxLink('https://example.com/admin.html', envelope));
  assert.equal(link.origin + link.pathname, 'https://example.com/admin.html');
  assert.equal(adminTxFromHash(link.hash), envelope);
});

test('adminTxFromHash gives an empty string for a fragment without tx=', () => {
  assert.equal(adminTxFromHash(''), '');
  assert.equal(adminTxFromHash('#admins'), '');
});

test('newAdminRefusal refuses an empty value, a secret, a muxed or corrupted address, the admin, and the pending admin', () => {
  const pending = Keypair.random().publicKey();
  const refusal = (value) => newAdminRefusal(value, { admin: ADMIN, pending });
  const notAnAddress = 'The new admin must be an account address (G...) or a contract address (C...)';
  assert.equal(refusal(''), 'The new admin\'s address is required');
  assert.equal(refusal(Keypair.random().secret()), notAnAddress);
  assert.equal(refusal(new MuxedAccount(new Account(ADMIN, '0'), '1').accountId()), notAnAddress);
  assert.equal(refusal(`${pending.slice(0, -1)}${pending.endsWith('A') ? 'B' : 'A'}`), notAnAddress);
  assert.equal(refusal(ADMIN), 'The new admin is already the contract\'s admin');
  assert.equal(refusal(pending), 'The new admin is already the pending admin');
});

test('newAdminRefusal lets an account or a contract address through', () => {
  assert.equal(newAdminRefusal(Keypair.random().publicKey(), { admin: ADMIN, pending: null }), null);
  assert.equal(newAdminRefusal(TREE, { admin: ADMIN, pending: null }), null);
});

// The signer entry of `keypair`'s key with `weight`.
const ed25519Signer = (keypair, weight = 1) =>
  new xdr.Signer({ key: xdr.SignerKey.signerKeyTypeEd25519(keypair.rawPublicKey()), weight });
const threeSigners = [first, second, third].map((keypair) => ed25519Signer(keypair));

test('custodyProblems finds nothing wrong with a 2-of-3 or 3-of-3 account whose own key has weight 0', () => {
  assert.deepEqual(custodyProblems(adminAccount([0, 2, 2, 2], threeSigners)), []);
  assert.deepEqual(custodyProblems(adminAccount([0, 3, 3, 3], threeSigners)), []);
});

test('custodyProblems names each custody rule an account breaks alone', () => {
  const hash = Buffer.alloc(32);
  const hashSigner = new xdr.Signer({ key: xdr.SignerKey.signerKeyTypeHashX(hash), weight: 1 });
  const cases = [
    [[1, 2, 2, 2], threeSigners, 'its own key has weight 1, not 0'],
    [[0, 1, 2, 2], threeSigners, 'its low, medium, and high thresholds are 1, 2, and 2, not equal'],
    [[0, 2, 1, 2], threeSigners, 'its low, medium, and high thresholds are 2, 1, and 2, not equal'],
    [[0, 1, 1, 1], threeSigners, 'its threshold is 1, below 2'],
    [[0, 4, 4, 4], threeSigners, 'its threshold is 4, above its 3 signers'],
    [[0, 2, 2, 2], [...threeSigners.slice(0, 2), hashSigner], `signer ${StrKey.encodeSha256Hash(hash)} is not an ed25519 key`],
    [[0, 2, 2, 2], [...threeSigners.slice(0, 2), ed25519Signer(third, 2)], `signer ${third.publicKey()} has weight 2, not 1`],
  ];
  for (const [thresholds, signers, problem] of cases) {
    assert.deepEqual(custodyProblems(adminAccount(thresholds, signers)), [problem]);
  }
});

// The diagnostic event a sent transaction publishes when its host function fails with `error`.
function hostFnFailed(error) {
  return new xdr.DiagnosticEvent({
    inSuccessfulContractCall: false,
    event: new xdr.ContractEvent({
      ext: xdr.ExtensionPoint.v0(),
      contractId: null,
      type: xdr.ContractEventType.diagnostic,
      body: xdr.ContractEventBody.v0(new xdr.ContractEventV0({
        topics: [xdr.ScVal.scvSymbol('host_fn_failed'), xdr.ScVal.scvError(error)],
        data: xdr.ScVal.scvVoid(),
      })),
    }),
  });
}

test('hostError words the error of a host_fn_failed event as a simulation does', () => {
  assert.equal(hostError([hostFnFailed(xdr.ScError.sceContract(20))]), 'Error(Contract, #20)');
  assert.equal(
    hostError([hostFnFailed(xdr.ScError.sceAuth(xdr.ScErrorCode.scecInvalidAction))]),
    'Error(Auth, InvalidAction)',
  );
  assert.equal(hostError([]), '');
});

test('explainFailure names a transaction the network refused', () => {
  assert.equal(
    explainFailure(new Error('transaction ERROR: txBadAuthExtra '), 'pool'),
    'The transaction carries a signature it does not use: more than the threshold needs, one signer twice, or a key that is not a signer. Build the call again and collect the threshold\'s signatures, one from each signer.',
  );
  assert.equal(
    explainFailure(new Error('transaction ERROR: txBadAuth '), 'pool'),
    'The transaction lacks signatures. Collect more from the admin account\'s signers.',
  );
  assert.equal(
    explainFailure(new Error('transaction ERROR: txBadSeq '), 'pool'),
    'This call is out of date: the admin account sent another transaction first. Build it again if it\'s still needed.',
  );
  assert.equal(
    explainFailure(new Error('transaction ERROR: txTooLate '), 'pool'),
    'This call has expired. Build it again.',
  );
  const unconfirmed = 'The network has not confirmed the transaction yet. Check the contract before building the call again.';
  assert.equal(explainFailure(new Error('transaction TRY_AGAIN_LATER:  '), 'pool'), unconfirmed);
  assert.equal(explainFailure(new Error('transaction DUPLICATE:  '), 'pool'), unconfirmed);
  assert.equal(explainFailure(new Error('transaction 5bb5 NOT_FOUND:  '), 'pool'), unconfirmed);
  assert.equal(
    explainFailure(new Error('transaction 5bb5 FAILED: txFailed Error(Auth, InvalidAction)'), 'asp-membership'),
    'The transaction\'s source is not the contract\'s admin.',
  );
  assert.equal(
    explainFailure(new Error('transaction ERROR: txInsufficientBalance '), 'pool'),
    'The paying account doesn\'t have enough XLM for the fee. Add some and try again.',
  );
});

test('explainFailure names the pool errors 18, 20 and 21', () => {
  const pool = (code) => explainFailure(new Error(`HostError: Error(Contract, #${code})`), 'pool');
  assert.equal(pool(18), 'Deposits into this pool are paused. Withdrawals and transfers still work.');
  assert.equal(pool(20), 'No admin transfer is pending.');
  assert.equal(pool(21), 'The contract does not run the code this pool accepts.');
});

test('explainFailure reads #6 as NoPendingAdmin from an allowlist and not from a blocklist', () => {
  const six = new Error('HostError: Error(Contract, #6)');
  assert.equal(explainFailure(six, 'asp-membership'), 'No admin transfer is pending.');
  assert.equal(explainFailure(six, 'asp-non-membership'), six.message);
  assert.equal(
    explainFailure(new Error('HostError: Error(Contract, #7)'), 'asp-non-membership'),
    'No admin transfer is pending.',
  );
});

test('explainFailure names a blocklist key that is already listed', () => {
  assert.equal(
    explainFailure(new Error('HostError: Error(Contract, #3)'), 'asp-non-membership'),
    'A key is already on the blocklist.',
  );
});

test('explainFailure names a call too large for one transaction', () => {
  assert.equal(
    explainFailure(new Error('HostError: Error(Budget, ExceededLimit)'), 'asp-non-membership'),
    'The call needs more resources than one transaction allows. For a blocklist insert, add fewer keys at a time.',
  );
});

test('explainFailure passes an error it does not know through unchanged', () => {
  assert.equal(explainFailure(new Error('HostError: Error(Contract, #1)'), 'pool'), 'HostError: Error(Contract, #1)');
});

test('explainFailure passes a pool code through unchanged from a contract the page does not list', () => {
  assert.equal(explainFailure(new Error('HostError: Error(Contract, #18)'), 'unknown'), 'HostError: Error(Contract, #18)');
});

// An RPC client that answers a send with `sent` and every read of the transaction with `landed`.
function stubServer(sent, landed) {
  return {
    sendTransaction: async () => ({ hash: 'ab12', ...sent }),
    getTransaction: async () => landed,
    pollTransaction: async () => landed,
  };
}

const submit = (server) => submitAdminCall({ networkPassphrase: Networks.TESTNET, xdr: insertLeafEnvelope().toXdr(), server });
const refusedResend = { status: 'ERROR', errorResult: { result: { type: 'txBadSeq' } } };
const failedWith20 = {
  status: 'FAILED',
  resultXdr: { result: { type: 'txFailed' } },
  diagnosticEventsXdr: [hostFnFailed(xdr.ScError.sceContract(20))],
};

test('submitAdminCall returns the landed copy of a transaction another signer sent', async () => {
  const landed = { status: 'SUCCESS' };
  assert.equal(await submit(stubServer(refusedResend, landed)), landed);
});

test('submitAdminCall throws the failure of the landed copy of a transaction another signer sent', async () => {
  await assert.rejects(
    submit(stubServer(refusedResend, failedWith20)),
    (error) => explainFailure(error, 'pool') === CONTRACT_ERRORS.pool[20],
  );
});

test('submitAdminCall waits for a transaction the network already holds instead of failing', async () => {
  const landed = { status: 'SUCCESS' };
  for (const status of ['DUPLICATE', 'TRY_AGAIN_LATER']) {
    const server = { ...stubServer({ status }, landed), getTransaction: async () => ({ status: 'NOT_FOUND' }) };
    assert.equal(await submit(server), landed, status);
  }
});

test('deadCall waits while the sequence number is free and the time bound open', async () => {
  const envelope = insertLeafEnvelope();
  const card = { server: { pollTransaction: async () => assert.fail('no lookup while the number is free') }, envelope: envelope.toXdr(), networkPassphrase: Networks.TESTNET, account: { seqNum: 41n } };
  assert.equal(await deadCall({ ...card, now: Number(envelope.timeBounds.maxTime) * 1000 - 1 }), null);
  assert.deepEqual(await deadCall({ ...card, now: Number(envelope.timeBounds.maxTime) * 1000 }), { reason: explainFailure('tx_too_late'), landed: false });
});

test('deadCall asks the network whether a used sequence number went to this call', async () => {
  const envelope = insertLeafEnvelope();
  const asked = [];
  // Sequence 42 is used.
  const dead = (landed) => deadCall({
    server: { pollTransaction: async (hash, { attempts }) => { asked.push([hash, attempts]); if (landed instanceof Error) throw landed; return landed; } },
    envelope: envelope.toXdr(),
    networkPassphrase: Networks.TESTNET,
    account: { seqNum: 42n },
    now: 0,
    kind: 'pool',
  });
  assert.deepEqual(await dead({ status: 'SUCCESS' }), { reason: 'This call already went through.', landed: true });
  assert.deepEqual(await dead(failedWith20), { reason: `This call went through and failed: ${CONTRACT_ERRORS.pool[20]}`, landed: false });
  assert.deepEqual(await dead({ status: 'NOT_FOUND' }), { reason: explainFailure('tx_bad_seq'), landed: false });
  // No answer isn't "not found": the call may have landed.
  await assert.rejects(dead(new NoAnswer()), NoAnswer);
  // tx.hash() is a Uint8Array; its toString ignores 'hex'.
  assert.ok(asked.every(([hash, attempts]) => hash === hex(envelope.hash()) && attempts === 10), JSON.stringify(asked));
});

test('repointsTo matches the pool, method, tree, and a given source', () => {
  const call = { contract: 'POOL', method: 'update_asp_membership', args: ['TREE'], source: 'ADMIN' };
  const repoint = { pool: 'POOL', method: 'update_asp_membership', tree: 'TREE' };
  assert.equal(repointsTo(call, repoint), true);
  assert.equal(repointsTo(call, { ...repoint, source: 'ADMIN' }), true);
  for (const other of [{ source: 'OTHER' }, { tree: 'OTHER' }, { pool: 'OTHER' }, { method: 'update_asp_non_membership' }]) {
    assert.equal(repointsTo(call, { ...repoint, ...other }), false, JSON.stringify(other));
  }
});

test('submitAdminCall names the host error of a sent transaction that failed', async () => {
  await assert.rejects(submit(stubServer({ status: 'PENDING' }, failedWith20)), /FAILED: txFailed Error\(Contract, #20\)/);
});

test('submitAdminCall throws the refusal of a transaction that never landed', async () => {
  const notFound = { status: 'NOT_FOUND' };
  await assert.rejects(
    submit(stubServer({ status: 'ERROR', errorResult: { result: { type: 'txBadAuth' } } }, notFound)),
    (error) => explainFailure(error, 'pool') === 'The transaction lacks signatures. Collect more from the admin account\'s signers.',
  );
  await assert.rejects(
    submit(stubServer(refusedResend, notFound)),
    (error) => explainFailure(error, 'pool') === 'This call is out of date: the admin account sent another transaction first. Build it again if it\'s still needed.',
  );
});

const UNANSWERED = 'The network didn\'t answer. Try again in a moment.';
const rpcAnswer = (body) => Response.json({ jsonrpc: '2.0', id: 1, ...body });

test('rpcServer reports a request the RPC never answered in plain words', async (t) => {
  const failures = {
    offline: async () => { throw new TypeError('Failed to fetch'); },
    'gateway error': async () => new Response('Bad Gateway', { status: 502 }),
    'rate limit': async () => new Response('Too Many Requests', { status: 429 }),
    'a page that is not JSON': async () => new Response('<html>Sign in to the Wi-Fi</html>'),
  };
  for (const [name, fetch] of Object.entries(failures)) {
    t.mock.method(globalThis, 'fetch', fetch);
    await assert.rejects(rpcServer('https://rpc.test').getLatestLedger(), { message: UNANSWERED }, name);
  }
});

test('rpcServer gives up on a request after 30 seconds', async (t) => {
  const waits = [];
  t.mock.method(AbortSignal, 'timeout', (ms) => {
    waits.push(ms);
    return AbortSignal.abort(new DOMException('The operation timed out.', 'TimeoutError'));
  });
  t.mock.method(globalThis, 'fetch', async (_url, { signal }) => {
    signal.throwIfAborted();
    return rpcAnswer({ result: {} });
  });
  await assert.rejects(rpcServer('https://rpc.test').getLatestLedger(), { message: UNANSWERED });
  assert.deepEqual(waits, [30_000]);
});

test('rpcServer keeps the message of an answer the RPC gave', async (t) => {
  const error = { code: -32600, message: 'startLedger must be within the ledger range: 1 - 2' };
  t.mock.method(globalThis, 'fetch', async () => rpcAnswer({ error }));
  await assert.rejects(rpcServer('https://rpc.test').getLatestLedger(), error);
  t.mock.method(globalThis, 'fetch', async () => new Response('Not Found', { status: 404 }));
  await assert.rejects(rpcServer('https://rpc.test').getLatestLedger(), { message: 'Request failed with status code 404' });
});

test('rpcServer keeps the error of a request it could not send', async (t) => {
  const fetch = t.mock.method(globalThis, 'fetch', async () => rpcAnswer({ result: {} }));
  await assert.rejects(rpcServer('https://rpc.test').getEvents({ startLedger: 1n, filters: [] }), { message: /BigInt/ });
  assert.equal(fetch.mock.callCount(), 0);
});

test('rpcServer tells a missing account from a read that got no answer, in the SDK\'s own reads too', async (t) => {
  const address = Keypair.random().publicKey();
  t.mock.method(globalThis, 'fetch', async () => rpcAnswer({ result: { entries: [], latestLedger: 1 } }));
  await assert.rejects(rpcServer('https://rpc.test').getAccount(address), {
    message: `${address.slice(0, 6)}...${address.slice(-4)} isn't an account on this network. Check the address, or fund the account first.`,
  });
  t.mock.method(globalThis, 'fetch', async () => new Response('Bad Gateway', { status: 502 }));
  await assert.rejects(rpcServer('https://rpc.test').getAccount(address), { message: UNANSWERED });
});
