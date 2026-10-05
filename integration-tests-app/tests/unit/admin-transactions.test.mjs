import assert from 'node:assert/strict';
import test from 'node:test';

import {
  Account,
  Address,
  Contract,
  Keypair,
  Networks,
  Operation,
  TransactionBuilder,
  nativeToScVal,
  xdr,
} from '@stellar/stellar-sdk';

import {
  describeAdminCall,
  explainFailure,
  hostError,
  signatureCount,
  signedBy,
  signingRule,
  signRefusal,
  submitAdminCall,
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

// An insert_leaf envelope carrying a signature by each of `signers`.
function envelopeSignedBy(...signers) {
  const envelope = insertLeafEnvelope();
  signers.forEach((signer) => envelope.sign(signer));
  return envelope.toXdr();
}

test('signRefusal refuses a key of weight 0, a signature past the threshold, and a second signature by one key', () => {
  assert.equal(
    signRefusal(twoOfThree, envelopeSignedBy(), Networks.TESTNET, ADMIN),
    `The connected account does not sign for ${ADMIN}`,
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
    'Another admin transaction used the sequence number first. Build the call again.',
  );
  assert.equal(
    explainFailure(new Error('transaction ERROR: txTooLate '), 'pool'),
    'The transaction\'s time bound has passed. Build the call again.',
  );
  const unconfirmed = 'The network has not confirmed the transaction yet. Check the contract before building the call again.';
  assert.equal(explainFailure(new Error('transaction TRY_AGAIN_LATER:  '), 'pool'), unconfirmed);
  assert.equal(explainFailure(new Error('transaction DUPLICATE:  '), 'pool'), unconfirmed);
  assert.equal(explainFailure(new Error('transaction 5bb5 NOT_FOUND:  '), 'pool'), unconfirmed);
  assert.equal(
    explainFailure(new Error('transaction 5bb5 FAILED: txFailed Error(Auth, InvalidAction)'), 'asp-membership'),
    'The transaction\'s source is not the contract\'s admin.',
  );
});

test('explainFailure names the pool errors 18 to 21', () => {
  const pool = (code) => explainFailure(new Error(`HostError: Error(Contract, #${code})`), 'pool');
  assert.equal(pool(18), 'Deposits into this pool are paused. Withdrawals and transfers still work.');
  assert.equal(pool(19), 'Deposits into this pool are not paused.');
  assert.equal(pool(20), 'No admin transfer is pending.');
  assert.equal(pool(21), 'The tree does not run the code this pool accepts.');
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
const failedWith19 = {
  status: 'FAILED',
  resultXdr: { result: { type: 'txFailed' } },
  diagnosticEventsXdr: [hostFnFailed(xdr.ScError.sceContract(19))],
};

test('submitAdminCall returns the landed copy of a transaction another signer sent', async () => {
  const landed = { status: 'SUCCESS' };
  assert.equal(await submit(stubServer(refusedResend, landed)), landed);
});

test('submitAdminCall throws the failure of the landed copy of a transaction another signer sent', async () => {
  await assert.rejects(
    submit(stubServer(refusedResend, failedWith19)),
    (error) => explainFailure(error, 'pool') === CONTRACT_ERRORS.pool[19],
  );
});

test('submitAdminCall names the host error of a sent transaction that failed', async () => {
  await assert.rejects(submit(stubServer({ status: 'PENDING' }, failedWith19)), /FAILED: txFailed Error\(Contract, #19\)/);
});

test('submitAdminCall throws the refusal of a transaction that never landed', async () => {
  const notFound = { status: 'NOT_FOUND' };
  await assert.rejects(
    submit(stubServer({ status: 'ERROR', errorResult: { result: { type: 'txBadAuth' } } }, notFound)),
    (error) => explainFailure(error, 'pool') === 'The transaction lacks signatures. Collect more from the admin account\'s signers.',
  );
  await assert.rejects(
    submit(stubServer(refusedResend, notFound)),
    (error) => explainFailure(error, 'pool') === 'Another admin transaction used the sequence number first. Build the call again.',
  );
});
