import assert from 'node:assert/strict';
import test from 'node:test';

import {
  Account,
  Address,
  Keypair,
  Networks,
  SorobanDataBuilder,
  StrKey,
  TransactionBuilder,
  hash,
  scValToNative,
  xdr,
} from '@stellar/stellar-sdk';

import {
  addSignature,
  authorizationPreimage,
  buildPauseAuthorization,
  decodeAuthorization,
  encodeAuthorization,
  pauseTransaction,
  walletSignature,
} from '../../../app/js/pause-authorization.js';

const ADMIN = Keypair.random().publicKey();
const HOLDER = Keypair.random().publicKey();
const POOL = 'CBZAWV3AKKKIIO3LEIF7DHODHHHTTL47M7WQSZYTU3ZYSBMM32MUM5H4';

const pauseEntry = () => buildPauseAuthorization({ admin: ADMIN, pool: POOL, nonce: -7n, latestLedger: 1_000 });

// Signs an authorization's preimage the way Freighter's signAuthEntry does.
const sign = (entry, signer, network = Networks.TESTNET) => signer.sign(hash(Buffer.from(authorizationPreimage(entry, network), 'base64')));

test('authorizationPreimage matches a preimage built by hand from the same fields', () => {
  const preimage = xdr.HashIdPreimage.envelopeTypeSorobanAuthorization(new xdr.HashIdPreimageSorobanAuthorization({
    networkId: hash(Buffer.from(Networks.TESTNET)),
    nonce: -7n,
    signatureExpirationLedger: 1_000 + 3_110_400 - 1,
    invocation: new xdr.SorobanAuthorizedInvocation({
      function: xdr.SorobanAuthorizedFunction.sorobanAuthorizedFunctionTypeContractFn(new xdr.InvokeContractArgs({
        contractAddress: new Address(POOL).toScAddress(),
        functionName: 'pause_deposits',
        args: [],
      })),
      subInvocations: [],
    }),
  }));
  assert.equal(authorizationPreimage(pauseEntry(), Networks.TESTNET), preimage.toXdr('base64'));
});

test('addSignature sorts the signatures by public key whichever order they arrive in', () => {
  const entry = pauseEntry();
  const [low, high] = [Keypair.random(), Keypair.random()]
    .sort((a, b) => Buffer.compare(a.rawPublicKey(), b.rawPublicKey()));
  const add = (target, signer) => addSignature(target, signer.publicKey(), sign(entry, signer), Networks.TESTNET);
  const inOrder = add(add(entry, low), high);
  const reversed = add(add(entry, high), low);
  assert.equal(reversed.toXdr('base64'), inOrder.toXdr('base64'));
  const signers = scValToNative(reversed.credentials.address.signature)
    .map(({ public_key: key }) => StrKey.encodeEd25519PublicKey(key));
  assert.deepEqual(signers, [low.publicKey(), high.publicKey()]);
});

test('addSignature refuses a signer who has already signed', () => {
  const entry = pauseEntry();
  const signer = Keypair.random();
  const signed = addSignature(entry, signer.publicKey(), sign(entry, signer), Networks.TESTNET);
  assert.throws(
    () => addSignature(signed, signer.publicKey(), sign(entry, signer), Networks.TESTNET),
    { message: `${signer.publicKey()} has already signed the authorization` },
  );
});

test('addSignature refuses a signature of another network\'s preimage', () => {
  const entry = pauseEntry();
  const signer = Keypair.random();
  assert.throws(
    () => addSignature(entry, signer.publicKey(), sign(entry, signer, Networks.PUBLIC), Networks.TESTNET),
    { message: `The signature is not ${signer.publicKey()}'s signature of the authorization on this network` },
  );
  assert.doesNotThrow(() => addSignature(entry, signer.publicKey(), sign(entry, signer), Networks.TESTNET));
});

test('walletSignature decodes the signature signAuthEntry returns into one addSignature accepts', () => {
  const entry = pauseEntry();
  const signer = Keypair.random();
  // `signAuthEntry` in `@stellar/freighter-api` 6 resolves to the signature as
  // base64 text, beside the account that made it.
  const { signedAuthEntry } = {
    signedAuthEntry: Buffer.from(sign(entry, signer)).toString('base64'),
    signerAddress: signer.publicKey(),
  };
  const signed = addSignature(entry, signer.publicKey(), walletSignature(signedAuthEntry), Networks.TESTNET);
  assert.deepEqual(decodeAuthorization(encodeAuthorization({ holder: 'Alex', entry: signed })).signers, [signer.publicKey()]);
});

test('walletSignature refuses a result that carries no signature', () => {
  assert.throws(() => walletSignature(null), { message: 'The wallet returned no signature' });
});

test('an authorization file round-trips', () => {
  const signer = Keypair.random();
  const entry = addSignature(pauseEntry(), signer.publicKey(), sign(pauseEntry(), signer), Networks.TESTNET);
  const file = encodeAuthorization({ holder: 'Alex', entry });
  const { entry: decoded, ...fields } = decodeAuthorization(file);
  assert.deepEqual(fields, {
    pool: POOL,
    admin: ADMIN,
    holder: 'Alex',
    nonce: -7n,
    expirationLedger: 1_000 + 3_110_400 - 1,
    signers: [signer.publicKey()],
  });
  assert.equal(decoded.toXdr('base64'), entry.toXdr('base64'));
  assert.equal(encodeAuthorization({ holder: 'Alex', entry: decoded }), file);
});

test('decodeAuthorization refuses a file that authorizes anything but a pause of one pool', () => {
  const { credentials } = pauseEntry();
  const invocation = (functionName, args, subInvocations = []) => new xdr.SorobanAuthorizedInvocation({
    function: xdr.SorobanAuthorizedFunction.sorobanAuthorizedFunctionTypeContractFn(new xdr.InvokeContractArgs({
      contractAddress: new Address(POOL).toScAddress(),
      functionName,
      args,
    })),
    subInvocations,
  });
  const pause = invocation('pause_deposits', []);
  // One entry per thing the file must not authorize, each otherwise a pause.
  const entries = {
    'another call': [credentials, invocation('unpause_deposits', [])],
    'an argument': [credentials, invocation('pause_deposits', [xdr.ScVal.scvVoid()])],
    'a sub-invocation': [credentials, invocation('pause_deposits', [], [pause])],
    'source-account credentials': [xdr.SorobanCredentials.sorobanCredentialsSourceAccount(), pause],
  };
  for (const [label, [entryCredentials, rootInvocation]] of Object.entries(entries)) {
    const entry = new xdr.SorobanAuthorizationEntry({ credentials: entryCredentials, rootInvocation });
    const file = JSON.stringify({ pool: POOL, holder: 'Alex', entry: entry.toXdr('base64') });
    assert.throws(() => decodeAuthorization(file), /something other than a pause/, label);
  }
});

test('pauseTransaction refuses a file whose expiration has passed before building anything', async () => {
  const authorization = decodeAuthorization(encodeAuthorization({ holder: 'Alex', entry: pauseEntry() }));
  const unreachable = async () => assert.fail('nothing is built for an expired authorization');
  const server = {
    getLatestLedger: async () => ({ sequence: authorization.expirationLedger }),
    getAccount: unreachable,
    simulateTransaction: unreachable,
  };
  await assert.rejects(
    pauseTransaction({ networkPassphrase: Networks.TESTNET, source: HOLDER, authorization, server }),
    /expired at ledger 3111399/,
  );
});

// A diagnostic event named `name`, such as those a simulation reports around
// every contract call.
function diagnosticEvent(name) {
  return new xdr.DiagnosticEvent({
    inSuccessfulContractCall: true,
    event: new xdr.ContractEvent({
      ext: xdr.ExtensionPoint.v0(),
      contractId: null,
      type: xdr.ContractEventType.diagnostic,
      body: xdr.ContractEventBody.v0(new xdr.ContractEventV0({
        topics: [xdr.ScVal.scvSymbol(name)],
        data: xdr.ScVal.scvVoid(),
      })),
    }),
  });
}

// An RPC stub at ledger 2,000 whose simulations return `simulations` in turn,
// and whose recent Soroban inclusion fees have `p99` as their 99th percentile.
const pauseServer = (simulations, p99 = '100') => ({
  getLatestLedger: async () => ({ sequence: 2_000 }),
  getAccount: async () => new Account(HOLDER, '5'),
  getFeeStats: async () => ({ sorobanInclusionFee: { p99 } }),
  simulateTransaction: async () => simulations.shift(),
});

test('pauseTransaction reads a simulation with no deposit_pause_changed event as an already paused pool', async () => {
  const authorization = decodeAuthorization(encodeAuthorization({ holder: 'Alex', entry: pauseEntry() }));
  // `deposits_paused` reads `false`, and the pause publishes the event of a
  // pause on a paused pool.
  const server = pauseServer([
    { result: { retval: xdr.ScVal.scvBool(false) }, events: [] },
    {
      result: { retval: xdr.ScVal.scvVoid() },
      events: [diagnosticEvent('fn_call'), diagnosticEvent('deposit_pause_repeated'), diagnosticEvent('fn_return')],
    },
  ]);
  assert.deepEqual(
    await pauseTransaction({ networkPassphrase: Networks.TESTNET, source: HOLDER, authorization, server }),
    { paused: true },
  );
});

test('pauseTransaction builds the pause at the p99 inclusion fee when the simulation publishes deposit_pause_changed', async () => {
  const entry = pauseEntry();
  const authorization = decodeAuthorization(encodeAuthorization({ holder: 'Alex', entry }));
  // `deposits_paused` reads `false`, and the pause publishes its event.
  const server = pauseServer([
    { result: { retval: xdr.ScVal.scvBool(false) }, events: [] },
    {
      _parsed: true,
      latestLedger: 2_000,
      transactionData: new SorobanDataBuilder().setResourceFee(100),
      minResourceFee: '100',
      result: { auth: [], retval: xdr.ScVal.scvVoid() },
      events: [diagnosticEvent('deposit_pause_changed')],
    },
  ], '5000');
  const built = await pauseTransaction({ networkPassphrase: Networks.TESTNET, source: HOLDER, authorization, server });
  const { fee, operations } = TransactionBuilder.fromXDR(built.xdr, Networks.TESTNET);
  // The simulation's resource fee comes on top of the bid.
  assert.equal(Number(fee) - 100, 5_000);
  assert.equal(operations.length, 1);
  const [{ func, auth }] = operations;
  assert.equal(func.invokeContract.functionName.toString(), 'pause_deposits');
  assert.deepEqual(auth.map((signed) => signed.toXdr('base64')), [entry.toXdr('base64')]);
});

test('pauseTransaction builds nothing when deposits_paused reads true', async () => {
  const authorization = decodeAuthorization(encodeAuthorization({ holder: 'Alex', entry: pauseEntry() }));
  const server = {
    ...pauseServer([{ result: { retval: xdr.ScVal.scvBool(true) }, events: [] }]),
    getAccount: async () => assert.fail('nothing is built for a paused pool'),
  };
  assert.deepEqual(
    await pauseTransaction({ networkPassphrase: Networks.TESTNET, source: HOLDER, authorization, server }),
    { paused: true },
  );
});

test('pauseTransaction reads an entry the host refuses as a file to sign again', async () => {
  const authorization = decodeAuthorization(encodeAuthorization({ holder: 'Alex', entry: pauseEntry() }));
  // `deposits_paused` reads `false`, and the host refuses the entry.
  const server = pauseServer([
    { result: { retval: xdr.ScVal.scvBool(false) }, events: [] },
    { error: 'HostError: Error(Auth, InvalidAction)' },
  ]);
  await assert.rejects(
    pauseTransaction({ networkPassphrase: Networks.TESTNET, source: HOLDER, authorization, server }),
    /does not authorize the pause/,
  );
});

test('pauseTransaction reads a spent nonce as a file already used', async () => {
  const authorization = decodeAuthorization(encodeAuthorization({ holder: 'Alex', entry: pauseEntry() }));
  // `deposits_paused` reads `false`, and the host refuses the entry's spent nonce.
  const server = pauseServer([
    { result: { retval: xdr.ScVal.scvBool(false) }, events: [] },
    { error: 'HostError: Error(Auth, ExistingValue)' },
  ]);
  await assert.rejects(
    pauseTransaction({ networkPassphrase: Networks.TESTNET, source: HOLDER, authorization, server }),
    { message: 'The file has already been used. The signers sign a new file.' },
  );
});

test('pauseTransaction passes any other refusal on unchanged', async () => {
  const authorization = decodeAuthorization(encodeAuthorization({ holder: 'Alex', entry: pauseEntry() }));
  // `deposits_paused` reads `false`, and the pause runs out of budget.
  const server = pauseServer([
    { result: { retval: xdr.ScVal.scvBool(false) }, events: [] },
    { error: 'HostError: Error(Budget, ExceededLimit)' },
  ]);
  await assert.rejects(
    pauseTransaction({ networkPassphrase: Networks.TESTNET, source: HOLDER, authorization, server }),
    { message: 'HostError: Error(Budget, ExceededLimit)' },
  );
});
