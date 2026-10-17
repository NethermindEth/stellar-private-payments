import assert from 'node:assert/strict';
import test from 'node:test';

import * as ed from '@noble/ed25519';
import { sha512 } from '@noble/hashes/sha2.js';

import {
  Account,
  Address,
  Keypair,
  Networks,
  SorobanDataBuilder,
  StrKey,
  TransactionBuilder,
  hash,
  nativeToScVal,
  scValToNative,
  xdr,
} from '@stellar/stellar-sdk';

import {
  addSignature,
  authorizationPreimage,
  buildPauseAuthorization,
  countedEntry,
  decodeAuthorization,
  describeAuthorization,
  encodeAuthorization,
  ledgerDate,
  mergeSignatures,
  nonceSpent,
  pauseFileProblem,
  pauseFileState,
  pauseFileWeight,
  pauseTransaction,
  uncountedSigners,
  verifySignatures,
  walletSignature,
} from '../../../app/js/pause-authorization.js';
import { shortAddress } from '../../../app/js/admin-transactions.js';

const ADMIN = Keypair.random().publicKey();
const SENDER = Keypair.random().publicKey();
const POOL = 'CBZAWV3AKKKIIO3LEIF7DHODHHHTTL47M7WQSZYTU3ZYSBMM32MUM5H4';

const pauseEntry = () => buildPauseAuthorization({ admin: ADMIN, pool: POOL, nonce: -7n, latestLedger: 1_000, maxEntryTtl: 17_280 });

// Lists any signatures, valid or not.
const listing = (entry, signatures) => new xdr.SorobanAuthorizationEntry({
  credentials: xdr.SorobanCredentials.sorobanCredentialsAddress(new xdr.SorobanAddressCredentials({
    ...entry.credentials.address,
    signature: nativeToScVal(signatures, { type: { public_key: ['symbol', null], signature: ['symbol', null] } }),
  })),
  rootInvocation: entry.rootInvocation,
});

const sign = (entry, signer, network = Networks.TESTNET) => signer.sign(hash(Buffer.from(authorizationPreimage(entry, network), 'base64')));

test('authorizationPreimage matches a preimage built by hand from the same fields', () => {
  const preimage = xdr.HashIdPreimage.envelopeTypeSorobanAuthorization(new xdr.HashIdPreimageSorobanAuthorization({
    networkId: hash(Buffer.from(Networks.TESTNET)),
    nonce: -7n,
    signatureExpirationLedger: 1_000 + 17_280 - 1,
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
    { message: `${shortAddress(signer.publicKey())} has already signed this file` },
  );
});

test('addSignature refuses a signature of another network\'s preimage', () => {
  const entry = pauseEntry();
  const signer = Keypair.random();
  assert.throws(
    () => addSignature(entry, signer.publicKey(), sign(entry, signer, Networks.PUBLIC), Networks.TESTNET),
    { message: `Not a valid signature from ${shortAddress(signer.publicKey())} on this network` },
  );
  assert.doesNotThrow(() => addSignature(entry, signer.publicKey(), sign(entry, signer), Networks.TESTNET));
});

test('walletSignature decodes the signature signAuthEntry returns into one addSignature accepts', () => {
  const entry = pauseEntry();
  const signer = Keypair.random();
  // freighter-api 6 returns the signature as base64.
  const { signedAuthEntry } = {
    signedAuthEntry: Buffer.from(sign(entry, signer)).toString('base64'),
    signerAddress: signer.publicKey(),
  };
  const signed = addSignature(entry, signer.publicKey(), walletSignature(signedAuthEntry), Networks.TESTNET);
  assert.deepEqual(decodeAuthorization(encodeAuthorization(signed)).signers, [signer.publicKey()]);
});

test('walletSignature refuses a result that carries no signature', () => {
  assert.throws(() => walletSignature(null), { message: 'Freighter returned no signature' });
});

test('an authorization file round-trips', () => {
  const signer = Keypair.random();
  const entry = addSignature(pauseEntry(), signer.publicKey(), sign(pauseEntry(), signer), Networks.TESTNET);
  const file = encodeAuthorization(entry);
  const { entry: decoded, ...fields } = decodeAuthorization(file);
  assert.deepEqual(fields, {
    pool: POOL,
    admin: ADMIN,
    nonce: -7n,
    expirationLedger: 1_000 + 17_280 - 1,
    signers: [signer.publicKey()],
  });
  assert.equal(decoded.toXdr('base64'), entry.toXdr('base64'));
  assert.equal(encodeAuthorization(decoded), file);
});

test('decodeAuthorization reads a file that still names a holder and drops the name', () => {
  const file = JSON.stringify({ ...JSON.parse(encodeAuthorization(pauseEntry())), holder: 'Alex' });
  assert.equal('holder' in decodeAuthorization(file), false);
  assert.equal(decodeAuthorization(file).pool, POOL);
});

test('decodeAuthorization names a file that holds no authorization', () => {
  for (const text of ['not json', '{}', JSON.stringify({ entry: 'AAAA' })]) {
    assert.throws(() => decodeAuthorization(text), { message: 'This is not a pause file' });
  }
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
  const entries = {
    'another call': [credentials, invocation('unpause_deposits', [])],
    'an argument': [credentials, invocation('pause_deposits', [xdr.ScVal.scvVoid()])],
    'a sub-invocation': [credentials, invocation('pause_deposits', [], [pause])],
    'source-account credentials': [xdr.SorobanCredentials.sorobanCredentialsSourceAccount(), pause],
  };
  for (const [label, [entryCredentials, rootInvocation]] of Object.entries(entries)) {
    const entry = new xdr.SorobanAuthorizationEntry({ credentials: entryCredentials, rootInvocation });
    const file = JSON.stringify({ pool: POOL, entry: entry.toXdr('base64') });
    assert.throws(() => decodeAuthorization(file), /does something other than pause one pool's deposits/, label);
  }
});

test('decodeAuthorization refuses a file listing more signatures than an account has keys', () => {
  // This package's SDK builds the oversized list.
  const entry = xdr.SorobanAuthorizationEntry.fromXDR(pauseEntry().toXDR('base64'), 'base64');
  const file = (n) => JSON.stringify({ entry: listing(entry, Array.from({ length: n }, () => ({ public_key: Keypair.random().rawPublicKey(), signature: Buffer.alloc(64) }))).toXDR('base64') });
  // Master key plus 20 signers.
  assert.equal(decodeAuthorization(file(21)).signers.length, 21);
  assert.throws(() => decodeAuthorization(file(22)), { message: 'This file carries more signatures than an admin account has keys' });
});

test('pauseFileWeight sums the weight each signer carries, and none for a key the admin lacks', () => {
  const [heavy, light, gone] = [Keypair.random().publicKey(), Keypair.random().publicKey(), Keypair.random().publicKey()];
  const rule = { weights: new Map([[heavy, 2], [light, 1]]) };
  assert.equal(pauseFileWeight({ signers: [heavy] }, rule), 2);
  assert.equal(pauseFileWeight({ signers: [heavy, light, gone] }, rule), 3);
});

test('mergeSignatures adds the signatures another copy of the file carries', () => {
  const entry = pauseEntry();
  const [first, second] = [Keypair.random(), Keypair.random()];
  const add = (target, signer) => addSignature(target, signer.publicKey(), sign(entry, signer), Networks.TESTNET);
  const both = add(add(entry, first), second);
  const rule = { threshold: 2, weights: new Map([[first.publicKey(), 1], [second.publicKey(), 1]]) };
  assert.equal(mergeSignatures(add(entry, first), add(entry, second), Networks.TESTNET, rule).toXdr('base64'), both.toXdr('base64'));
  assert.equal(mergeSignatures(both, add(entry, first), Networks.TESTNET, rule).toXdr('base64'), both.toXdr('base64'));
  const other = buildPauseAuthorization({ admin: ADMIN, pool: POOL, nonce: 8n, latestLedger: 1_000, maxEntryTtl: 17_280 });
  const foreign = addSignature(other, second.publicKey(), sign(other, second), Networks.TESTNET);
  assert.throws(() => mergeSignatures(add(entry, first), foreign, Networks.TESTNET, rule), /Not a valid signature from /);
});

test('mergeSignatures given the rule adds only counted signatures, and none past the threshold', () => {
  const entry = pauseEntry();
  const [first, second, third, removed] = [Keypair.random(), Keypair.random(), Keypair.random(), Keypair.random()];
  const add = (target, signer) => addSignature(target, signer.publicKey(), sign(entry, signer), Networks.TESTNET);
  const rule = (threshold) => ({ threshold, weights: new Map([[first.publicKey(), 1], [second.publicKey(), 1], [third.publicKey(), 1], [removed.publicKey(), 0]]) });
  const signers = (merged) => new Set(describeAuthorization(merged).signers);
  // Zero weight: never added.
  const withRemoved = mergeSignatures(add(entry, first), add(add(entry, removed), second), Networks.TESTNET, rule(3));
  assert.deepEqual(signers(withRemoved), new Set([first.publicKey(), second.publicKey()]));
  // One short: takes one more.
  assert.equal(signers(mergeSignatures(add(entry, first), add(add(entry, second), third), Networks.TESTNET, rule(2))).size, 2);
  // At the threshold: takes none, so swapping a signer voids it.
  const ready = add(add(entry, first), second);
  assert.equal(mergeSignatures(ready, add(entry, third), Networks.TESTNET, rule(2)).toXdr('base64'), ready.toXdr('base64'));
});

const littleEndian = (bytes) => BigInt(`0x${ed.etc.bytesToHex(Uint8Array.from(bytes).reverse())}`);
const scalarBytes = (n) => Uint8Array.from({ length: 32 }, (_, i) => Number((n >> BigInt(8 * i)) & 0xffn));

// Adds an order-2 point to R: a cofactored check passes, verify_strict refuses.
function torsionSigned(signer, message) {
  ed.hashes.sha512 ??= sha512;
  const { scalar, pointBytes } = ed.utils.getExtendedPublicKey(signer.rawSecretKey());
  const order = ed.Point.CURVE().n;
  const r = ed.etc.mod(littleEndian(ed.etc.randomBytes(32)), order);
  const R = ed.Point.BASE.multiply(r).add(ed.Point.fromHex(`ec${'ff'.repeat(30)}7f`)).toBytes();
  const k = ed.etc.mod(littleEndian(sha512(ed.etc.concatBytes(R, pointBytes, message))), order);
  return ed.etc.concatBytes(R, scalarBytes(ed.etc.mod(r + k * scalar, order)));
}

test('addSignature refuses a signature the host refuses, even one a cofactored check passes', () => {
  const entry = pauseEntry();
  const signer = Keypair.random();
  const message = hash(Buffer.from(authorizationPreimage(entry, Networks.TESTNET), 'base64'));
  const shifted = torsionSigned(signer, message);
  assert.equal(signer.verify(message, Buffer.from(shifted)), true);
  assert.throws(() => addSignature(entry, signer.publicKey(), shifted, Networks.TESTNET), /Not a valid signature from .* on this network/);
  // s past the group order.
  const good = signer.sign(message);
  const unreduced = ed.etc.concatBytes(good.subarray(0, 32), scalarBytes(littleEndian(good.subarray(32)) + ed.Point.CURVE().n));
  assert.throws(() => addSignature(entry, signer.publicKey(), unreduced, Networks.TESTNET), /Not a valid signature from .* on this network/);
  assert.doesNotThrow(() => addSignature(entry, signer.publicKey(), good, Networks.TESTNET));
});

test('addSignature refuses a small-order key or R, even where [s]B - [k]A equals R', () => {
  ed.hashes.sha512 ??= sha512;
  const entry = pauseEntry();
  const message = hash(Buffer.from(authorizationPreimage(entry, Networks.TESTNET), 'base64'));
  const order = ed.Point.CURVE().n;
  const challenge = (R, A) => ed.etc.mod(littleEndian(sha512(ed.etc.concatBytes(R, A, message))), order);
  const times = (point, n) => (n === 0n ? ed.Point.ZERO : point.multiply(n, false));
  // Order-8 key, with R = [s]B + [j]T cancelling [k]T.
  const T = ed.Point.fromHex('26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05');
  let forged;
  while (!forged) {
    const s = ed.etc.mod(littleEndian(ed.etc.randomBytes(32)), order);
    for (let j = 0n; j < 8n && !forged; j += 1n) {
      const R = times(ed.Point.BASE, s).add(times(T, j)).toBytes();
      if ((challenge(R, T.toBytes()) + j) % 8n === 0n) forged = ed.etc.concatBytes(R, scalarBytes(s));
    }
  }
  assert.throws(() => addSignature(entry, StrKey.encodeEd25519PublicKey(Buffer.from(T.toBytes())), forged, Networks.TESTNET), /Not a valid signature/);
  // R is the identity, s = k * a.
  const signer = Keypair.random();
  const { scalar, pointBytes } = ed.utils.getExtendedPublicKey(signer.rawSecretKey());
  const identity = ed.Point.ZERO.toBytes();
  const s = ed.etc.mod(challenge(identity, pointBytes) * scalar, order);
  assert.throws(() => addSignature(entry, signer.publicKey(), ed.etc.concatBytes(identity, scalarBytes(s)), Networks.TESTNET), /Not a valid signature/);
});

test('verifySignatures keeps signatures that check out and refuses a forged or repeated one', () => {
  const entry = pauseEntry();
  const signer = Keypair.random();
  const signed = addSignature(entry, signer.publicKey(), sign(entry, signer), Networks.TESTNET);
  assert.equal(verifySignatures(signed, Networks.TESTNET).toXdr('base64'), signed.toXdr('base64'));
  assert.equal(verifySignatures(entry, Networks.TESTNET).toXdr('base64'), entry.toXdr('base64'));
  const forged = listing(entry, [{ public_key: signer.rawPublicKey(), signature: sign(entry, signer, Networks.PUBLIC) }]);
  assert.throws(() => verifySignatures(forged, Networks.TESTNET), /Not a valid signature from .* on this network/);
  const valid = { public_key: signer.rawPublicKey(), signature: sign(entry, signer) };
  assert.throws(() => verifySignatures(listing(entry, [valid, valid]), Networks.TESTNET), /has already signed this file/);
  const shifted = torsionSigned(signer, hash(Buffer.from(authorizationPreimage(entry, Networks.TESTNET), 'base64')));
  assert.throws(() => verifySignatures(listing(entry, [{ public_key: signer.rawPublicKey(), signature: Buffer.from(shifted) }]), Networks.TESTNET), /Not a valid signature from /);
});

test('pauseFileProblem names a used, expired, or overlong file, and a previous admin\'s', () => {
  const [kept, removed] = [Keypair.random().publicKey(), Keypair.random().publicKey()];
  const file = { admin: ADMIN, expirationLedger: 18_279, signers: [kept] };
  // The account's own key stays at weight 0.
  const chain = { poolAdmin: ADMIN, rule: { weights: new Map([[kept, 1], [ADMIN, 0]]) }, latestLedger: 18_278, maxEntryTtl: 17_280, spent: false };
  assert.equal(pauseFileProblem(file, chain), null);
  assert.equal(pauseFileProblem({ ...file, signers: [] }, chain), null);
  assert.match(pauseFileProblem(file, { ...chain, latestLedger: 18_279 }), /^Expired around \d{4}-\d{2}-\d{2}\. The signers need to sign a new file\.$/);
  assert.equal(pauseFileProblem(file, { ...chain, spent: true }), 'Already used. The signers need to sign a new file.');
  // The host allows up to max_entry_ttl - 1 ledgers ahead.
  assert.equal(pauseFileProblem(file, { ...chain, latestLedger: 999 }), null);
  assert.match(
    pauseFileProblem(file, { ...chain, latestLedger: 999, maxEntryTtl: 17_279 }),
    /^The network now limits how long a file lasts\. This one works only from about \d{4}-\d{2}-\d{2}\. The signers need to sign a new file\.$/,
  );
  // Only counted signatures go in; the host takes at most 20.
  const many = Array.from({ length: 21 }, () => Keypair.random().publicKey());
  const everyone = { ...chain, rule: { weights: new Map(many.map((key) => [key, 1])) } };
  assert.equal(pauseFileProblem({ ...file, signers: many.slice(0, 20) }, everyone), null);
  assert.equal(pauseFileProblem({ ...file, signers: [...many.slice(0, 20), removed] }, everyone), null);
  assert.equal(pauseFileProblem({ ...file, signers: many }, everyone), '21 signatures, but the network takes at most 20. The signers need to sign a new file.');
  assert.equal(pauseFileProblem(file, { ...chain, poolAdmin: SENDER }), `Made for ${shortAddress(ADMIN)}, but the pool's admin is now ${shortAddress(SENDER)}. The signers need to sign a new file.`);
  assert.equal(pauseFileProblem({ ...file, signers: [kept, removed] }, chain), null);
  assert.equal(pauseFileProblem({ ...file, signers: [kept, ADMIN] }, chain), null);
});

test('pauseFileState reads a file as unusable, short, ready for a paused pool, or ready', () => {
  const [one, two] = [Keypair.random().publicKey(), Keypair.random().publicKey()];
  const file = { admin: ADMIN, expirationLedger: 18_279, signers: [one] };
  const chain = { poolAdmin: ADMIN, rule: { threshold: 2, weights: new Map([[one, 1], [two, 1]]) }, latestLedger: 18_278, maxEntryTtl: 17_280, spent: false, paused: false };
  assert.deepEqual(pauseFileState(file, { ...chain, spent: true }), { problem: 'Already used. The signers need to sign a new file.' });
  assert.deepEqual(pauseFileState(file, chain), { short: true });
  assert.deepEqual(pauseFileState(file, { ...chain, paused: true }), { short: true });
  assert.deepEqual(pauseFileState({ ...file, signers: [one, two] }, { ...chain, paused: true }), { paused: true });
  assert.deepEqual(pauseFileState({ ...file, signers: [one, two] }, chain), { ready: true });
});

test('ledgerDate gives the day a ledger closes at five seconds a ledger', () => {
  assert.equal(ledgerDate(1_000 + 17_280, 1_000, Date.UTC(2030, 0, 1)), '2030-01-02');
  assert.equal(ledgerDate(1_000 - 17_280, 1_000, Date.UTC(2030, 0, 1)), '2029-12-31');
});

test('countedEntry leaves out the signature of a key that no longer signs for the admin', () => {
  const entry = pauseEntry();
  const [kept, removed] = [Keypair.random(), Keypair.random()];
  const add = (target, signer) => addSignature(target, signer.publicKey(), sign(entry, signer), Networks.TESTNET);
  const both = add(add(entry, kept), removed);
  // A removed signer stays at weight 0, or leaves.
  for (const rule of [{ weights: new Map([[kept.publicKey(), 1]]) }, { weights: new Map([[kept.publicKey(), 1], [removed.publicKey(), 0]]) }]) {
    assert.deepEqual(uncountedSigners(describeAuthorization(both), rule), [removed.publicKey()]);
  }
  const rule = { weights: new Map([[kept.publicKey(), 1], [removed.publicKey(), 0]]) };
  const counted = countedEntry(both, rule);
  assert.deepEqual(describeAuthorization(counted).signers, [kept.publicKey()]);
  assert.equal(verifySignatures(counted, Networks.TESTNET).toXdr('base64'), counted.toXdr('base64'));
});

test('nonceSpent reads the temporary nonce entry the host writes under the admin', async () => {
  const keys = [];
  const server = (entries) => ({ getLedgerEntries: async (key) => { keys.push(key.toXdr('base64')); return { entries }; } });
  assert.equal(await nonceSpent(server([]), ADMIN, -7n), false);
  assert.equal(await nonceSpent(server([{}]), ADMIN, -7n), true);
  const expected = xdr.LedgerKey.contractData(new xdr.LedgerKeyContractData({
    contract: new Address(ADMIN).toScAddress(),
    key: xdr.ScVal.scvLedgerKeyNonce(new xdr.ScNonceKey({ nonce: -7n })),
    durability: xdr.ContractDataDurability.temporary,
  }));
  assert.deepEqual(keys, [expected.toXdr('base64'), expected.toXdr('base64')]);
});

test('pauseTransaction refuses a file whose expiration has passed before building anything', async () => {
  const authorization = decodeAuthorization(encodeAuthorization(pauseEntry()));
  const unreachable = async () => assert.fail('nothing is built for an expired authorization');
  const server = {
    getLatestLedger: async () => ({ sequence: authorization.expirationLedger }),
    getAccount: unreachable,
    simulateTransaction: unreachable,
  };
  await assert.rejects(
    pauseTransaction({ networkPassphrase: Networks.TESTNET, source: SENDER, authorization, server }),
    { message: 'Expired. The signers need to sign a new file.' },
  );
});

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

// RPC stub at ledger 2,000: `simulations` in turn, `p99` as the fee percentile.
const pauseServer = (simulations, p99 = '100') => ({
  getLatestLedger: async () => ({ sequence: 2_000 }),
  getAccount: async () => new Account(SENDER, '5'),
  getFeeStats: async () => ({ sorobanInclusionFee: { p99 } }),
  simulateTransaction: async () => simulations.shift(),
});

test('pauseTransaction reads a simulation with no deposit_pause_changed event as an already paused pool', async () => {
  const authorization = decodeAuthorization(encodeAuthorization(pauseEntry()));
  // Reads unpaused, then the pause finds the pool paused.
  const server = pauseServer([
    { result: { retval: xdr.ScVal.scvBool(false) }, events: [] },
    {
      result: { retval: xdr.ScVal.scvVoid() },
      events: [diagnosticEvent('fn_call'), diagnosticEvent('deposit_pause_repeated'), diagnosticEvent('fn_return')],
    },
  ]);
  assert.deepEqual(
    await pauseTransaction({ networkPassphrase: Networks.TESTNET, source: SENDER, authorization, server }),
    { paused: true },
  );
});

test('pauseTransaction builds the pause at the p99 inclusion fee when the simulation publishes deposit_pause_changed', async () => {
  const entry = pauseEntry();
  const authorization = decodeAuthorization(encodeAuthorization(entry));
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
  const built = await pauseTransaction({ networkPassphrase: Networks.TESTNET, source: SENDER, authorization, server });
  const { fee, operations } = TransactionBuilder.fromXDR(built.xdr, Networks.TESTNET);
  // The resource fee comes on top of the bid.
  assert.equal(Number(fee) - 100, 5_000);
  assert.equal(operations.length, 1);
  const [{ func, auth }] = operations;
  assert.equal(func.invokeContract.functionName.toString(), 'pause_deposits');
  assert.deepEqual(auth.map((signed) => signed.toXdr('base64')), [entry.toXdr('base64')]);
});

test('pauseTransaction builds nothing when deposits_paused reads true', async () => {
  const authorization = decodeAuthorization(encodeAuthorization(pauseEntry()));
  const server = {
    ...pauseServer([{ result: { retval: xdr.ScVal.scvBool(true) }, events: [] }]),
    getAccount: async () => assert.fail('nothing is built for a paused pool'),
  };
  assert.deepEqual(
    await pauseTransaction({ networkPassphrase: Networks.TESTNET, source: SENDER, authorization, server }),
    { paused: true },
  );
});

test('pauseTransaction reads an entry the host refuses as a file to sign again', async () => {
  const authorization = decodeAuthorization(encodeAuthorization(pauseEntry()));
  const server = pauseServer([
    { result: { retval: xdr.ScVal.scvBool(false) }, events: [] },
    { error: 'HostError: Error(Auth, InvalidAction)' },
  ]);
  await assert.rejects(
    pauseTransaction({ networkPassphrase: Networks.TESTNET, source: SENDER, authorization, server }),
    /network refused the file's signatures/,
  );
});

test('pauseTransaction reads a spent nonce as a file already used', async () => {
  const authorization = decodeAuthorization(encodeAuthorization(pauseEntry()));
  const server = pauseServer([
    { result: { retval: xdr.ScVal.scvBool(false) }, events: [] },
    { error: 'HostError: Error(Auth, ExistingValue)' },
  ]);
  await assert.rejects(
    pauseTransaction({ networkPassphrase: Networks.TESTNET, source: SENDER, authorization, server }),
    { message: 'Already used. The signers need to sign a new file.' },
  );
});

test('pauseTransaction passes any other refusal on unchanged', async () => {
  const authorization = decodeAuthorization(encodeAuthorization(pauseEntry()));
  const server = pauseServer([
    { result: { retval: xdr.ScVal.scvBool(false) }, events: [] },
    { error: 'HostError: Error(Budget, ExceededLimit)' },
  ]);
  await assert.rejects(
    pauseTransaction({ networkPassphrase: Networks.TESTNET, source: SENDER, authorization, server }),
    { message: 'HostError: Error(Budget, ExceededLimit)' },
  );
});
