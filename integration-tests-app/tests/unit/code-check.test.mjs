import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';

import { xdr } from '@stellar/stellar-sdk';

import {
  GITHUB_TIMEOUT_MS,
  checkCode,
  codeRecordsRead,
  codeStatus,
  contractRows,
  lookupAttestation,
  parseAttestation,
  recordedHash,
  sourceRepo,
  wasmMeta,
} from '../../../app/js/code-check.js';

// stellar-cli 28.1.0's Linux tarball, the subject of the fixture's one attestation.
const HASH = 'c1680deee94301d33ada7a17f98411e642a4248c727afbd2e43050d345746462';
const OTHER_HASH = '0'.repeat(64);
const COMMIT = 'c0f4d0da891bbf214c08b8c5035ae6db80e9a3bd';
const HOME = 'NethermindEth/stellar-private-payments';
const FORK = 'someone/fork';
const NOW = 1_800_000_000_000;
const FIXTURE = readFileSync(new URL('../../../cli/src/testdata/attestations.json', import.meta.url), 'utf8');

const VERIFIER_B = { role: 'verifier.B', contractId: 'CB', package: 'circom-groth16-verifier', key: 'B' };
const MANIFEST = {
  pools: [{ poolContractId: 'CPOOL' }, { poolContractId: 'CGVK', gvkMode: 'viewOnly' }],
  asp_membership: 'CALLOW',
  added_asp_memberships: [{ contractId: 'CADDED', deploymentLedger: 1 }],
  asp_non_membership: 'CBLOCK',
  asp_membership_wasm_hash: HASH,
  asp_non_membership_wasm_hash: 'block',
  public_key_registry_verifier_wasm_hash: 'regv',
  verifiers: { '': 'CNONE', B: 'CB' },
  public_key_registry: 'CREG',
  public_key_registry_verifier: 'CREGV',
};

const fixtureStatement = () => JSON.parse(Buffer.from(JSON.parse(FIXTURE).attestations[0].bundle.dsseEnvelope.payload, 'base64'));

/** The fixture's statement, as if `contracts-release.yml` on `main` of `repo` made it. */
function releaseStatement(repo) {
  const statement = fixtureStatement();
  statement.predicate.buildDefinition.externalParameters.workflow = {
    repository: `https://github.com/${repo}`,
    path: '.github/workflows/contracts-release.yml',
    ref: 'refs/heads/main',
  };
  statement.predicate.runDetails.metadata.invocationId = `https://github.com/${repo}/actions/runs/7/attempts/1`;
  return statement;
}

/** `releaseStatement(HOME)` with `edit` applied to its predicate. */
function edited(edit) {
  const statement = releaseStatement(HOME);
  edit(statement.predicate);
  return statement;
}

/** A GitHub reply listing `statements` in order, each in the fixture's envelope. */
function reply(statements) {
  const body = JSON.parse(FIXTURE);
  const [envelope] = body.attestations;
  body.attestations = statements.map((statement) => {
    const attestation = structuredClone(envelope);
    attestation.bundle.dsseEnvelope.payload = Buffer.from(JSON.stringify(statement)).toString('base64');
    return attestation;
  });
  return new Response(JSON.stringify(body));
}

const parseHome = (statements) => parseAttestation(reply(statements), { hash: HASH, repo: HOME });

/** A manifest whose release records `recorded` for verifier B and was built for `network`. */
const released = (recorded, network = 'testnet') => ({ contracts_release: { network, code: recorded ? { CB: recorded } : {} } });

const releaseCode = (repo, feature) => ({
  hash: HASH,
  meta: [
    ['cliver', '28.0.0'],
    ['bldopt', '--package=circom-groth16-verifier'],
    ['bldopt', '--locked'],
    ['bldopt', '--optimize'],
    ['bldopt', feature],
    ['source_repo', `github:${repo}`],
  ],
});

function memoryStorage() {
  const items = new Map();
  return { items, getItem: (key) => items.get(key) ?? null, setItem: (key, value) => items.set(key, value) };
}

test('the fixture decodes and is not a release attestation', async () => {
  assert.equal(fixtureStatement().subject[0].digest.sha256, HASH);
  assert.equal(await parseAttestation(new Response(FIXTURE), { hash: HASH, repo: 'stellar/stellar-cli' }), null);
});

test('codeStatus gives each status, named in snake_case as the CLI names it', async () => {
  const code = releaseCode(HOME, '--features=vk-testnet-b');
  const attested = await parseHome([releaseStatement(HOME)]);
  const build = { repo: HOME, commit: COMMIT, runUrl: `https://github.com/${HOME}/actions/runs/7/attempts/1` };
  assert.deepEqual(attested, build);
  assert.deepEqual(codeStatus(released(HASH), VERIFIER_B, code, attested), { status: 'attested', ...build, otherRepo: false });
  assert.deepEqual(codeStatus(released(HASH), VERIFIER_B, code, null), { status: 'matches_manifest' });
  assert.deepEqual(codeStatus(released(OTHER_HASH), VERIFIER_B, code, attested), { status: 'differs' });
  assert.deepEqual(codeStatus(released(undefined), VERIFIER_B, code, null), { status: 'unknown', reason: 'not_recorded' });
  assert.deepEqual(codeStatus(released(HASH), VERIFIER_B, code, undefined), { status: 'unknown', reason: 'github_unchecked' });
  assert.deepEqual(codeStatus(released(HASH), VERIFIER_B, undefined, attested), { status: 'unknown', reason: 'code_unread' });
});

test('a fork that attested its own build is attested and flagged', async () => {
  const lookup = await parseAttestation(reply([releaseStatement(FORK)]), { hash: HASH, repo: FORK });
  assert.deepEqual(codeStatus(released(HASH), VERIFIER_B, releaseCode(FORK, '--features=vk-testnet-b'), lookup), {
    status: 'attested',
    repo: FORK,
    commit: COMMIT,
    runUrl: `https://github.com/${FORK}/actions/runs/7/attempts/1`,
    otherRepo: true,
  });
});

test('an attestation made in another repository is rejected', async () => {
  const statement = edited((predicate) => {
    predicate.buildDefinition.externalParameters.workflow.repository = `https://github.com/${FORK}`;
  });
  assert.equal(await parseHome([statement]), null);
});

test('an attestation of another file or kind is rejected', async () => {
  const otherFile = releaseStatement(HOME);
  otherFile.subject = [{ digest: { sha256: OTHER_HASH } }];
  assert.equal(await parseHome([otherFile]), null);
  const releaseKind = { ...releaseStatement(HOME), predicateType: 'https://in-toto.io/attestation/release/v0.1' };
  assert.equal(await parseHome([releaseKind]), null);
});

test('an attestation from another workflow or ref is rejected', async () => {
  const otherWorkflow = edited((predicate) => {
    predicate.buildDefinition.externalParameters.workflow.path = '.github/workflows/release.yml';
  });
  assert.equal(await parseHome([otherWorkflow]), null);
  const otherRef = edited((predicate) => {
    predicate.buildDefinition.externalParameters.workflow.ref = 'refs/heads/feature';
  });
  assert.equal(await parseHome([otherRef]), null);
});

test('a matching attestation behind another workflow\'s provenance is used', async () => {
  const first = edited((predicate) => {
    predicate.buildDefinition.externalParameters.workflow.path = '.github/workflows/release.yml';
    predicate.buildDefinition.resolvedDependencies[0].digest.gitCommit = 'a'.repeat(40);
  });
  assert.equal((await parseHome([first, releaseStatement(HOME)]))?.commit, COMMIT);
});

test('a bad commit or run URL is rejected', async () => {
  for (const bad of ['c0f4d0da', 'g0f4d0da891bbf214c08b8c5035ae6db80e9a3bd']) {
    const statement = edited((predicate) => {
      predicate.buildDefinition.resolvedDependencies[0].digest.gitCommit = bad;
    });
    assert.equal(await parseHome([statement]), null, bad);
  }
  const run = `https://github.com/${HOME}/actions/runs/7`;
  for (const bad of [`${run}/../8`, `${run}?attempt=1`, `${run}\n`]) {
    const statement = edited((predicate) => {
      predicate.runDetails.metadata.invocationId = bad;
    });
    assert.equal(await parseHome([statement]), null, JSON.stringify(bad));
  }
});

test('a verifier whose meta does not fit its role differs', () => {
  const otherKey = releaseCode(HOME, '--features=vk-testnet-a');
  assert.deepEqual(codeStatus(released(HASH), VERIFIER_B, otherKey, null), { status: 'differs' });
  const otherNetwork = releaseCode(HOME, '--features=vk-futurenet-b');
  assert.deepEqual(codeStatus(released(HASH), VERIFIER_B, otherNetwork, null), { status: 'differs' });
  assert.deepEqual(codeStatus(released(HASH, null), VERIFIER_B, otherNetwork, null), { status: 'matches_manifest' });
  const gvkV = { ...VERIFIER_B, key: 'gvk_V' };
  assert.deepEqual(codeStatus(released(HASH, null), gvkV, releaseCode(HOME, '--features=vk-testnet-a-gvk-v'), null), { status: 'differs' });
  assert.deepEqual(codeStatus(released(HASH, null), gvkV, releaseCode(HOME, '--features=vk-testnet-gvk-v'), null), { status: 'matches_manifest' });
  const twoFeatures = releaseCode(HOME, '--features=vk-testnet-b');
  twoFeatures.meta.push(['bldopt', '--features=vk-testnet-a']);
  assert.deepEqual(codeStatus(released(HASH), VERIFIER_B, twoFeatures, null), { status: 'differs' });
  const twoPackages = releaseCode(HOME, '--features=vk-testnet-b');
  twoPackages.meta.push(['bldopt', '--package=circom-groth16-verifier']);
  assert.deepEqual(codeStatus(released(HASH), VERIFIER_B, twoPackages, null), { status: 'differs' });
});

/** A fetch that records each call and fails it. */
function spy() {
  const calls = [];
  const fetch = async (url) => {
    calls.push(url);
    throw new Error('offline');
  };
  return { calls, fetch };
}

test('a Wasm without a valid source_repo sends no request', async () => {
  const pool = { role: 'pool', contractId: 'CB', package: 'pool' };
  assert.equal(sourceRepo(releaseCode(HOME, '--features=vk-testnet-b').meta), HOME);
  for (const repo of [undefined, 'github:owner/..', 'github:own er/x', 'gitlab:a/b']) {
    const code = { hash: HASH, meta: [['bldopt', '--package=pool'], ...(repo ? [['source_repo', repo]] : [])] };
    assert.equal(sourceRepo(code.meta), null, repo);
    const { calls, fetch } = spy();
    const check = (manifest) => checkCode({ manifest, row: pool, code, fetch, storage: memoryStorage(), now: NOW });
    assert.deepEqual(await check(released(HASH)), { status: 'matches_manifest' }, repo);
    assert.deepEqual(await check(released(undefined)), { status: 'unknown', reason: 'not_recorded' }, repo);
    assert.deepEqual(calls, [], repo);
  }
});

test('code that differs, or that could not be read, sends no request', async () => {
  const code = releaseCode(HOME, '--features=vk-testnet-b');
  for (const [manifest, unread, status] of [
    [released(OTHER_HASH), code, { status: 'differs' }],
    [released(HASH), undefined, { status: 'unknown', reason: 'code_unread' }],
    [released(HASH), null, { status: 'unknown', reason: 'no_code' }],
  ]) {
    const { calls, fetch } = spy();
    assert.deepEqual(await checkCode({ manifest, row: VERIFIER_B, code: unread, fetch, storage: memoryStorage(), now: NOW }), status);
    assert.deepEqual(calls, []);
  }
  const { calls, fetch } = spy();
  const checked = await checkCode({ manifest: released(HASH), row: VERIFIER_B, code, fetch, storage: memoryStorage(), now: NOW });
  assert.deepEqual(checked, { status: 'unknown', reason: 'github_unchecked', problem: 'offline' });
  assert.equal(calls.length, 1);
});

test('an unreadable reply is unknown and not cached', async () => {
  const storage = memoryStorage();
  const code = releaseCode(HOME, '--features=vk-testnet-b');
  for (const [response, problem] of [
    [new Response('', { status: 403 }), 'GitHub answered HTTP 403'],
    [new Response('{}'), 'GitHub\'s reply could not be read'],
  ]) {
    const fetch = async (url) => {
      assert.equal(url, `https://api.github.com/repos/${HOME}/attestations/sha256:${HASH}`);
      return response;
    };
    const result = await lookupAttestation({ fetch, storage, hash: HASH, repo: HOME, now: NOW });
    assert.deepEqual(result, { problem });
    assert.equal(storage.items.size, 0);
    assert.deepEqual(codeStatus(released(HASH), VERIFIER_B, code, result.lookup), { status: 'unknown', reason: 'github_unchecked' });
  }
});

test('a match is cached for 24 hours and a miss for 10 minutes, the status computed from the manifest each time', async () => {
  const code = releaseCode(HOME, '--features=vk-testnet-b');
  const offline = async () => {
    throw new Error('offline');
  };
  const statusAt = async (storage, recorded, now, fetch = offline) => {
    const { lookup } = await lookupAttestation({ fetch, storage, hash: HASH, repo: HOME, now });
    return codeStatus(released(recorded), VERIFIER_B, code, lookup).status;
  };

  const match = memoryStorage();
  assert.equal(await statusAt(match, HASH, NOW, async () => reply([releaseStatement(HOME)])), 'attested');
  assert.equal(await statusAt(match, HASH, NOW + 86_399_999), 'attested');
  assert.equal(await statusAt(match, OTHER_HASH, NOW + 86_399_999), 'differs');
  assert.equal(await statusAt(match, HASH, NOW + 86_400_000), 'unknown');

  const miss = memoryStorage();
  const notFound = async () => new Response('', { status: 404 });
  assert.equal(await statusAt(miss, HASH, NOW, notFound), 'matches_manifest');
  assert.equal(await statusAt(miss, HASH, NOW + 599_999), 'matches_manifest');
  assert.equal(await statusAt(miss, OTHER_HASH, NOW + 599_999), 'differs');
  assert.equal(await statusAt(miss, HASH, NOW + 600_000), 'unknown');

  // A miss stamped a week ahead, after the clock moved back, is stale.
  const future = memoryStorage();
  await statusAt(future, HASH, NOW + 604_800_000, notFound);
  assert.equal(await statusAt(future, HASH, NOW), 'unknown');
});

test('a cached lookup of another shape is asked again', async () => {
  const build = { repo: HOME, commit: COMMIT, runUrl: `https://github.com/${HOME}/actions/runs/7` };
  for (const lookup of [{}, { ...build, commit: 'c0f4d0d' }, { ...build, runUrl: 'javascript:alert(1)' }, { ...build, repo: FORK }]) {
    const storage = memoryStorage();
    storage.setItem(`poolstellar_code_status_${HASH}`, JSON.stringify({ checkedAt: NOW, lookup }));
    const { calls, fetch } = spy();
    assert.deepEqual(await lookupAttestation({ fetch, storage, hash: HASH, repo: HOME, now: NOW }), { problem: 'offline' }, JSON.stringify(lookup));
    assert.equal(calls.length, 1);
  }
});

test('rows that share a Wasm ask GitHub once', async () => {
  const calls = [];
  const fetch = async (url) => {
    calls.push(url);
    await new Promise((resolve) => setTimeout(resolve, 5));
    return new Response('', { status: 404 });
  };
  const storage = memoryStorage();
  const ask = () => lookupAttestation({ fetch, storage, hash: HASH, repo: HOME, now: NOW });
  assert.deepEqual(await Promise.all([ask(), ask()]), [{ lookup: null }, { lookup: null }]);
  assert.equal(calls.length, 1);
});

test('a request with no answer in time is unknown and not cached', { timeout: 2_000 }, async () => {
  assert.equal(GITHUB_TIMEOUT_MS, 10_000);
  const storage = memoryStorage();
  // Fails only when its signal aborts, so only the timeout ends the request.
  const fetch = (url, { signal }) => new Promise((_, reject) => signal.addEventListener('abort', () => reject(signal.reason)));
  const result = await lookupAttestation({ fetch, storage, hash: HASH, repo: HOME, now: NOW, timeoutMs: 5 });
  assert.deepEqual(result, { problem: 'The operation was aborted due to timeout' });
  assert.equal(storage.items.size, 0);
});

test('contractRows names each contract with its role, and a manifest without contracts_release records the hashes deploy.sh writes for the trees and the registry verifier', () => {
  const rows = contractRows(MANIFEST);
  assert.deepEqual(rows, [
    { role: 'pool', contractId: 'CPOOL', package: 'pool' },
    { role: 'pool', contractId: 'CGVK', package: 'pool-gvk' },
    { role: 'asp_membership', contractId: 'CALLOW', package: 'asp-membership' },
    { role: 'added_asp_membership', contractId: 'CADDED', package: 'asp-membership' },
    { role: 'asp_non_membership', contractId: 'CBLOCK', package: 'asp-non-membership' },
    { role: 'public_key_registry', contractId: 'CREG', package: 'public-key-registry' },
    { role: 'public_key_registry_verifier', contractId: 'CREGV', package: 'circom-groth16-verifier', key: 'keyOwnership' },
    { role: 'verifier.none', contractId: 'CNONE', package: 'circom-groth16-verifier', key: '' },
    VERIFIER_B,
  ]);
  assert.deepEqual(rows.map((row) => recordedHash(MANIFEST, row)), [...Array(2), HASH, HASH, 'block', undefined, 'regv', ...Array(2)]);
  const withRelease = { ...MANIFEST, contracts_release: { code: { CB: OTHER_HASH, CALLOW: OTHER_HASH } } };
  assert.deepEqual(rows.map((row) => recordedHash(withRelease, row)), [...Array(2), OTHER_HASH, HASH, 'block', undefined, 'regv', undefined, OTHER_HASH]);
  // As the CLI loads a manifest with a field of the wrong type: no records, and no registry verifier.
  for (const malformed of [{ ...withRelease, contracts_release: { network: 5, code: { CB: OTHER_HASH } } }, { ...withRelease, asp_membership_wasm_hash: 5 }]) {
    const bare = contractRows(malformed);
    assert.deepEqual(bare, rows.filter(({ role }) => role !== 'public_key_registry_verifier'));
    assert.deepEqual(bare.map((row) => recordedHash(malformed, row)), Array(8).fill(undefined));
  }
});

test('a manifest with a field of the wrong type compares with none of its records', () => {
  // If read, the recorded OTHER_HASH would make the code differ.
  const code = releaseCode(HOME, '--features=vk-futurenet-b');
  for (const malformed of [released(OTHER_HASH, 5), { ...released(OTHER_HASH, null), asp_membership_wasm_hash: 5 }]) {
    assert.deepEqual(codeStatus(malformed, VERIFIER_B, code, null), { status: 'unknown', reason: 'not_recorded' });
    assert.equal(codeRecordsRead(malformed), false);
  }
  assert.equal(codeRecordsRead(MANIFEST), true);
  assert.equal(codeRecordsRead(released(HASH)), true);
});

test('a contract with no Wasm, such as a Stellar asset contract, is unknown', () => {
  const build = { repo: HOME, commit: COMMIT, runUrl: `https://github.com/${HOME}/actions/runs/7` };
  for (const lookup of [build, null, undefined]) {
    assert.deepEqual(codeStatus(released(HASH), VERIFIER_B, null, lookup), { status: 'unknown', reason: 'no_code' });
  }
});

/** A `contractmetav0` custom section holding `entries`, under 128 bytes so its size is one byte. */
function metaSection(entries) {
  const name = [...Buffer.from('contractmetav0')];
  const payload = entries.flatMap(([key, val]) => [...xdr.ScMetaEntry.scMetaV0(new xdr.ScMetaV0({ key, val })).toXDR()]);
  return [0, 1 + name.length + payload.length, name.length, ...name, ...payload];
}

test('wasmMeta returns the entries of both contractmetav0 sections, in order', async () => {
  const wasm = new Uint8Array([
    ...[0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00],
    ...metaSection([['cliver', '28.0.0'], ['bldopt', '--package=pool']]),
    ...metaSection([['source_repo', `github:${HOME}`]]),
  ]);
  const meta = await wasmMeta(wasm);
  assert.deepEqual(meta, [['cliver', '28.0.0'], ['bldopt', '--package=pool'], ['source_repo', `github:${HOME}`]]);
  assert.equal(sourceRepo(meta), HOME);
});
