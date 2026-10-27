// Which CI run built each contract's code, from its Wasm's meta, the manifest, and GitHub's
// attestations. Reads what an attestation's payload claims and checks no signature. Kept out of
// admin.js so Node tests can import it.
import { xdr } from '@stellar/stellar-sdk';

const HOME_REPO = 'NethermindEth/stellar-private-payments';
const WORKFLOW = '.github/workflows/contracts-release.yml';
const WORKFLOW_REF = 'refs/heads/main';
const SLSA_PROVENANCE = 'https://slsa.dev/provenance/v1';
const VERIFIER = 'circom-groth16-verifier';
const MATCH_TTL_MS = 86_400_000;
const MISS_TTL_MS = 600_000;
// How long a GitHub request may take, so a stalled one reads as unknown instead of holding the whole table.
export const GITHUB_TIMEOUT_MS = 10_000;
const REPO = /^github:([A-Za-z0-9-]+\/[A-Za-z0-9._-]+)$/;

/**
 * Returns one `{ role, contractId, package }` row per contract the manifest names. A verifier's row
 * adds its `key`.
 */
export function contractRows(manifest) {
  const verifier = (role, contractId, key) => ({ role, contractId, package: VERIFIER, key });
  return [
    ...manifest.pools.map(({ poolContractId, gvkMode }) => ({
      role: 'pool',
      contractId: poolContractId,
      package: gvkMode && gvkMode !== 'off' ? 'pool-gvk' : 'pool',
    })),
    { role: 'asp_membership', contractId: manifest.asp_membership, package: 'asp-membership' },
    ...(manifest.added_asp_memberships ?? []).map(({ contractId }) => ({ role: 'added_asp_membership', contractId, package: 'asp-membership' })),
    { role: 'asp_non_membership', contractId: manifest.asp_non_membership, package: 'asp-non-membership' },
    { role: 'public_key_registry', contractId: manifest.public_key_registry, package: 'public-key-registry' },
    ...(codeRecords(manifest).public_key_registry_verifier
      ? [verifier('public_key_registry_verifier', manifest.public_key_registry_verifier, 'keyOwnership')]
      : []),
    ...Object.entries(manifest.verifiers).map(([key, contractId]) => verifier(`verifier.${key || 'none'}`, contractId, key)),
  ];
}

// Without a release entry, the hash deploy.sh records for the role.
const ROLE_HASH = {
  asp_membership: 'asp_membership_wasm_hash',
  added_asp_membership: 'asp_membership_wasm_hash',
  asp_non_membership: 'asp_non_membership_wasm_hash',
  public_key_registry_verifier: 'public_key_registry_verifier_wasm_hash',
};

const isMap = (value) => typeof value === 'object' && value !== null && !Array.isArray(value);
const isText = (value) => value == null || typeof value === 'string';

/** Reports whether every code record in the manifest has the right type. */
export function codeRecordsRead(manifest) {
  const { contracts_release: release = {} } = manifest;
  return isMap(release) && isText(release.network)
    && (release.code === undefined || (isMap(release.code) && Object.values(release.code).every((hash) => typeof hash === 'string')))
    && [...Object.values(ROLE_HASH), 'public_key_registry_verifier'].every((field) => isText(manifest[field]));
}

// As in the CLI, one record of the wrong type drops them all.
const codeRecords = (manifest) => (codeRecordsRead(manifest) ? manifest : {});

/** Returns the Wasm hash the manifest records for a row's contract, if any. */
export function recordedHash(manifest, { role, contractId }) {
  const records = codeRecords(manifest);
  return records.contracts_release?.code?.[contractId] ?? records[ROLE_HASH[role]];
}

/** Returns the `[key, value]` entries of every `contractmetav0` section of a Wasm, in order. */
export async function wasmMeta(bytes) {
  return WebAssembly.Module.customSections(await WebAssembly.compile(bytes), 'contractmetav0')
    .flatMap((section) => xdr.decodeStream(xdr.ScMetaEntry, new Uint8Array(section)))
    .map(({ value: { key, val } }) => [key.toString(), val.toString()]);
}

/**
 * Returns the meta's first `source_repo` as `owner/name`, or null when it is not a valid GitHub
 * repository.
 */
export function sourceRepo(meta) {
  const repo = meta.find(([key]) => key === 'source_repo')?.[1].match(REPO)?.[1];
  return repo && !['.', '..'].includes(repo.split('/')[1]) ? repo : null;
}

/**
 * Reports whether `url` is `https://github.com/<repo>/actions/runs/<n>`, optionally followed by
 * `/attempts/<n>`.
 */
function isRunUrl(url, repo) {
  const prefix = `https://github.com/${repo}/actions/runs/`;
  return typeof url === 'string' && url.startsWith(prefix) && /^[0-9]+(\/attempts\/[0-9]+)?$/.test(url.slice(prefix.length));
}

/** Reports whether `build` names `repo`, a commit of 40 hex digits, and a run in `repo`. */
const isBuildOf = (build, repo) => build?.repo === repo
  && typeof build.commit === 'string'
  && /^[0-9a-f]{40}$/i.test(build.commit)
  && isRunUrl(build.runUrl, repo);

/**
 * Returns GitHub's answer for `hash`: the `{ repo, commit, runUrl }` the first release attestation
 * names, or null for none (a 404 included). Throws, saying why, for any other reply.
 */
export async function parseAttestation(response, { hash, repo }) {
  if (response.status === 404) return null;
  if (response.status !== 200) throw new Error(`GitHub answered HTTP ${response.status}`);
  const attestations = (await response.json().catch(() => null))?.attestations;
  if (!Array.isArray(attestations)) throw new Error('GitHub\'s reply could not be read');
  return attestations.map((attestation) => releaseBuild(attestation, hash, repo)).find(Boolean) ?? null;
}

/**
 * Returns the build an attestation names when it is an SLSA provenance for `hash` by the release
 * workflow on `main` of `repo`, else null.
 */
function releaseBuild(attestation, hash, repo) {
  let statement;
  try {
    statement = JSON.parse(atob(attestation.bundle.dsseEnvelope.payload));
  } catch {
    return null;
  }
  const { buildDefinition, runDetails } = statement?.predicate ?? {};
  const workflow = buildDefinition?.externalParameters?.workflow;
  const build = {
    repo,
    commit: buildDefinition?.resolvedDependencies?.[0]?.digest?.gitCommit,
    runUrl: runDetails?.metadata?.invocationId,
  };
  const matches = statement?.predicateType === SLSA_PROVENANCE
    && Array.isArray(statement.subject)
    && statement.subject.some((subject) => subject?.digest?.sha256 === hash)
    && workflow?.repository === `https://github.com/${repo}`
    && workflow.path === WORKFLOW
    && workflow.ref === WORKFLOW_REF
    && isBuildOf(build, repo);
  return matches ? build : null;
}

/**
 * Returns the first of `differs`, `attested`, and `matches_manifest` that applies to a row's
 * contract, else `unknown` with its `reason`. `code` is `{ hash, meta }`, null when the contract
 * runs no Wasm, or undefined when unread. `lookup` is what `parseAttestation` returns, null when
 * the meta has no valid `source_repo`, or undefined when GitHub could not be checked.
 */
export function codeStatus(manifest, row, code, lookup) {
  if (code === null) return { status: 'unknown', reason: 'no_code' };
  if (!code) return { status: 'unknown', reason: 'code_unread' };
  if (differs(manifest, row, code)) return { status: 'differs' };
  if (lookup) {
    const { repo, commit, runUrl } = lookup;
    return { status: 'attested', repo, commit, runUrl, otherRepo: repo !== HOME_REPO };
  }
  if (lookup === undefined) return { status: 'unknown', reason: 'github_unchecked' };
  return recordedHash(manifest, row) != null ? { status: 'matches_manifest' } : { status: 'unknown', reason: 'not_recorded' };
}

/**
 * Returns a row's code status, as `codeStatus` does, asking GitHub through `lookupAttestation` only
 * when the code fits the row and its Wasm names a valid `source_repo`. Adds `problem` when GitHub
 * could not be checked.
 */
export async function checkCode({ manifest, row, code, fetch, storage, now }) {
  const repo = code && !differs(manifest, row, code) ? sourceRepo(code.meta) : null;
  if (!repo) return codeStatus(manifest, row, code, null);
  const { lookup, problem } = await lookupAttestation({ fetch, storage, hash: code.hash, repo, now });
  return { ...codeStatus(manifest, row, code, lookup), ...(problem && { problem }) };
}

/** Reports whether a row's code is not the manifest's or does not fit the row's role. */
function differs(manifest, row, code) {
  const recorded = recordedHash(manifest, row);
  return (recorded != null && recorded !== code.hash) || !fitsRole(row, codeRecords(manifest).contracts_release?.network, code.meta);
}

/**
 * Reports whether the meta's `bldopt` entries, if any, hold exactly one package, the row's, and for
 * a verifier exactly one feature, its key's.
 */
function fitsRole(row, network, meta) {
  const opts = meta.filter(([key]) => key === 'bldopt').map(([, value]) => value);
  const values = (prefix) => opts.filter((opt) => opt.startsWith(prefix)).map((opt) => opt.slice(prefix.length));
  const packages = values('--package=');
  const features = values('--features=');
  return opts.length === 0 || (packages.length === 1 && packages[0] === row.package
    && (row.key === undefined || (features.length === 1 && namesKey(features[0], row.key, network))));
}

// The verifier's `build.rs` rule: `vk-<network>-<key>`, lowercased, `_` as `-`, "" as `none`.
const dashed = (name) => name.toLowerCase().replaceAll('_', '-');

/**
 * Reports whether `feature` embeds `key` for `network`, or for any network without a dash when it
 * is absent.
 */
function namesKey(feature, key, network) {
  const tail = dashed(key || 'none');
  if (network != null) return feature === `vk-${dashed(network)}-${tail}`;
  // The first dash ends the network, so `vk-testnet-a-gvk-v` never names `gvk_V`.
  return /^vk-[^-]+-(.+)$/.exec(feature)?.[1] === tail;
}

// Rows that share a Wasm wait on one request.
const asking = new Map();

/**
 * Returns GitHub's answer for `hash` in `repo` as `{ lookup }`, from `storage` while it is fresh:
 * 24 hours for a match and 10 minutes for a miss. Only a match or a miss is cached; for any other
 * reply, or none within `timeoutMs`, `lookup` is undefined and `problem` says why. A call for a hash
 * already being asked about shares that request. `storage` defaults to `localStorage`, and
 * `timeoutMs` to `GITHUB_TIMEOUT_MS`. `now` and `timeoutMs` are in milliseconds.
 */
export function lookupAttestation(options) {
  const key = `${options.repo}@${options.hash}`;
  if (!asking.has(key)) asking.set(key, ask(options).finally(() => asking.delete(key)));
  return asking.get(key);
}

async function ask({ fetch, storage, hash, repo, now, timeoutMs = GITHUB_TIMEOUT_MS }) {
  const key = `poolstellar_code_status_${hash}`;
  try {
    // Read inside the try: blocked storage throws on access, and costs only a request.
    const { checkedAt, lookup } = JSON.parse((storage ?? localStorage).getItem(key));
    // An entry stamped in the future, after the clock moved back, is stale. One of another shape,
    // from another version or edited by hand, is asked again.
    const age = now - checkedAt;
    if ((lookup === null || isBuildOf(lookup, repo)) && age >= 0 && age < (lookup ? MATCH_TTL_MS : MISS_TTL_MS)) return { lookup };
  } catch {
    // No entry, a corrupt one, or no storage.
  }
  let lookup;
  try {
    const response = await fetch(`https://api.github.com/repos/${repo}/attestations/sha256:${hash}`, { signal: AbortSignal.timeout(timeoutMs) });
    lookup = await parseAttestation(response, { hash, repo });
  } catch (err) {
    return { problem: err.message };
  }
  try {
    (storage ?? localStorage).setItem(key, JSON.stringify({ checkedAt: now, lookup }));
  } catch {
    // Full or blocked storage only costs a request on the next load.
  }
  return { lookup };
}
