# Deploying pools

`deployments/scripts/deploy.sh` provides support for deploying pools.
It deploys the contracts of a release, as
[Deploy from a release](#deploy-from-a-release) describes. Without one, it
builds the contracts first; see [CONTRIBUTING.md](CONTRIBUTING.md) for build
prerequisites.

## Usage

```sh
deployments/scripts/deploy.sh <network> [OPTIONS]
```

Run `deployments/scripts/deploy.sh --help` for the full, authoritative option
list; this file explains the pool spec syntax and walks through common cases.

## Pool spec syntax

```
--pool [<policy>:][<gvk-mode>:]<asset-spec>
```

`--pool` is repeatable — a single deployment can mix policies and GVK modes
across pools. Each (policy, GVK mode) combination actually used gets its own
verifier contract, since the verifying key is baked into the WASM.

| Placeholder | Values |
|---|---|
| `<policy>` | See [ASP policies](#asp-policies) below. |
| `<gvk-mode>` | Omit for `gvk-off`. See [Global View Key (GVK)](#global-view-key-gvk) below. |
| `<asset-spec>` | `native:<TOKEN_CONTRACT_ID>` \| `classic:<CODE>:<ISSUER>:<TOKEN_CONTRACT_ID>`. `<TOKEN_CONTRACT_ID>` must be the asset's own Stellar asset contract. `deploy.sh` warns about each flag that gives a classic issuer a power over the pool's balance. |

If neither `--token` nor `--pool` is given, one native XLM pool deploys by
default.

## Required options

| Option | Meaning |
|---|---|
| `--deployer <NAME>` | Stellar identity or secret key used to deploy |
| `--asp-levels <N>` | Merkle tree levels for asp-membership |
| `--pool-levels <N>` | Merkle tree levels for pool |
| `--max-deposit <N>` | Maximum deposit amount |
| `--kdf-domain <STRING>` | Privacy key derivation domain. Any chosen string. Shows in the message signed by users for key derivation |
| `--policy-flags <SPEC>` | Default `<policy>` for `--pool` specs that omit one; required unless every spec includes its own |

## Other options

| Option | Meaning |
|---|---|
| `--admin <ADDRESS>` | Admin address (`G...` or `C...`); defaults to the deployer's. For the multisig admin account a shared deployment needs, see the [governance runbook](https://github.com/NethermindEth/stellar-private-payments/blob/main/docs/src/governance.md) |
| `--token <ADDRESS>` | Legacy single-pool native XLM contract (cannot mix with `--pool`) |
| `--gvk-authority-pubkey <JSON>` / `--gvk-authority-pubkey-file <PATH>` | Admin Baby JubJub public key (`{"x":"0x..","y":"0x.."}`), required by any pool using `gvk-viewonly` or `gvk-traceable` |
| `--vk-json <JSON>` / `--vk-file <PATH>` | Verification key for allowlist-blocklist (AB) ceremony builds only — other VKs load automatically from `deployments/<network>/circuit_keys/` |
| `--skip-init` | Deploy Wasm only, no constructors |
| `--release-dir <DIR>` | Deploy the contracts of a release downloaded to `<DIR>` instead of building them. Cannot be combined with `--vk-json`, `--vk-file`, or `--skip-init` |
| `--release-repo <OWNER/REPO>` | Repository whose `contracts-release.yml` workflow must have attested the release; defaults to `NethermindEth/stellar-private-payments` |
| `--allow-unverified` | Warn instead of stopping when the release's attestation cannot be verified, or, on mainnet, when the contracts are built locally |
| `--yes` | Skip the confirmation prompt on mainnet |

Per-pool `policyFlags` and `gvkMode` are recorded in
`deployments/<network>/deployments.json`.

## ASP policies

The Association Set Provider (ASP) membership/non-membership trees let a pool
screen who is transacting without compromising privacy: proofs show
the user belongs to an approved set or avoids a blocked one.

| `<policy>` | Meaning |
|---|---|
| `none` | Unrestricted — no ASP membership or non-membership proof required. |
| `allowlist` | User must prove membership in the ASP membership tree (approved public keys only). |
| `blocklist` | User must prove non-membership in the ASP non-membership tree (excluded public keys are rejected). |
| `allowlist-blocklist` | Both checks: membership in the allowlist and non-membership in the blocklist. |

## Global View Key (GVK)

A Global View Key lets the pool admin decrypt and view notes — see [Global
View Key](docs/src/global_view_key.md) for the full scheme.

| `<gvk-mode>` | Meaning |
|---|---|
| `gvk-off` (default) | Deploys plain `pool`, no encryption or admin visibility. |
| `gvk-viewonly` | Deploys `pool-gvk`; admin can decrypt note outputs only. |
| `gvk-traceable` | Deploys `pool-gvk`; admin can decrypt both inputs and outputs. |

Any pool spec using `gvk-viewonly` or `gvk-traceable` needs the admin's Baby
JubJub public key via `--gvk-authority-pubkey-file`.

`tools/gvkey-gen` generates and validates one such key:

```sh
cargo run -p gvkey-gen -- generate --out-file admin-d.json > admin-pub.json
```

**Back up `admin-d.json` — the private key cannot be recovered.** `gvkey-gen
generate` can also save the key into an encrypted client SDK wallet database via
`--db PATH --storage-account <identity>`.

## Template

Every option in its generic `<placeholder>` form:

```sh
deployments/scripts/deploy.sh <network> \
  --deployer <identity> \
  --policy-flags <policy> \
  --asp-levels <n> \
  --pool-levels <n> \
  --max-deposit <n> \
  --kdf-domain <string> \
  --pool <policy>:<gvk-mode>:<asset-spec> \
  --gvk-authority-pubkey-file <path>   # only if any pool uses gvk-viewonly/gvk-traceable
```

## Examples

Single native XLM pool, blocklist only (uses the committed key at
`deployments/testnet/circuit_keys/policy_tx_2_2_B_vk.json`, no `--vk-file`
needed):

```sh
deployments/scripts/deploy.sh testnet \
  --deployer <identity> \
  --policy-flags blocklist \
  --asp-levels 10 \
  --pool-levels 20 \
  --max-deposit 1000000000 \
  --kdf-domain Nethermind \
  --pool native:$(stellar contract id asset --asset native --network testnet)
```

Mixed-policy: a blocklist pool alongside an allowlist-blocklist pool, both
native XLM:

```sh
deployments/scripts/deploy.sh testnet \
  --deployer <identity> \
  --asp-levels 10 \
  --pool-levels 20 \
  --max-deposit 1000000000 \
  --kdf-domain Nethermind \
  --pool blocklist:native:$(stellar contract id asset --asset native --network testnet) \
  --pool allowlist-blocklist:native:$(stellar contract id asset --asset native --network testnet)
```

Mixing a plain pool with a GVK-traceable one in one deployment:

```sh
deployments/scripts/deploy.sh testnet \
  --deployer <identity> \
  --gvk-authority-pubkey-file ./admin-pub.json \
  --asp-levels 10 \
  --pool-levels 20 \
  --max-deposit 1000000000 \
  --kdf-domain Nethermind \
  --pool blocklist:native:$(stellar contract id asset --asset native --network testnet) \
  --pool allowlist-blocklist:gvk-traceable:native:$(stellar contract id asset --asset native --network testnet)
```

## Deploy from a release

A contracts release is the GitHub release `contracts-v<version>`, where
`<version>` is the contracts version, the `version` under `[workspace.package]`
in the root `Cargo.toml`. It holds the Wasm of every contract, a verifier Wasm
for each `policy_tx_2_2*_vk.json` and `keyOwnership_vk.json` file in
`deployments/*/circuit_keys/`, the source archive they were built from,
`contracts.json`, which says what each Wasm is, and `SHA256SUMS`. Bumping the
contracts version on `main` publishes a release, as
[CONTRIBUTING.md](CONTRIBUTING.md) describes: the `contracts-release.yml`
workflow builds the files, rebuilds them on a second runner, and attests each
file, signing a GitHub record that this run built it, before publishing it.

Download a release into a new directory and pass that directory to
`--release-dir`:

```sh
gh release download contracts-v<version> \
  --repo NethermindEth/stellar-private-payments --dir <release-dir>
deployments/scripts/deploy.sh testnet \
  --deployer <identity> \
  --policy-flags blocklist \
  --asp-levels 10 \
  --pool-levels 20 \
  --max-deposit 1000000000 \
  --kdf-domain Nethermind \
  --pool native:$(stellar contract id asset --asset native --network testnet) \
  --release-dir <release-dir>
```

Before any transaction, `deploy.sh` checks the release:

1. It runs `gh attestation verify` on `SHA256SUMS`, which passes only when
   `contracts-release.yml` on the `main` branch of `--release-repo` attested
   the file on a GitHub-hosted runner. `gh` must be installed and logged in.
2. It checks `contracts.json` and every file it deploys against `SHA256SUMS`,
   and stops when `contracts.json` names a repository other than
   `--release-repo`.
3. It picks each verifier by the SHA-256 of this network's key file, and
   checks the build options each Wasm records in its meta, the contract
   metadata `stellar contract info meta` prints: the package it was built
   from and, for a verifier, the feature that embeds its key.

It then deploys the files it picked, and records the release and each
contract's Wasm hash in the manifest under `contracts_release`.

When the attestation check fails, `deploy.sh` stops. `--allow-unverified`
turns that stop into a warning and relaxes no other check, but those checks
then rest only on what the release says about itself, including which key
each verifier holds.

A fork publishes its own releases the same way, from its own `main` with
GitHub Actions turned on. Pass the fork as `--repo` to `gh release download`
and as `--release-repo` to `deploy.sh`.

`scripts/build-contracts.sh --out <dir>` builds the same files locally, with
no attestation, so its output is for checking a release. `deploy.sh` deploys
it only with `--allow-unverified`, and only when it was built with `--tag` and
`--repo`, because `deploy.sh` compares the repository its `contracts.json`
names with `--release-repo`.

Without `--release-dir`, `deploy.sh` builds the contracts with your own
Stellar CLI and Rust toolchain. That code matches no release, and the manifest
records none. On mainnet, which `deploy.sh` detects by the network
passphrase, it refuses such a run unless `--allow-unverified` is passed. On
every mainnet run, with or without a release, it also refuses `--vk-json` and
`--vk-file`, a `circuit_keys` directory or key file that is a link, and
verifiers built for another network.

A release holds verifiers only for the key files committed when it was made.
Before a network with keys of its own, such as mainnet, can deploy from a
release, commit its key files under `deployments/<network>/circuit_keys/`, add
a feature for each one to `contracts/circom-groth16-verifier/Cargo.toml`,
named as the `vk-testnet-*` features are, and then bump the contracts version.
Off mainnet, a network whose key files are copies of testnet's deploys the
release's testnet verifiers.

## Keep a deployment alive

The network archives a contract entry when its lifetime runs out, and
rewriting an entry does not extend it. Each user call extends the entries it
depends on by at most a day, so a pool with steady traffic stays alive while a
quiet one runs down. An archived entry is restored inside the next transaction
that needs it, and that transaction's sender pays for a full minimum lifetime,
which is several XLM for a contract's code.

To keep the entries user calls depend on alive and spare users that cost,
extend the deployment from an operator account at least every 150 days. User
calls then add nothing to an entry until it falls below 30 days, and pay no
rent for it. The loop below leaves nullifiers, registrations, and the
blocklist's `Node` entries to archive. The next call that needs one of them
restores it.

Without that upkeep, a user call extends an entry once the entry has lost an
hour. A transaction simulated just before that point and applied just after
it owes an hour of rent that its simulation did not include. The SDK adds
that hour to the refundable fee of every transaction it builds. The sender
needs just over 0.6 XLM more balance to submit a `transact`, and the network
refunds whatever rent the transaction does not owe.

For each contract in the deployment, the following loop extends its instance,
its `State`, `Admin`, and `NextIndex` entries, and its Wasm. It also reads the
trees from each pool, since a re-pointed pool can read a blocklist the manifest
does not name:

```bash
NETWORK=testnet
OPERATOR=deployer
MANIFEST="deployments/$NETWORK/deployments.json"
STATE=AAAAEAAAAAEAAAABAAAADwAAAAVTdGF0ZQAAAA==
ADMIN=AAAAEAAAAAEAAAABAAAADwAAAAVBZG1pbgAAAA==
NEXT_INDEX=AAAAEAAAAAEAAAABAAAADwAAAAlOZXh0SW5kZXgAAAA=
IDS="$(
  jq -r '.asp_membership, .asp_non_membership, .public_key_registry, .verifiers[],
    .pools[].poolContractId, (.added_asp_memberships // [])[].contractId' "$MANIFEST"
  for pool in $(jq -r '.pools[].poolContractId' "$MANIFEST"); do
    stellar ledger entry fetch contract-data --contract "$pool" --network "$NETWORK" --key-xdr AAAAFA== \
      | jq -r '.entries[0].val.contract_data.val.contract_instance.storage[]
        | select(.key.vec[0].symbol == "ASPMembership" or .key.vec[0].symbol == "ASPNonMembership")
        | .val.address'
  done
)"
for id in $(sort -u <<<"$IDS"); do
  args=(--ledgers-to-extend 3110399 --source-account "$OPERATOR" --network "$NETWORK")
  stellar contract extend --id "$id" "${args[@]}"
  stellar contract extend --id "$id" --key-xdr "$STATE" --key-xdr "$ADMIN" \
    --key-xdr "$NEXT_INDEX" "${args[@]}"
  stellar contract extend --wasm-hash "$(stellar contract info hash --id "$id" --network "$NETWORK")" "${args[@]}"
done
```

Replace the following:

- `testnet`: the network the deployment is on.
- `deployer`: the `stellar keys` identity that pays for the extensions.

The extension skips a key the contract does not have. The value 3,110,399 is
the longest extension the network accepts, one ledger less than its maximum
entry lifetime. An extension also skips an entry that has already archived.
Restore that entry first with `stellar contract restore` and the same
arguments.

The Wasm is most of the cost. At mainnet's rate on 2026-10-07, keeping the
code of two pools, their two verifiers, and both trees alive costs about
1.4 XLM a day.
