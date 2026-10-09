# Deploying pools

`deployments/scripts/deploy.sh` provides support for deploying pools.
It builds the contracts before submitting deployment transactions. See
[CONTRIBUTING.md](CONTRIBUTING.md) for build prerequisites.

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
| `<asset-spec>` | `native:<TOKEN_CONTRACT_ID>` \| `contract:<TOKEN_CONTRACT_ID>` \| `classic:<CODE>:<ISSUER>:<TOKEN_CONTRACT_ID>` |

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
| `--admin <ADDRESS>` | Admin address (`G...` or `C...`); defaults to the deployer's |
| `--token <ADDRESS>` | Legacy single-pool token contract (cannot mix with `--pool`) |
| `--gvk-authority-pubkey <JSON>` / `--gvk-authority-pubkey-file <PATH>` | Admin Baby JubJub public key (`{"x":"0x..","y":"0x.."}`), required by any pool using `gvk-viewonly` or `gvk-traceable` |
| `--vk-json <JSON>` / `--vk-file <PATH>` | Verification key for allowlist-blocklist (AB) ceremony builds only — other VKs load automatically from `deployments/<network>/circuit_keys/` |
| `--skip-init` | Deploy WASM only, no constructors |
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
generate` can also save the key into a client SDK wallet database via
`--db PATH`.

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

Mixed-policy: a blocklist native pool alongside an allowlist-blocklist EURC
pool (for testnet EURC, see the [Circle EURC
docs](https://www.circle.com/eurc#how-to-start-using-eurc) and
[faucet](https://faucet.circle.com/)):

```sh
deployments/scripts/deploy.sh testnet \
  --deployer <identity> \
  --asp-levels 10 \
  --pool-levels 20 \
  --max-deposit 1000000000 \
  --kdf-domain Nethermind \
  --pool blocklist:native:$(stellar contract id asset --asset native --network testnet) \
  --pool allowlist-blocklist:classic:EURC:GB3Q6QDZYTHWT7E5PVS3W7FUT5GVAFC5KSZFFLPU25GO7VTC3NM2ZTVO:$(stellar contract id asset --asset EURC:GB3Q6QDZYTHWT7E5PVS3W7FUT5GVAFC5KSZFFLPU25GO7VTC3NM2ZTVO --network testnet)
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
it owes rent the simulation did not include, so it can fail with an
insufficient refundable fee and has to be submitted again.

For each contract in the deployment, the following loop extends its instance,
its `State`, `Admin`, and `NextIndex` entries, and its Wasm:

```bash
NETWORK=testnet
OPERATOR=deployer
STATE=AAAAEAAAAAEAAAABAAAADwAAAAVTdGF0ZQAAAA==
ADMIN=AAAAEAAAAAEAAAABAAAADwAAAAVBZG1pbgAAAA==
NEXT_INDEX=AAAAEAAAAAEAAAABAAAADwAAAAlOZXh0SW5kZXgAAAA=
for id in $(jq -r '.asp_membership, .asp_non_membership, .public_key_registry,
    .verifiers[], .pools[].poolContractId' "deployments/$NETWORK/deployments.json"); do
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
