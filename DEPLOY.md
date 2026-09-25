# Deploying pools

`deployments/scripts/deploy.sh` provides support for deploying pools.
Requires building contracts. See [CONTRIBUTING.md](CONTRIBUTING.md) for build prerequisites.

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
  --pool blocklist:native:$(stellar contract id asset --asset native --network testnet) \
  --pool allowlist-blocklist:gvk-traceable:native:$(stellar contract id asset --asset native --network testnet)
```
