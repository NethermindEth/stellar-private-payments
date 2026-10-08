# Configuration

Most of a deployment's configuration is fixed at construction. No contract has an upgrade entry
point and no setter exists for these values, so changing one means deploying new contracts and
asking users to move.

## Fixed at deployment

`deploy.sh` takes each value below. For the option syntax, see [Deploying pools](../deploy.md).

| Choice | Option | Values | Effect |
| --- | --- | --- | --- |
| Network | `deploy.sh NETWORK` | A Stellar CLI network name | Names the manifest's folder. The manifest records the network's RPC URL and passphrase, and clients refuse a wallet or RPC on another network. |
| Asset | `--pool` | Native XLM, or a classic asset through its own Stellar asset contract | One pool holds one asset. `deploy.sh` refuses other token contracts and any classic asset whose issuer can freeze or claw back balances. |
| Policy | `--pool` prefix or `--policy-flags` | `none`, `allowlist`, `blocklist`, `allowlist-blocklist` | Which ASP checks the pool requires. See [Choose a policy](#choose-a-policy). |
| GVK mode | `--pool` prefix | `gvk-off` (default), `gvk-viewonly`, `gvk-traceable` | Whether the pool encrypts notes to a GVK, and which ones. See [Choose a GVK mode](#choose-a-gvk-mode). |
| GVK public key | `--gvk-authority-pubkey-file` | A key from `gvkey-gen` | The key every GVK pool in the run encrypts to. |
| Maximum deposit | `--max-deposit` | An amount in the token's smallest unit | The largest single deposit. `1000000000` is 100 XLM. The limit is per transaction, so a user can split a larger amount. Withdrawals have no limit. |
| KDF domain | `--kdf-domain` | Any string | Part of the message users sign to derive their keys. The same wallet gets different keys under another domain. |
| Pool depth | `--pool-levels` | `20` | The committed circuits prove against 20 levels. See [Limits](features-and-limits.md#limits) for the capacity this gives. |
| Allowlist depth | `--asp-levels` | `10` | The committed circuits prove against 10 levels. |
| Verifier | Built by `deploy.sh` | One per policy and GVK mode in use | The verifying key is built into the verifier, and a pool's verifier is fixed. |

One `deploy.sh` run deploys one allowlist, one blocklist, and one public key registry, and every
pool in the run shares them, along with the admin and the KDF domain.

## Changeable after deployment

| Setting | How | Who |
| --- | --- | --- |
| Admin of a pool or tree | Two-step transfer. See [Governance](governance.md). | The admin, then the new admin |
| Deposits open or paused | `pause_deposits` and `unpause_deposits` | The admin, or a holder of a pause file |
| Allowlist members | `insert_leaf`. There is no delete. | The allowlist's admin |
| Blocklist entries | `insert_leaf`, `insert_leaves`, and `delete_leaf` | The blocklist's admin |
| Trees a pool reads | Re-point to another tree of the pool's tree code | The pool's admin |
| Pools clients use | The `enabled` field of each pool in the manifest. Clients ignore a disabled pool entirely, so its users can't withdraw through them. The bootnode keys its archive on the enabled pools, so a change starts a new archive, and by default deletes the old one, which it can't rebuild past the RPC's event retention. | Whoever publishes the manifest |

## Choose a policy

The ASP screens the note public key of every note a transaction spends, deposits included. For
what that does and doesn't stop, see [Compliance controls](compliance.md#screening).

| Policy | Who can spend | ASP work | Removing someone |
| --- | --- | --- | --- |
| `none` | Anyone | None | Not possible |
| `allowlist` | Members only | Enroll each user before their first deposit | Re-point to a new allowlist without them |
| `blocklist` | Anyone not listed | List keys as needed | Delete the entry |
| `allowlist-blocklist` | Members not listed | Both | Either |

Blocklist writes force users with a transaction in flight to prove again; allowlist writes don't.
See [Allowlist and blocklist](run-an-asp.md#allowlist-and-blocklist).

## Choose a GVK mode

| Mode | Contract | The GVK holder can read |
| --- | --- | --- |
| `gvk-off` | `pool` | Nothing |
| `gvk-viewonly` | `pool-gvk` | Every note created: its owner's note public key, its amount, and its blinding |
| `gvk-traceable` | `pool-gvk` | Also every note spent, which links each spend to the transaction that created the note |

The GVK is fixed for the life of the pool. Transferring the admin does not move it, a lost GVK
private key ends the audit for good, and a leaked one exposes the pool's whole history. To
generate a key pair:

```bash
cargo run -p gvkey-gen -- generate --out-file gvk-private.json > gvk-public.json
```

Pass `gvk-public.json` to `deploy.sh` and keep `gvk-private.json` offline. For the encryption
scheme, see [Global View Key](../global_view_key.md).

## Client and hosting settings

| Setting | Where | Effect |
| --- | --- | --- |
| `SPP_NETWORK` | Web app build | Selects `deployments/NETWORK/` to bundle. One build serves one deployment. |
| `PUBLIC_URL` | Web app build | The path the app is served under, for example `/pools/`. |
| `--deployment` | `spp` CLI | The manifest's directory or file. The CLI also reads it from `deployment` under `[defaults]` in `~/.config/spp/config.toml`. |
| `BOOTNODE_DEPLOYMENT` | Bootnode | The manifest the bootnode indexes. For the other settings, see the [bootnode README](https://github.com/NethermindEth/stellar-private-payments/blob/main/tools/bootnode/README.md). |
| Bootnode URL | Each user's app settings, or `spp config set-bootnode` | The bootnode a client falls back to. Point users at yours. |
