# Operator manual

This manual is for people who want to run their own privacy pool, their own ASP (association set
provider, the party that decides who may spend), or both. It assumes you know Stellar accounts and
the Stellar CLI, and no background in zero-knowledge proofs. The [Glossary](glossary.md) defines
every term the pages use.

Warning: the code is unaudited, and the committed circuit keys come from a local setup, not a
trusted setup ceremony. Don't hold real value in a deployment.

## Roles

A deployment has six roles. One organization can hold all of them.

| Role | Holds | Does |
| --- | --- | --- |
| Admin account signers | One signer key each | Approve admin calls: pause deposits, re-point pools, claim fees, edit trees, transfer the admin; sign pause files ahead of time |
| ASP | The admin of a tree | Adds members to the allowlist, adds and removes blocklist entries |
| GVK holder | A GVK private key | Decrypts every note in a `pool-gvk` pool |
| Bootnode operator | A server and a PostgreSQL database | Serves contract events older than the RPC keeps |
| App host | A static web server | Serves the web app and its admin page |
| Users | A Stellar wallet | Deposit, transfer, and withdraw |

Each pool and each tree has its own admin. `deploy.sh` makes one account the admin of every
contract, so to give a role to another account, transfer the admin of each contract that role
covers, as [Transfer the admin](../governance.md#transfer-the-admin) describes.

The admin page covers every role. The `spp` CLI and the SDKs have one command group or handle per
role:

| Role | CLI | Rust and browser SDK |
| --- | --- | --- |
| ASP of an allowlist | `spp allowlist` | `AllowlistOperator` |
| ASP of a blocklist | `spp blocklist` | `BlocklistOperator` |
| Admin of a pool | `spp pool-admin` | `PoolAdmin` |
| Admin account signers | `spp envelope` | `Envelopes`, Rust only |
| GVK holder | `spp gvk audit` | `GvkAuthority` |

A write command signs with `--account` and sends the call at once, which suits a single-key admin.
With `--out FILE`, it writes the unsigned call for the signers of a multisig admin instead, as
[Sign with the CLI](../governance.md#sign-with-the-cli) describes.

## Components

```mermaid
flowchart LR
    users["Users<br/>(web app, spp CLI)"]
    admin["Admin account"]
    subgraph chain["Stellar network"]
        pool["Pool"]
        verifier["Verifier"]
        allow["Allowlist"]
        block["Blocklist"]
        registry["Public key registry"]
        rpc["RPC"]
    end
    bootnode["Bootnode"]
    gvk["GVK holder"]

    users -- "transact" --> pool
    users -- "register keys" --> registry
    pool -- "check proof" --> verifier
    pool -- "read roots" --> allow
    pool -- "read root" --> block
    admin -- "pause, re-point,<br/>claim fees, transfer admin" --> pool
    admin -- "edit entries" --> allow
    admin -- "edit entries" --> block
    rpc -. "recent events" .-> users
    rpc -. "events" .-> bootnode
    bootnode -. "old events" .-> users
    rpc -. "events" .-> gvk
```

No server holds user data or keys. The web app and the CLI rebuild each user's notes from contract
events, read through an RPC or, for events older than the RPC keeps, a bootnode.

## Pages

1. [How a pool works](how-a-pool-works.md): notes, the three operations, and what stays private.
2. [Run it locally](run-locally.md): a full deployment on your machine in four commands.
3. [Configuration](configuration.md): every choice a deployment makes, and which ones are final.
4. [Deploy a pool](deploy.md): circuit keys, the admin account, `deploy.sh`, the app, and the
   bootnode.
5. [Run an ASP](run-an-asp.md): add and remove allowlist members and blocklist entries.
6. [Compliance controls](compliance.md): what each control enforces and what it doesn't.
7. [Governance](governance.md): what the admin can do, what a pause stops, and what happens if
   the admin account is lost or stolen.
8. [Features and limits](features-and-limits.md): what users and operators can do, and the
   fixed limits.
9. [Glossary](glossary.md): the terms these pages use.
