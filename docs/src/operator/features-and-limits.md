# Features and limits

## Web app

The user app has four views:

| View | What a user can do |
| --- | --- |
| Overview | See balances, notes, and recent activity across the deployment's pools |
| Move Funds | Deposit, transfer to a Stellar address or to a pair of public keys, and withdraw |
| Advanced | Choose which notes to spend and how to split the outputs |
| Disclosure | Generate a disclosure receipt, or verify one with no wallet |

On first use, the app asks the user to sign one message, from which it derives their keys, and
offers to register them in the public key registry. Settings show the user's public keys and ASP
secret, and set the bootnode and explorer URLs. A user can sign and pay with a different account
from the one that owns their notes.

## Admin page

The admin page builds every admin call into its Admin Transaction card, where the admin account's
signers review, sign, and submit it. Its tabs:

| Tab | Purpose |
| --- | --- |
| Overview | The tree addresses the other tabs write to, and each tree's state |
| Allowlist | Add members |
| Blocklist | Add and remove keys |
| Global View | Decrypt and export a GVK pool's notes with the GVK private key |
| Pools | Pause and unpause deposits, check and build re-points, and build and submit pause files |
| Admins | Propose, cancel, and accept admin transfers |

## CLI

The `spp` command-line client covers the user side of the app: `onboard`, `register`, `deposit`,
`transfer`, `withdraw`, `transact`, `overview`, `notes`, `feed`, `keys`, `asp-secret`, and
`disclosure generate` and `disclosure verify`. `transact` chooses the notes to spend and the
outputs, as [Advanced transactions](../transact.md) describes. The CLI signs with Stellar CLI
identities. It has no admin commands; admin calls go through the admin page or the Stellar CLI.

## SDKs

The Rust crate `stellar-private-payments` and the npm package `stellar-private-payments` expose
the same operations to other applications. See the
[Rust SDK README](https://github.com/NethermindEth/stellar-private-payments/blob/main/sdk/native/README.md)
and the
[browser SDK README](https://github.com/NethermindEth/stellar-private-payments/blob/main/sdk/web/README.md).

## Support

| Area | Supported |
| --- | --- |
| Assets | Native XLM, and classic assets whose issuer can't freeze or claw back balances |
| Browser wallets | Freighter |
| Browsers | Chromium-based browsers are tested. The app needs the Origin Private File System and web workers. |
| Networks | Any Stellar network with a manifest. The repository holds a testnet manifest; `deploy-local.sh` makes a local one. |

## Limits

| Limit | Value |
| --- | --- |
| Notes per transaction | Two spent, two created |
| Transactions per pool | 524,288, filling its commitment tree of 2^20 commitments |
| Allowlist members | 1,024 per allowlist |
| Notes per disclosure receipt | One to four. A receipt stops verifying once 90 more transactions land in the pool. |
| Contracts per manifest | 25 that clients index: the enabled pools, every allowlist, and the registry |
| Event history | About seven days on the public testnet RPC. Older history needs a bootnode. |
| Contract upgrades | None. A fix means new contracts. |

## Known gaps

- Contract storage expires when unused. A call that reads an archived entry restores it and pays
  for the restore, which can cost several XLM.
- Browser storage can be lost, for example to antivirus software. The user signs again to recover
  their keys, and the client rebuilds their notes from events. App settings and the record of past
  operations are lost.
