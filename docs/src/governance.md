# Governance runbook

One key administers every pool and tree a deployment runs: the admin account, a Stellar account
that needs M of its N signers to sign every change. This runbook is for those signers and for the
holders of the account's pre-signed pauses.

The admin can pause deposits, switch the trees a pool reads, edit the lists, and hand its role to
another account. It cannot move funds. Only `transact` moves tokens, against a verifier fixed at
construction, and no contract has an upgrade entry point.

The commands below run on `testnet`. On another network, replace `testnet` with its name.

## Set up the admin account

The admin account has this shape:

- M is at least 2, and every signer is an ed25519 key of weight 1. An M-of-N account survives
  N - M lost signers and M - 1 stolen ones, as long as the signers replace each before the next.
  A 1-of-N account survives no stolen signer.
- The low, medium, and high thresholds all equal M, and the master weight is 0, so the account's
  own key signs nothing.
- The account is never merged. Anyone can create a merged account again at the same address, and
  it comes back with its master key as its only signer.

Each signer creates a key on their own device and sends its address. The signer signs with
that key from two programs, so the key has to be in both: Freighter signs admin calls and pause
files on the admin page, and the Stellar CLI signs a signer replacement and the other transactions
the page cannot describe (see [Sign with the CLI](#sign-with-the-cli)). Create the key as an
account in Freighter, then add it to the CLI from Freighter's recovery phrase, which the CLI keeps
in the operating system's credential store:

```bash
stellar keys add SIGNER --secure-store
```

Replace `SIGNER` with a name for the key. The command asks for the recovery phrase. For a
Freighter account other than the first, add `--hd-path N`, where `N` counts Freighter's accounts
from 0. Don't create the key with `stellar keys generate`, which by default writes its seed phrase
to a plain-text file in the CLI's configuration directory.

One person then creates the account and gives it its signers in one transaction:

```bash
stellar keys generate admin
scripts/gov/create-multisig.sh testnet --account admin --threshold 2 --fund \
  --signer SIGNER_1 --signer SIGNER_2 --signer SIGNER_3
```

Replace `SIGNER_1`, `SIGNER_2`, and `SIGNER_3` with the signers' addresses (`G...`). The script
refuses a threshold below 2 or above the number of signers, a signer given twice or by an alias,
and an account that already has signers, then prints the signers and thresholds it reads back
from the network. On mainnet, fund the account from another account, leave out `--fund`, and pass
`--yes`.

Keep the account funded. It pays the fee of every admin call.

### Watch the account and the contracts

The signers rely on a watcher that alerts them on every operation of the admin account, and on
each of these events from every pool and tree the manifest names, and from every tree those pools
read:

| Event | Published by | When |
| --- | --- | --- |
| `DepositPauseChanged` | pools | Deposits pause or unpause |
| `DepositPauseRepeated` | pools | A pause lands on a pool that is already paused, which spends the pause file |
| `AspMembershipUpdated`, `AspNonMembershipUpdated` | pools | The pool switches to another allowlist or blocklist |
| `AdminTransferProposed`, `AdminTransferCancelled`, `AdminTransferAccepted` | pools and trees | An admin transfer starts, is withdrawn, or completes |
| `LeafAdded` | allowlists | A member joins |
| `LeafInserted`, `LeafDeleted` | blocklists | A key is listed or released |

The pool events and the admin transfer events carry their name in lowercase with underscores as
their topic, for example `deposit_pause_changed`. A pre-signed pause arrives in a transaction from
a holder's account, so only the pool's events show it: `deposit_pause_changed` when the pause
closes the pool, and `deposit_pause_repeated` when the pool was already paused. After a
`deposit_pause_repeated`, read the nonce from that transaction, as
[Pre-sign deposit pauses](#pre-sign-deposit-pauses) shows, to name the holder whose file was
spent, and sign a replacement file for them.

After a blocklist re-point, a pool reads a tree the manifest does not name. To list the trees a
pool reads, read its instance entry, whose key is `AAAAFA==`:

```bash
stellar ledger entry fetch contract-data --contract POOL --network testnet --key-xdr AAAAFA== \
  | jq -c '.entries[0].val.contract_data.val.contract_instance.storage[]
    | select(.key.vec[0].symbol == "ASPMembership" or .key.vec[0].symbol == "ASPNonMembership")
    | {(.key.vec[0].symbol): .val.address}'
```

Replace `POOL` with the pool's address. `ASPMembership` names the allowlist and `ASPNonMembership`
the blocklist. Whenever a pool publishes `asp_membership_updated` or `asp_non_membership_updated`,
add the tree in the event's `new_tree` field to the trees the watcher covers.

## Deploy under the admin account

Pass the admin account's address to `deploy.sh`. Every pool and tree takes it as its admin at
construction, and the deployer keeps no power over them:

```bash
deployments/scripts/deploy.sh testnet --deployer DEPLOYER --admin ADMIN_ACCOUNT \
  --asp-levels 10 --pool-levels 20 --max-deposit 1000000000 \
  --pool blocklist:native:$(stellar contract id asset --asset native --network testnet)
```

Replace `DEPLOYER` with the deployer's `stellar keys` identity and `ADMIN_ACCOUNT` with the admin
account's address.

`deploy.sh` admits native XLM and any classic asset whose issuer has `AUTH_IMMUTABLE` set and
neither `AUTH_REVOCABLE` nor `AUTH_CLAWBACK_ENABLED`, each named with its own Stellar asset
contract. It refuses every other token, `contract:` specs included, because the issuer or the
token's own code could freeze or take a pool's balance. For the spec syntax, see
[Deploying pools](./deploy.md).

After it writes the manifest, `deploy.sh` runs `deployments/scripts/verify-deployment.sh` against
it and exits with its status. The check reads the chain and prints one line per check:

- Every contract the manifest names has the manifest's `admin` and no pending admin transfer. An
  allowlist another party runs is checked against the `admin` its `added_asp_memberships` entry
  names.
- Every pool stores the Stellar asset contract of its asset in the manifest, and that asset
  passes the rule above. A `contract` asset fails.
- Every pool, a disabled one too, stores the manifest's tree code hashes and reads an allowlist
  the manifest names.
- Every tree a pool reads that the manifest does not name, such as a blocklist the pool was
  re-pointed to, has no pending admin transfer. A tree another party runs keeps its own admin, so
  the tree's admin prints as a notice, naming the pool that reads it, when it is not the
  manifest's `admin`.
- The admin account has the shape above. Off mainnet, a failure here prints as a notice, because
  local and test deployments use one key as the admin.

CI runs the same check on every pull request and every push to `main` that changes a manifest, so
merge a manifest only after every admin transfer it records has completed. The Stellar CLI has no
default mainnet RPC, so CI reads mainnet through the RPC URL in the `MAINNET_RPC_URL` repository
variable, and without it skips a mainnet manifest with a notice. To run the check by hand:

```bash
deployments/scripts/verify-deployment.sh testnet
```

## Make an admin call

Every admin call is a transaction whose source is the contract's admin, so the admin account's
signers sign the transaction itself. The admin page builds it, carries it from signer to signer,
and submits it:

1. Connect Freighter with any account on the network and build the call: list writes on the
   Allowlist and Blocklist tabs, pauses and re-points on the Pools tab, and admin transfers on the
   Admins tab. The page reads the contract's admin from its `Admin` entry, builds the call with
   that account as the source, valid for 24 hours, and loads it into the Admin transaction card.
2. Copy the XDR and send it to the first signer.
3. Each signer, on their own device, pastes the XDR into the card and reads the description:
   source, sequence, expiry, maximum fee, contract, function, and arguments. A signer who did not
   expect this exact call stops here. Otherwise the signer connects Freighter with their signer
   key, presses Sign with Freighter, and copies the XDR on to the next signer. The card counts the
   signatures against the account's threshold.
4. Once the count reaches the threshold, anyone presses Submit.

Make one admin call at a time. Each uses the admin account's next sequence number, so a call
built while another is in flight fails with `tx_bad_seq` once the other lands, and has to be built
again. A call submitted after its 24 hours fails with `tx_too_late`. When Submit reports that the
network has not confirmed the transaction yet, check the contract before building the call again.

A call that reads an archived entry, such as a contract's `Admin` entry that nothing has extended,
restores the entry itself, and the admin account pays for the restore inside the call's fee. On
testnet on 2026-10-03, an `insert_leaf` that restored five archived entries simulated to a fee of
66,214,618 stroops, about 6.6 XLM. The card shows the maximum fee before anyone signs.

### Sign with the CLI

The card describes only contract calls. A signer change, and the acceptance of a tree the
manifest does not name, go through the Stellar CLI instead, as a file passed from signer to
signer.

The CLI builds a transaction with no time bound. Signed and never sent, such a transaction stays
valid until another admin transaction uses its sequence number, and every signer holds a copy.
Before the first signature, whoever built `tx.xdr` bounds it to 24 hours, as the admin page does:

```bash
stellar tx decode --output json < tx.xdr \
  | jq -c --argjson t $(( $(date +%s) + 86400 )) \
    '.tx.tx.cond = {time: {min_time: 0, max_time: $t}}' \
  | stellar tx encode > tx-bounded.xdr
mv tx-bounded.xdr tx.xdr
```

Each signer, on their own device, reads the transaction and adds a signature:

```bash
stellar tx decode --output json-formatted < tx.xdr
stellar tx sign --sign-with-key SIGNER --network testnet < tx.xdr > tx-signed.xdr
```

The decoded `cond` field holds the bound, with `max_time` in Unix seconds. A signer who reads
`"cond": "none"` stops and asks for a bounded transaction. Replace `SIGNER` with the signer's
`stellar keys` identity, or sign from a hardware wallet with `--sign-with-ledger` in its place.
The next signer takes `tx-signed.xdr` as their `tx.xdr`. Once M signers have signed, anyone sends
it before the bound passes, after which it fails with `tx_too_late`:

```bash
stellar tx send --network testnet < tx.xdr
```

## Pre-sign deposit pauses

Gathering M signers takes longer than a soundness bug allows, so the signers sign pauses ahead of
time. A pause file holds the admin account's authorization of one `pause_deposits()` call on one
pool. Its holder sends it from their own account with no signer present. Sign one file per holder
per pool.

A file works once, because the network spends its nonce when the pause lands. Submitting a file
that was already used fails with `Error(Auth, ExistingValue)`. A file expires
3,110,399 ledgers after the ledger it was built at, about 180 days at five seconds a ledger.

To make a file, use the Pause authorizations panel on the Pools tab:

1. Choose the pool, name the holder, and press Build. The page draws a random nonce and offers the
   file as `pause-HOLDER-POOL.json`, with the holder's name and the pool's address in place of
   `HOLDER` and `POOL`.
2. Each signer loads the file and presses Sign with Freighter. Before Freighter opens, the panel
   shows the pool, the admin, the holder, the nonce, and the expiration ledger. A signer who did
   not expect exactly this file rejects the request in Freighter. Otherwise the signer checks
   that Freighter shows `pause_deposits` on that pool, approves, and passes the file that comes
   back to the next signer. Freighter signs the authorization, not a transaction.
3. Once the file carries M signatures, give it to its holder, and record the holder, pool, nonce,
   and expiration ledger the file states. When a pause lands, its nonce and that record name the
   holder whose file it was.

To pause, the holder connects Freighter with any funded account, chooses their files, one per
pool, and presses Submit. The page reads each pool's deposit flag first and holds back the file
for a pool that is already paused, which leaves that file's nonce unspent. It reports each pool on
its own line. The holder's account pays the fee, including the restore of any archived entry the
pause reads.

On testnet on 2026-10-03, a pause that restored nothing was charged 500,686 stroops, about 0.05
XLM. A restore costs far more: the call under [Make an admin call](#make-an-admin-call) that
restored five entries simulated to about 6.6 XLM. Keep at least 10 XLM above the account's minimum
balance for each pool file you hold, and check the balance each time the signers re-sign your
files.

A file that reaches a pool after another pause has closed it counts as used: the call succeeds,
leaves the flag as it is, publishes `deposit_pause_repeated`, and spends the nonce.

Neither `deposit_pause_changed` nor `deposit_pause_repeated` names the file, so read a landed
pause's nonce from its transaction's authorization entry:

```bash
stellar tx fetch --hash HASH --network testnet \
  | jq '[.. | objects | select(has("nonce")) | .nonce] | unique'
```

Replace `HASH` with the hash of the transaction that published the event.

The signers sign a replacement file in five cases:

- After each use, since the nonce is spent.
- After each signer change, since a file that carries a removed signer's signature fails as a
  whole.
- After an admin transfer, since a file authorizes the pool's previous admin.
- Before the expiration ledger.
- After the network lowers its `max_entry_ttl` setting, once the page builds files for the new
  value.

The host refuses an authorization that expires more than `max_entry_ttl - 1` ledgers after the
ledger that uses it, and the page sets each file's expiration as far out as the setting allowed
on 2026-10-03, when it read 3,110,400. If a network upgrade lowers the setting, every file fails at
Submit with `Error(Auth, InvalidInput)` until enough ledgers pass to bring its expiration within
the new bound. Files the page builds fail the same way until `MAX_ENTRY_TTL` in
`app/js/pause-authorization.js` holds the new value. Each time the signers re-sign files, read the
setting:

```bash
stellar network settings --network testnet \
  | jq '.. | objects | select(has("max_entry_ttl")) | .max_entry_ttl'
```

## Transfer the admin

A pool's or tree's admin changes in two steps, from the Admins tab. The tab lists every pool and
tree the manifest names, a disabled pool too, with its admin and its pending admin. Each button
builds an admin call into the card:

| Button | Call | Source | Effect |
| --- | --- | --- | --- |
| Propose | `update_admin(new_admin)` | the current admin | Records the address in the field as the pending admin, replacing any earlier proposal |
| Cancel | `cancel_admin_transfer()` | the current admin | Clears the pending admin |
| Accept | `accept_admin()` | the pending admin | Installs the pending admin and clears the entry |

The current admin keeps every power until the new admin accepts, and the new admin's own signers
sign the acceptance. Cancel and Accept fail with `NoPendingAdmin` when nothing is pending.

Replacing a signer needs no transfer. Transfer the admin only when the contracts move to another
account, such as another institution's. A transfer moves no view key: a `pool-gvk` pool's view key
is fixed at construction, and stays with whoever holds its private key.

Once the transfer completes, update `admin` in the manifest, and sign pause files for the new
admin.

## Re-point a pool

A pool reads one allowlist and one blocklist. `update_asp_membership` and
`update_asp_non_membership` switch it to another tree at once, which is called a re-point. The
pool refuses a tree whose code differs from the code fixed at its construction with
`TreeCodeMismatch` (#21), so a new tree comes from the same release as the pools.

A re-point has two uses: leaving a tree another party runs, and removing an allowlist member,
since an allowlist has no delete. To remove a member, ask them to withdraw first. Once the pool
reads an allowlist without their leaf, their notes in that pool can no longer move.

The re-point check reads the new tree's entries from its events, and clients replay a new
allowlist's history from its deployment ledger, so finish these steps while the tree is younger
than the RPC's event retention, about seven days on the public testnet RPC:

1. Read the latest ledger with `stellar ledger latest --network testnet` and keep it as the
   tree's deployment ledger. Then read the tree code the pool accepts, and deploy the tree from
   that code with the deployer as its admin, so the deployer can load it without the quorum:

   ```bash
   stellar contract invoke --id POOL --source-account DEPLOYER --network testnet --send=no \
     -- get_asp_wasm_hashes
   stellar contract deploy --wasm-hash HASH \
     --source-account DEPLOYER --network testnet -- --admin DEPLOYER_ADDRESS --levels LEVELS
   ```

   Replace the following:

   - `POOL`: the pool's address.
   - `HASH`: the first hash `get_asp_wasm_hashes` prints for an allowlist, or the second for a
     blocklist.
   - `DEPLOYER_ADDRESS`: the deployer's address.
   - `LEVELS`: the levels of the allowlist the pool reads, the value given to
     `deploy.sh --asp-levels`.

   The deploy builds nothing, so the tree runs the exact code the pool accepts. A blocklist takes
   only `--admin`, so its deploy drops `--levels LEVELS`.
2. Write the entries the tree should hold to a records file, one per line, and load them from
   the deployer's account.

   For an allowlist, the records file holds the leaves as `0x` hex values. Insert each one:

   ```bash
   stellar contract invoke --id TREE --source-account DEPLOYER --network testnet \
     -- insert_leaf --leaf LEAF
   ```

   Replace `TREE` with the new tree's address and `LEAF` with each line of the records file. A
   leaf is the hash the Allowlist tab derives from a member's note public key and the ASP
   secret. To remove a member, the leaves are those of the allowlist the pool reads, less the
   member's: take them from the ASP's own records, or from that allowlist's `LeafAdded` events.

   For a blocklist, the records file holds note public keys, as the Blocklist tab takes them.
   Load them through that tab, which stores each key with its 32 bytes reversed, the order the
   blocklist expects. Enter the new tree's address in the Overview tab's ASP Non-Membership
   Contract ID field, paste the keys on the Blocklist tab, and press Add to Blocklist. The page
   builds the insert with the deployer, the tree's admin, as its source. Copy the XDR from the
   Admin transaction card to `tx.xdr`, then sign it with `--sign-with-key DEPLOYER` and send it
   as "Sign with the CLI" describes. A note public key passed to the CLI's `insert_leaf` lands in
   the other byte order, and its owner stays unblocked.
3. Hand the tree to the admin account. The deployer proposes it:

   ```bash
   stellar contract invoke --id TREE --source-account DEPLOYER --network testnet \
     -- update_admin --new_admin ADMIN_ACCOUNT
   ```

   The admin page lists only the trees its manifest names, so build the acceptance with the CLI,
   then sign and send it as in [Sign with the CLI](#sign-with-the-cli):

   ```bash
   stellar contract invoke --id TREE --source-account ADMIN_ACCOUNT --network testnet \
     --build-only -- accept_admin \
   | stellar tx simulate --source-account ADMIN_ACCOUNT --network testnet > tx.xdr
   ```

4. For an allowlist, add `{ "contractId": "TREE", "deploymentLedger": LEDGER }` to the manifest's
   `added_asp_memberships`, with `LEDGER` the deployment ledger from step 1, and merge it.
   Clients refuse a pool whose allowlist the manifest does not name. Rebuild the bootnode with the
   new manifest and restart it once with `--rescan-from LEDGER`, as
   [Add an allowlist](./bootnode.md#add-an-allowlist) describes, and release a CLI build, which
   embeds the manifest.
5. On the Pools tab's Re-point panel, choose the pool and the kind of tree, enter the new tree's
   address, choose the records file, and press Check. A blocklist also takes its deployment
   ledger; an allowlist's comes from the manifest. Each check reports on its own line:
   - The tree runs the code the pool accepts.
   - An allowlist has the depth of the allowlist the pool reads.
   - The tree's admin is the pool's admin. A tree another party runs passes once you tick the box
     that names its admin.
   - The manifest names an allowlist.
   - The tree's entries, read from its events, match the records file.
6. Once every check passes, press Build re-point and make the admin call.

`deploy.sh` points every pool at the same allowlist and blocklist, so run the check and the
re-point for each pool that reads the old tree, one admin call per pool. A member removed from one
pool's allowlist still transacts in every pool that reads the old one.

A blocklist re-point skips step 4: clients build their blocklist proofs against whichever
blocklist the pool reads. An allowlist another party runs is deployed and loaded by that party,
and its `added_asp_memberships` entry also carries that party's address as `admin`, which the
deployment check reads.

Clients index at most 25 contracts: the enabled pools, `asp_membership`, each entry of
`added_asp_memberships`, and the public key registry. Over that, every client's sync fails, and
the deployment check fails the manifest. Once no pool reads an allowlist, drop its entry from
`added_asp_memberships`.

The Allowlist and Blocklist tabs write to the trees in the Overview tab's two contract ID fields,
which start as the manifest's trees. After a re-point, enter the new tree's address there before
writing to it.

The Re-point panel cannot check a tree older than the RPC's event retention, such as the
deployment's own allowlist a week after the deploy, so its Build re-point stays disabled. To
re-point a pool back to such a tree, compare the tree's entries with your records some other way
first, and for an allowlist, make sure the manifest still names it. Then build the call with the
CLI:

```bash
stellar contract invoke --id POOL --source-account ADMIN_ACCOUNT --network testnet \
  --build-only -- update_asp_membership --new_asp_membership TREE \
| stellar tx simulate --source-account ADMIN_ACCOUNT --network testnet > tx.xdr
```

Replace `POOL` with the pool's address and `TREE` with the tree's. For a blocklist, call
`update_asp_non_membership --new_asp_non_membership TREE` instead. Bound, sign, and send `tx.xdr`
as [Sign with the CLI](#sign-with-the-cli) describes.

## Replace a signer

Replace a signer with one transaction from the admin account that adds the new signer and sets
the old one's weight to 0, so the account never has fewer signers than its threshold. Build it:

```bash
stellar tx new set-options --source-account ADMIN_ACCOUNT --network testnet --build-only \
  --inclusion-fee 200 --signer NEW_SIGNER --signer-weight 1 \
| stellar tx operation add set-options --source-account ADMIN_ACCOUNT --network testnet \
  --build-only --signer OLD_SIGNER --signer-weight 0 > tx.xdr
```

Replace `NEW_SIGNER` and `OLD_SIGNER` with the two signers' addresses. Each operation costs the
100-stroop base fee, so `--inclusion-fee` is 200 for the two. The signers sign it and send it as
"Sign with the CLI" describes. Then they sign replacements for every pause file that carries the
old signer's signature, since those files now fail.

## Incidents

| Incident | Response |
| --- | --- |
| A signer's device is lost or stolen | While M other signers remain, replace the signer, then sign replacements for every pause file that carries its signature. One stolen key cannot sign alone, but replace it before another is lost. |
| A soundness bug in a circuit, the verifier, or a pool | A holder submits a pause file for every pool at once. Transfers and withdrawals cannot be stopped. Warn users and deploy fixed contracts, since none can be upgraded. |
| A key is sanctioned | List it, together with any other keys due, in each blocklist a pool reads. [Watch the account and the contracts](#watch-the-account-and-the-contracts) shows how to find them. Enter each blocklist's address in the Overview tab's ASP Non-Membership Contract ID field in turn, and add the keys on the Blocklist tab. Each blocklist write voids the proofs in flight in every pool that reads that blocklist. Until the calls land, the key's owner can move value to a fresh key. |
| A tree another party runs misbehaves | Pause the pools that read it. Prepare a replacement tree as [Re-point a pool](#re-point-a-pool) describes. For an allowlist, that includes step 4: publish the manifest entry, restart the bootnode with `--rescan-from`, and release a CLI build, all before the re-point. Then check the tree, re-point, and unpause. |
| Deposits pause unexpectedly | Read the nonce from the landed pause, as [Pre-sign deposit pauses](#pre-sign-deposit-pauses) shows, and find its holder in the record. No call revokes a signed file, so replace a signer whose signature that holder's files carry, which voids every file with that signature. Then unpause, and sign replacements for the voided files. |
