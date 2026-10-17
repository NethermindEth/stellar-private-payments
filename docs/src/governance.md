# Governance runbook

One admin account administers every pool and tree a deployment runs: a Stellar account that needs
M of its N signers on every change. This runbook is for those signers and for whoever keeps the
account's pause files.

The admin can pause deposits, switch the trees a pool reads, edit the lists, and hand its role to
another account. It cannot move funds: only `transact` moves tokens, against a verifier fixed at
construction, and no contract has an upgrade entry point.

The commands below run on `testnet`. On another network, replace `testnet` with its name.

## Set up the admin account

The admin account has this shape:

- M is at least 2, and every signer is an ed25519 key of weight 1. An M-of-N account survives
  N - M lost signers and M - 1 stolen ones if each is replaced before the next goes. A 1-of-N
  account survives no stolen signer.
- The low, medium, and high thresholds all equal M, and the master weight is 0.
- The account is never merged. Anyone can recreate a merged account at the same address, with its
  master key as the only signer.

Each signer creates a key on their own device and sends its address. The key has to be in two
programs: Freighter signs admin calls and pause files on the admin page, and the Stellar CLI signs
what the page cannot describe (see [Sign with the CLI](#sign-with-the-cli)). Create the key as a
Freighter account, then add it to the CLI's credential store from Freighter's recovery phrase:

```bash
stellar keys add SIGNER --secure-store
```

Replace `SIGNER` with a name for the key. For a Freighter account other than the first, add
`--hd-path N`, where `N` counts Freighter's accounts from 0. Don't use `stellar keys generate`,
which by default writes the seed phrase to a plain-text file.

One person then creates the account and gives it its signers in one transaction:

```bash
stellar keys generate admin
scripts/gov/create-multisig.sh testnet --account admin --threshold 2 --fund \
  --signer SIGNER_1 --signer SIGNER_2 --signer SIGNER_3
```

Replace `SIGNER_1`, `SIGNER_2`, and `SIGNER_3` with the signers' addresses (`G...`). The script
refuses a threshold below 2, an account that already has signers, and the account's own address as
a signer, since it sets that key's weight to 0. During a fee surge, raise the most it pays per
operation with `--base-fee STROOPS` (default 100). On mainnet, fund the account from another
account, leave out `--fund`, and pass `--yes`. Keep the account funded: it pays the fee of every
admin call.

### Watch the account and the contracts

Run a watcher that alerts the signers on every operation of the admin account, and on these events
from every pool and tree the manifest names and every tree those pools read:

| Event | Published by | When |
| --- | --- | --- |
| `DepositPauseChanged` | pools | Deposits pause or unpause |
| `DepositPauseRepeated` | pools | A pause or unpause finds the flag already set; `paused` is the flag. A pause file sent this way is spent |
| `AspMembershipUpdated`, `AspNonMembershipUpdated` | pools | The pool switches to another allowlist or blocklist |
| `AdminTransferProposed`, `AdminTransferCancelled`, `AdminTransferAccepted` | pools and trees | An admin transfer starts, is withdrawn, or completes |
| `LeafAdded` | allowlists | A member joins |
| `LeafInserted`, `LeafDeleted` | blocklists | A key is listed or released |

The pool and admin transfer events use their name in lowercase with underscores as their topic,
for example `deposit_pause_changed`. A pause file can be sent from any account, so only the
pool's events show it. After a `deposit_pause_repeated` with `paused` true, read the nonce from its
transaction, as [Pre-sign deposit pauses](#pre-sign-deposit-pauses) shows, to find which file was
spent, and sign a replacement for whoever kept it.

After a blocklist re-point, a pool reads a tree the manifest does not name. To list the trees a
pool reads, read its instance entry, whose key is `AAAAFA==`:

```bash
stellar ledger entry fetch contract-data --contract POOL --network testnet --key-xdr AAAAFA== \
  | jq -c '.entries[0].val.contract_data.val.contract_instance.storage[]
    | select(.key.vec[0].symbol == "ASPMembership" or .key.vec[0].symbol == "ASPNonMembership")
    | {(.key.vec[0].symbol): .val.address}'
```

Replace `POOL` with the pool's address. `ASPMembership` names the allowlist and `ASPNonMembership`
the blocklist. When a pool publishes `asp_membership_updated` or `asp_non_membership_updated`, add
the event's `new_tree` to the trees the watcher covers.

## Deploy under the admin account

Pass the admin account's address to `deploy.sh`. Every pool and tree takes it as its admin at
construction, and the deployer keeps no power over them:

```bash
deployments/scripts/deploy.sh testnet --deployer DEPLOYER --admin ADMIN_ACCOUNT \
  --kdf-domain KDF_DOMAIN --asp-levels 10 --pool-levels 20 --max-deposit 1000000000 \
  --pool blocklist:native:$(stellar contract id asset --asset native --network testnet)
```

Replace the following:

- `DEPLOYER`: the deployer's `stellar keys` identity.
- `ADMIN_ACCOUNT`: the admin account's address.
- `KDF_DOMAIN`: the key derivation domain, which users see in the message they sign.

`deploy.sh` takes native XLM and classic assets, and refuses a token ID that is not the asset's own
Stellar asset contract. For a classic asset, it warns about each power the issuer's flags give it
over the pool's balance: `AUTH_REQUIRED` stops deposits until the issuer authorizes the pool,
`AUTH_REVOCABLE` lets it freeze the balance, `AUTH_CLAWBACK_ENABLED` lets it take the balance back,
and without `AUTH_IMMUTABLE` it can still set any of them. For the spec syntax, see
[Deploying pools](./deploy.md).

`deploy.sh` then runs `deployments/scripts/verify-deployment.sh` on the manifest it wrote and exits
with its status. The check compares each contract's admin, pending transfer, token, and tree code
with the manifest, and the admin account with the shape above. Off mainnet, a custody failure is
only a notice, because local and test deployments use one key. `verify-deployment.sh --help` lists
every check.

CI runs the check on every pull request and push to `main` that changes a manifest, so merge a
manifest only after every admin transfer it records has completed. CI reads mainnet through the
`MAINNET_RPC_URL` repository variable, since the Stellar CLI has no default mainnet RPC, and skips
a mainnet manifest with a notice when it is unset. To run the check by hand:

```bash
deployments/scripts/verify-deployment.sh testnet
```

## Make an admin call

Every admin call is a transaction whose source is the contract's admin, so the admin account's
signers sign the transaction itself. The admin page builds it and carries it between signers:

1. Connect Freighter with any account on the network and build the call: list writes on the
   Allowlist and Blocklist tabs, pauses and re-points on the Pools tab, and admin transfers on the
   Admins tab. The page reads the contract's admin from its `Admin` entry, builds the call with
   that account as the source, valid for 24 hours, and loads it into the Admin Transaction card.
2. Press Copy link and send the link to the first signer.
3. Each signer, on their own device, opens the link, connects Freighter, and reads the call the card
   describes. A signer who did not expect this exact call stops here. Otherwise the signer presses
   Sign beside their key in the card's signer list, then Copy link, and sends the new link on.
   Freighter switches to that key when it holds it. The card shows who has signed and counts the
   signatures against the account's threshold.
4. Once the count reaches the threshold, anyone presses Submit.

When the connected account can sign the call alone, as a single-key admin or one signer of a 1-of-N
account can, Freighter asks for its signature as soon as the call is built and the page submits it.
A rejected request leaves the call in the card for the steps above.

Make one admin call at a time: each uses the account's next sequence number, so a call built while
another is in flight can no longer land once the other does. A call also expires after its 24
hours. The card checks its call with the network when it loads the call, on Sign and Submit, and
when the call's time bound passes. Once the call went through, from any signer's copy, the card
says so. Once the call can no longer land, the card empties and says why. Then, or when Submit
reports that the network has not confirmed the transaction yet, check the contract before building
the call again.

A call that reads an archived entry, such as an `Admin` entry nothing has extended, restores it,
and the admin account pays for the restore within the call's fee. On testnet on 2026-10-03, an
`insert_leaf` that restored five entries simulated to a fee of 66,214,618 stroops, about 6.6 XLM.
The card shows the maximum fee before anyone signs.

An entry that archives while signers sign makes the call fail once sent, so the page refuses to
build a call that reads an entry with less than 25 hours left, the call's 24 hours plus an hour.
The card then lists a `stellar contract extend` command for each such entry. Run them from any
funded account, replacing `ACCOUNT`, then build the call again.

`accept_admin` and `update_admin` extend an admin entry from the ledger they land on, so every
call the page builds carries 100,000 stroops of refundable fee beyond its simulation. The network
refunds what the call does not owe.

### Sign with the CLI

The card describes only contract calls. A signer change, and the acceptance of a tree the manifest
does not name, go through the Stellar CLI as a file passed from signer to signer.

The CLI builds a transaction with no time bound, which, once signed, stays valid until another
admin transaction uses its sequence number. Before the first signature, whoever built `tx.xdr`
bounds it to 24 hours and, for a contract call, adds the same refundable fee as the admin page:

```bash
stellar tx decode --output json < tx.xdr \
  | jq -c --argjson t $(( $(date +%s) + 86400 )) \
    '.tx.tx.cond = {time: {min_time: 0, max_time: $t}}
    | if (.tx.tx.ext | type) == "object"
      then .tx.tx.fee += 100000 | .tx.tx.ext.v1.resource_fee |= (tonumber + 100000 | tostring)
      else . end' \
  | stellar tx encode > tx-bounded.xdr
mv tx-bounded.xdr tx.xdr
```

The CLI does not check how long the call's entries live. Before the first signature, fetch each
persistent entry in the footprint `stellar tx decode` shows with `stellar ledger entry fetch`, and
extend with `stellar contract extend` any whose `liveUntilLedgerSeq` is less than 18,000 ledgers
(25 hours) past `latestLedger`.

Each signer, on their own device, reads the transaction and adds a signature:

```bash
stellar tx decode --output json-formatted < tx.xdr
stellar tx sign --sign-with-key SIGNER --network testnet < tx.xdr > tx-signed.xdr
```

The decoded `cond` field holds the bound, with `max_time` in Unix seconds. A signer who reads
`"cond": "none"` stops and asks for a bounded transaction. Replace `SIGNER` with the signer's
`stellar keys` identity, or use `--sign-with-ledger` for a hardware wallet. The next signer takes
`tx-signed.xdr` as their `tx.xdr`. Once M signers have signed, anyone sends it before the bound
passes:

```bash
stellar tx send --network testnet < tx.xdr
```

## Pre-sign deposit pauses

Gathering M signers takes longer than a soundness bug allows, so the signers sign pauses ahead of
time. A pause file holds the admin account's authorization of one `pause_deposits()` call on one
pool, and whoever keeps it sends it from any funded account with no signer present. Sign one file
per pool for each person who keeps files.

A file works once, because the network spends its nonce when the pause lands, and a used file fails
with `Error(Auth, ExistingValue)`. The page reads the network's `max_entry_ttl`, and a file expires
`max_entry_ttl - 1` ledgers after the ledger it was built at: 3,110,399 ledgers, about 180 days, on
testnet and mainnet as of 2026-10-14.

To make a file, use the Pre-signed deposit pauses panel on the Pools tab:

1. Choose the pool and press New pause file. The page draws a random nonce and holds the file in
   the panel. When the connected account can sign alone, as a single-key admin can, Freighter asks
   for its signature at once.
2. Each signer reads the pool, admin, nonce, and expiration ledger on the file's card. A signer who
   did not expect exactly this file stops here. Otherwise the signer presses Sign beside their key,
   checks that Freighter shows `pause_deposits` on that pool, and approves. Freighter switches to
   that key when it holds it. A signer on another device gets the file from Save file and adds it
   with Open pause files. Opening a copy of a file the panel holds adds the copy's signatures until
   the file meets the threshold, so copies signed on different devices combine. The panel checks
   every signature the way the network does, and collects no more signatures than the threshold
   needs.
3. Once the card reads Ready, with the date the file works until, press Save file, give
   `pause-POOL-NONCE-signed-N.json` to whoever will pause deposits, and record who keeps it with
   its pool, nonce, and expiration ledger. A landed pause's nonce and that record name who kept
   the file.

To pause, whoever keeps the files connects Freighter with any funded account, adds the files with
Open pause files, one per pool, and presses Pause deposits now. The button stays disabled until a
file in the panel can pause a pool whose deposits are still open, and a card whose file cannot says
why. A signature from a key that no longer signs for the admin, such as a removed signer's, is left
out, so the file still pauses while the signatures left meet the threshold.

The page reads each pool again before sending, says why it leaves out any file, and sends the rest
after a confirmation that names the pools. It reports each pool on its own line, and a file that
paused its pool leaves the panel. The connected account pays the fee, including any restore the
pause needs.

On testnet on 2026-10-03, a pause that restored nothing cost 500,686 stroops, about 0.05 XLM, and
a restore can cost several XLM. Keep at least 10 XLM above the minimum balance for each pool file
you hold. That covers a deployment the operator keeps alive. A pause that restores a pool's archived
Wasm pays a full minimum lifetime of rent for it and can cost more.

A file that lands after another pause has closed the pool still counts as used: it publishes
`deposit_pause_repeated` and spends the nonce. Neither pause event names the file, so read a
landed pause's nonce from its transaction:

```bash
stellar tx fetch --hash HASH --network testnet \
  | jq '[.. | objects | select(has("nonce")) | .nonce] | unique'
```

Replace `HASH` with the hash of the transaction that published the event.

The signers sign a replacement file:

- After each use, since the nonce is spent.
- After a signer change that leaves a file's counted signatures short of the threshold.
- After an admin transfer, since a file authorizes the pool's previous admin.
- Before the expiration ledger.
- After the network lowers its `max_entry_ttl` setting.

If an upgrade lowers the setting, existing files cannot pause until their expiration falls within
the new bound, and their cards say from when. Read the setting after each network upgrade:

```bash
stellar network settings --network testnet \
  | jq '.. | objects | select(has("max_entry_ttl")) | .max_entry_ttl'
```

## Transfer the admin

A pool's or tree's admin changes in two steps, from the Admins tab. The tab lists every pool and
tree the manifest names, a disabled pool too, with its admin and its pending admin. Each button
builds an admin call as [Make an admin call](#make-an-admin-call) describes:

| Button | Call | Source | Effect |
| --- | --- | --- | --- |
| Propose | `update_admin(new_admin)` | the current admin | Records the address in the field as the pending admin, replacing any earlier proposal |
| Cancel | `cancel_admin_transfer()` | the current admin | Clears the pending admin |
| Accept | `accept_admin()` | the pending admin | Installs the pending admin and clears the entry |

The current admin keeps every power until the new admin's own signers sign the acceptance. Cancel
and Accept show only while a transfer is pending. Propose refuses a malformed address, an account
that does not exist, the current admin, and the pending admin, and asks for confirmation when the
new admin lacks the shape in [Set up the admin account](#set-up-the-admin-account).

Replacing a signer needs no transfer. Transfer the admin only when the contracts move to another
account, such as another organization's. A transfer moves no GVK: a `pool-gvk` pool's GVK is fixed
at construction and stays with whoever holds its private key.

Once the transfer completes, update `admin` in the manifest and sign pause files for the new admin.

## Re-point a pool

A pool reads one allowlist and one blocklist. `update_asp_membership` and
`update_asp_non_membership` switch it to another tree at once, which is called a re-point. The
pool refuses a tree whose code differs from the code fixed at its construction with
`TreeCodeMismatch` (#21), so a new tree comes from the same release as the pools.

A re-point has two uses: leaving a tree another party runs, and removing an allowlist member, since
an allowlist has no delete. To remove a member, ask them to withdraw first. Once the pool reads an
allowlist without their leaf, their notes in that pool can no longer move.

Clients replay an allowlist from its deployment ledger, and the re-point check compares its entries
with your file from its events, so for an allowlist finish these steps while the tree is younger
than the RPC's event retention, about seven days on the public testnet RPC:

1. For an allowlist, read the latest ledger with `stellar ledger latest --network testnet` and
   keep it as the tree's deployment ledger. Read the tree code the pool accepts and deploy the tree
   from that code, with the deployer as its admin so the deployer can load it without the signers:

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
   only `--admin`, so drop `--levels LEVELS` for one.
2. Write the entries the tree should hold to a records file, one per line, and load them from the
   deployer's account.

   For an allowlist, the records file holds the leaves as `0x` hex values. Insert each one:

   ```bash
   stellar contract invoke --id TREE --source-account DEPLOYER --network testnet \
     -- insert_leaf --leaf LEAF
   ```

   Replace `TREE` with the new tree's address and `LEAF` with each line of the records file. A
   leaf is the hash the Allowlist tab derives from a member's note public key and the ASP
   secret. To remove a member, load the current allowlist's leaves less the member's, from the
   ASP's records or that allowlist's `LeafAdded` events.

   For a blocklist, the records file holds note public keys as the Blocklist tab takes them. Load
   them through that tab, never the CLI's `insert_leaf`, which would store each key in the wrong
   byte order and leave its owner unblocked. Enter the new tree's address in the Overview tab's ASP
   Non-Membership Contract ID field, paste the keys on the Blocklist tab, and press Add to
   Blocklist. No pool uses the tree yet, so the page asks first; confirm. The page builds the insert
   with the deployer as its source. If Freighter is connected as the deployer, it signs and the page
   sends the insert at once. Otherwise open Transaction XDR in the Admin Transaction card, press
   Copy XDR, save it as `tx.xdr`, sign it with `--sign-with-key DEPLOYER`, and send it as [Sign with
   the CLI](#sign-with-the-cli) describes.
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
   `added_asp_memberships`, with `LEDGER` the deployment ledger from step 1, and merge it, since
   clients refuse a pool whose allowlist the manifest does not name. The deployment check on the
   pull request fails a new entry whose `LEDGER` the RPC no longer holds, since the bootnode could
   never index that allowlist. Point the bootnode at the new manifest and restart it while its
   upstream RPC still holds `LEDGER`, as [Add an allowlist](./bootnode.md#add-an-allowlist)
   describes. Redeploy the web app, which bundles the manifest when it is built, and give CLI
   users the new `deployments.json` for `--deployment` or their provisioned copy.
5. On the Pools tab's Switch allowlist or blocklist panel, choose the pool and the list, enter the
   new tree's address, add the records file under Compare with a file of expected entries, and
   press Check. Each line says what it found. Tick a line that asks for confirmation once you
   accept what it says; Build waits for every line. Without a file, the panel compares a blocklist
   key by key with the pool's current one, and an allowlist by its entry count only.
6. Once every check passes, press Build and make the admin call. The panel reads Built while the
   call waits for signers in the Admin Transaction card, and Done once the card sees it land.

`deploy.sh` points every pool at the same trees, so re-point each pool that reads the old tree,
one admin call per pool. The keep-alive loop in
[Keep a deployment alive](./deploy.md#keep-a-deployment-alive) reads each pool's trees, so it
covers the new tree from its next run. A removed member still transacts in every pool that reads
the old allowlist.

A blocklist re-point skips step 4, since clients prove against whichever blocklist the pool reads.
An allowlist another party runs is deployed and loaded by that party, and its
`added_asp_memberships` entry also carries that party's address as `admin` for the deployment
check.

Clients index at most 25 contracts: the enabled pools, `asp_membership`, each entry of
`added_asp_memberships`, and the public key registry. Past that, every client's sync fails, so
drop an allowlist's entry once no pool reads it.

The Allowlist and Blocklist tabs write to the trees in the Overview tab's contract ID fields,
which start as the manifest's. After a re-point, enter the new tree's address there before writing
to it. The page asks before a write to a list no pool on the Pools tab uses, and that tab marks a
list a pool's policy leaves out as not used.

Without a file of expected entries, the panel reads storage, which has no age limit: a blocklist's
keys, or an allowlist's entry count. That is the way back to an allowlist older than the RPC's event
retention, such as the deployment's own allowlist a week after the deploy: compare its entries with
your records some other way, make sure the manifest still names it, and check it with no file.

## Replace a signer

One transaction from the admin account adds the new signer and sets the old one's weight to 0, so
the account never has fewer signers than its threshold. Build it:

```bash
stellar tx new set-options --source-account ADMIN_ACCOUNT --network testnet --build-only \
  --inclusion-fee 200 --signer NEW_SIGNER --signer-weight 1 \
| stellar tx operation add set-options --source-account ADMIN_ACCOUNT --network testnet \
  --build-only --signer OLD_SIGNER --signer-weight 0 > tx.xdr
```

Replace `NEW_SIGNER` and `OLD_SIGNER` with the two signers' addresses. Each operation costs the
100-stroop base fee, so `--inclusion-fee` is 200 for the two. Sign and send it as
[Sign with the CLI](#sign-with-the-cli) describes, then sign replacements for every pause file
that carries the old signer's signature. Such a file leaves that signature out and pauses only while
its other signatures meet the threshold. The panel stops collecting signatures at the threshold, so
when every signer has the same weight, a file it built is then short.

## Incidents

| Incident | Response |
| --- | --- |
| A signer's device is lost or stolen | While M other signers remain, replace the signer, then sign replacements for every pause file that carries its signature. One stolen key cannot sign alone, but replace it before another is lost. |
| A soundness bug in a circuit, the verifier, or a pool | Whoever keeps the pause files submits one for every pool at once. Transfers and withdrawals cannot be stopped. Warn users and deploy fixed contracts, since none can be upgraded. |
| A key is sanctioned | List it, with any other keys due, in each blocklist a pool reads ([Watch the account and the contracts](#watch-the-account-and-the-contracts) shows how to find them): enter each blocklist's address in the Overview tab's ASP Non-Membership Contract ID field in turn, and add the keys on the Blocklist tab. Each write voids the proofs in flight in every pool that reads that blocklist. Until the calls land, the key's owner can move value to a fresh key. |
| A tree another party runs misbehaves | Pause the pools that read it. Prepare a replacement tree as [Re-point a pool](#re-point-a-pool) describes, including step 4 for an allowlist, before the re-point. Then check the tree, re-point, and unpause. |
| Deposits pause unexpectedly | Read the landed pause's nonce, as [Pre-sign deposit pauses](#pre-sign-deposit-pauses) shows, and find in the record who kept that file. No call revokes a signed file. Replace signers whose signatures that person's files carry until each file falls short of the threshold; when every signer has the same weight, one replacement voids a file the panel built. Then unpause and sign replacements for the voided files. |
