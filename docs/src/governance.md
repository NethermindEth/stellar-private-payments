# Governance

Every privileged function of the pools and the association set providers (ASPs) belongs to one
contract, the governor. A change is queued as an operation, waits out a delay in public, and is
then executed by anyone. Four roles divide the authority, and no single key holds both the power
to freeze users in and the power to change the contracts.

The addresses, the contract id, and the four delays live in the `governance` block of
`deployments/<network>/deployments.json`. Every command below reads them from there.

## Roles

| Role | Held by | Entry points | What it may do |
| --- | --- | --- | --- |
| `council` | the 3-of-5 account | `schedule`, `cancel`, `unpause` | Queues any call against any contract: a new pool admin, a new ASP address, a role grant, a permission-table row, a pause with no deadline. Cancels any queued call, its own or the recovery key's. Clears any pause at once. |
| `operator` | the compliance key | `execute_now` | Adds a leaf to the allowlist, adds one to the blocklist, removes one from the blocklist. Reaches no other function on any contract. |
| `guardian` | the incident key | `pause` | Pauses any contract, any bits, at once. Every guardian pause carries a deadline. Cannot queue, cancel, or unpause anything. |
| `recovery` | the cold key | `schedule`, limited to `grant_role` and `revoke_role` on the governor | Queues a new council account and the removal of the old one when the old one's keys are lost. |

One address holds one role. The constructor refuses a configuration that grants two roles to
the same address, and `grant_role` refuses the same later.

## Delays

Delays are counts of ledgers. The wall-clock figures assume a five-second close.

| Number | Mainnet | Testnet |
| --- | --- | --- |
| `delay`, every operation the council schedules | 120,960 (7 days) | 360 (30 minutes) |
| `recovery_delay`, operations the recovery key schedules | 241,920 (14 days) | 720 (1 hour) |
| `grace`, how long a ready operation stays executable | 241,920 (14 days) | 17,280 (1 day) |
| `guardian_pause`, how long a guardian pause holds | 138,240 (8 days) | 720 (1 hour) |

A guardian pause, a council `unpause`, a council `cancel`, and an operator write through
`execute_now` all take effect in the transaction that carries them.

All four numbers are constructor arguments and the governor exposes no function that changes
one. A different delay means deploying a new governor and handing every target to it, which is
what `deployments/scripts/deploy.sh` does. Read the live values with `get_delays`:

```bash
NETWORK=testnet
MANIFEST=deployments/$NETWORK/deployments.json
GOVERNOR=$(jq -r .governance.governor "$MANIFEST")
COUNCIL=$(jq -r .governance.council "$MANIFEST")

stellar contract invoke --id "$GOVERNOR" --source-account "$COUNCIL" --network "$NETWORK" \
  --send=no -- get_delays
```

## The council's signer set

The council address is a Stellar account with five signers of weight 1, low, medium, and high
thresholds of 3, and a master weight of 0. Three of the five sign every operation the council
sends, and the account's own key can no longer sign anything on its own.

Create one with the five signer addresses in hand:

```bash
scripts/gov/create-multisig.sh testnet --account council --threshold 3 \
  --signer G... --signer G... --signer G... --signer G... --signer G...
```

The script puts the signers and the master weight of 0 in a single transaction, so the account
is never left without a working signer set, and prints the signer list it reads back from the
network.

Rotating a signer is one transaction that drops the outgoing weight to 0 and adds the incoming
signer at weight 1, signed by three of the current five. Both operations go in the same
transaction so the count never dips below the threshold:

```bash
stellar tx new set-options --source-account "$COUNCIL" --network "$NETWORK" --build-only \
  --inclusion-fee 200 --signer "$OUTGOING" --signer-weight 0 \
| stellar tx operation add set-options --source-account "$COUNCIL" --network "$NETWORK" \
  --build-only --signer "$INCOMING" --signer-weight 1 \
| stellar tx sign --sign-with-key alice --network "$NETWORK" \
| stellar tx sign --sign-with-key bob --network "$NETWORK" \
| stellar tx sign --sign-with-key carol --network "$NETWORK" \
| stellar tx send --network "$NETWORK"
```

Each operation costs the 100-stroop base fee, so `--inclusion-fee` is 100 times the number of
operations in the transaction.

One key lost leaves four, and three of them still meet the threshold. Rotate the lost signer out
at the next opportunity. Two keys lost leaves exactly three, so every operation now needs all
three holders present; rotate both out before anything else, because a third loss ends the
account. Three keys lost leaves the council unable to sign, and no rotation can bring it back.
That is what the recovery key is for: it schedules a `grant_role` of the council role to a fresh
account and a `revoke_role` of the dead one, both against the governor, and they become
executable after `recovery_delay`.

## Running an operation

An operation is the five-tuple `(target, function, args, predecessor, salt)`. `predecessor` is
the hash of an operation that must execute first, or 32 zero bytes for none, and `salt`
distinguishes two otherwise identical calls. `args` is a JSON array of XDR `ScVal` objects,
because the governor forwards `Vec<Val>` and the contract spec cannot describe the element type.

Build the call unsigned, collect three signatures, and send it:

```bash
ZERO=0000000000000000000000000000000000000000000000000000000000000000
POOL=$(jq -r '.pools[0].poolContractId' "$MANIFEST")
NEW_ASP=C...

stellar contract invoke --id "$GOVERNOR" --source-account "$COUNCIL" --network "$NETWORK" \
  --build-only \
  -- schedule --target "$POOL" --function update_asp_membership \
     --args "[{\"address\":\"$NEW_ASP\"}]" \
     --predecessor "$ZERO" --salt "$ZERO" --caller "$COUNCIL" \
| stellar tx sign --sign-with-key alice --network "$NETWORK" \
| stellar tx sign --sign-with-key bob --network "$NETWORK" \
| stellar tx sign --sign-with-key carol --network "$NETWORK" \
| stellar tx send --network "$NETWORK"
```

`get_pending` lists what is queued, with the ledger at which each operation becomes ready, and
`get_operation_state` answers for one hash. Both read without a transaction:

```bash
stellar contract invoke --id "$GOVERNOR" --source-account "$COUNCIL" --network "$NETWORK" \
  --send=no -- get_pending
```

Once the ready ledger has passed, anyone executes the operation from any funded account. The
call repeats the five-tuple and takes no caller:

```bash
stellar contract invoke --id "$GOVERNOR" --source-account "$ANY_ACCOUNT" --network "$NETWORK" \
  -- execute --target "$POOL" --function update_asp_membership \
     --args "[{\"address\":\"$NEW_ASP\"}]" --predecessor "$ZERO" --salt "$ZERO"
```

An operation nobody executes within `grace` of becoming ready returns `Expired` and has to be
scheduled again.

To withdraw a queued operation, the council sends `cancel` with the same five arguments plus its
own address as `caller`. The guardian cannot cancel anything, and neither can anyone else.

A change to the governor's own roles or permission table is an operation whose target is the
governor. The functions are `grant_role` and `revoke_role`, each taking a member address and a
role symbol, and `set_fn_role` and `clear_fn_role`, taking a target address, a function symbol,
and, for `set_fn_role`, the role to require:

```bash
stellar contract invoke --id "$GOVERNOR" --source-account "$COUNCIL" --network "$NETWORK" \
  --build-only \
  -- schedule --target "$GOVERNOR" --function grant_role \
     --args '[{"address":"G..."},{"symbol":"operator"}]' \
     --predecessor "$ZERO" --salt "$ZERO" --caller "$COUNCIL"
```

The council has no instant pause. Its pause with no deadline is a queued call to the target's own
`pause` with `until` absent, which lands after `delay` like every other operation:

```bash
stellar contract invoke --id "$GOVERNOR" --source-account "$COUNCIL" --network "$NETWORK" \
  --build-only \
  -- schedule --target "$POOL" --function pause --args '[{"u32":7},"void"]' \
     --predecessor "$ZERO" --salt "$ZERO" --caller "$COUNCIL"
```

The operator's writes need no queue. They go through `execute_now`, which checks the permission
table and forwards the call in the same transaction:

```bash
OPERATOR=$(jq -r .governance.operator "$MANIFEST")
ASP=$(jq -r .asp_membership "$MANIFEST")

stellar contract invoke --id "$GOVERNOR" --source-account operator-key --network "$NETWORK" \
  -- execute_now --target "$ASP" --function insert_leaf \
     --args '[{"u256":{"hi_hi":0,"hi_lo":0,"lo_hi":0,"lo_lo":7}}]' --caller "$OPERATOR"
```

## Stopping a deployment

The guardian pauses one contract per transaction. There is no call that fans out, because pools
and ASPs honor different flags and a single flag set would be refused by one of them. Walk the
manifest instead:

```bash
GUARDIAN=$(jq -r .governance.guardian "$MANIFEST")
pause() {
  stellar contract invoke --id "$GOVERNOR" --source-account guardian-key --network "$NETWORK" \
    -- pause --target "$1" --flags "$2" --caller "$GUARDIAN"
}

for pool in $(jq -r '.pools[] | select(.enabled) | .poolContractId' "$MANIFEST"); do
  pause "$pool" 7
done
pause "$(jq -r .asp_membership "$MANIFEST")" 1
pause "$(jq -r .asp_non_membership "$MANIFEST")" 1
```

A pool reads bit 1 as deposits, bit 2 as transfers, and bit 4 as withdrawals, so 7 is everything.
Both ASPs read bit 1 as mutations and refuse any other bit. A flag set of zero is refused
everywhere.

To pause a subset of the bits rather than all of them, read `get_pause_state` on every target
first. A lapsed pause leaves its bits set, and the new deadline covers all of them, so a leftover
bit widens the pause past the shapes the flag set names. After a guardian pause lapses, the
council clears the bits it set with a queued `unpause`, so the next incident pause covers only the
shapes that incident names.

## Incident playbooks

### An operator key is compromised

The guardian reads `get_pause_state` on each target, then pauses mutations on both ASPs and
deposits on both pools, which holds for `guardian_pause`. The council schedules a `revoke_role`
of the operator and a `grant_role` of a replacement on the same day, and both land after
`delay`. The new operator then deletes the bad
blocklist leaves. The allowlist tree is append-only, so a poisoned allowlist is answered by a
queued re-pointing of the pool to a fresh tree, not by deletion. The sanctions list is stale for
the days the replacement takes.

Replacing a compromised guardian is the same pair against the governor, a `grant_role` for the
new address and a `revoke_role` for the old one, and the guardian can cancel either no more than
it can cancel anything else. Execute the grant first, or name it as the revoke's `predecessor`,
so the deployment is never left without a guardian while the pair lands. Two addresses may hold
the role at once; one address may not hold two.

### A verifier or circuit bug

The guardian pauses every bit on both pools. The council schedules the target's own `pause` with
no deadline the same day, so the freeze survives the guardian's deadline, and schedules the ASP
mitigations and an exit plan alongside it. The freeze ends in a coordinated reopening at an
announced ledger, or in a migration to fresh contracts. It does not end in a patch: the pools
are not upgradeable.

### The council quorum is lost

The recovery key schedules a `grant_role` of the council role to a new account. After
`recovery_delay`, anyone executes it. The new council then schedules a `revoke_role` of the dead
account. A live council can cancel a recovery operation, which is why recovery only succeeds when
nobody is left to cancel.

### The council key is stolen

The thief's change is in `get_pending` for the whole delay, and withdrawals stay open for all of
it. Users withdraw, and the honest team deploys fresh contracts and migrates. The guardian pauses
deposits, which the thief undoes at once, and must not pause withdrawals. No on-chain path returns
governance to the honest signers.

## Pause bits and user funds

A pool honors deposits (1), transfers (2), and withdrawals (4); an ASP honors mutations (1). No
key can both freeze withdrawals and land a lasting change while they are frozen. The guardian's
pause is the only instant one, and it lapses at its deadline, `guardian_pause` after the ledger
that set it.

A lapse stops the bits being honored without clearing them. `get_pause_state` still reports every
bit an earlier pause set, and the next timed pause puts all of them under its new deadline. A
guardian pause of deposits alone therefore re-freezes withdrawals left set by an earlier one, for
the whole `guardian_pause` window. Once the council clears every bit on a contract, the guardian
cannot pause that contract again before that deadline, because the deadline survives the unpause.

The council's own long freeze is a queued call and therefore public for `delay` before it takes
effect, and during a suspected council compromise the guardian does not pause withdrawals,
because a freeze during the notice period is what would trap users. The guardian cancels
nothing.

## The guardian's two-key rule

The guardian pauses withdrawals only on evidence it verifies itself, never on a report alone, and
never while an operation sits in `get_pending`. Both halves answer the same attack: whoever holds
the council key can call the on-call responder, claim that forged proofs are flowing, and have
the guardian close the exit a few days before the takeover lands. Pausing deposits and transfers
on a report is fine once `get_pause_state` shows no withdrawals bit left from an earlier pause,
because a leftover bit turns that pause into a withdrawal freeze. Withdrawals need the responder
to have seen the bad state.

## Storage lifetimes

Soroban archives persistent entries nobody renews, and an archived entry fails every call whose
footprint touches it until it is restored. Three things keep that from happening.

Each contract bumps its own instance on every call, along with the entries that call reads or
writes; a pool also bumps its verifier's and both ASPs' instances. The `ttl-keeper` service
covers what no call touches: idle pools, untouched root ring slots, old nullifiers, the sparse
tree's long tail, and the governor's queue and role table. The SDK covers
the rest for a user standing in front of an archived entry, by honoring the simulation's restore
preamble and sending the restore before it retries the call.

Run the keeper against a manifest with a funded account whose address the manifest records as
`governance.ttlKeeper`:

```bash
TTL_KEEPER_SECRET=S... cargo run -p ttl-keeper -- \
  --deployment deployments/testnet/deployments.json \
  --rpc-url https://soroban-testnet.stellar.org \
  --bootnode-url https://bootnode.example.com \
  --state-file keeper-state.json
```

`tools/ttl-keeper/alerts.yml` carries four Prometheus rules: `KeeperRoundsFailing`,
`KeeperClassificationMismatch`, `ContractStorageNearExpiry`, and `KeeperBalanceLow`. For the
flags, the thresholds, and what the keeper does not cover, see
[the keeper's README](https://github.com/NethermindEth/stellar-private-payments/blob/main/tools/ttl-keeper/README.md).

The keeper has two limits. The non-membership tree names a node's children only inside that
node's own stored value, so the walk cannot descend past an archived node, and a subtree archived
several levels down recovers one level per round, which at the default hourly interval is one
hour per level. The public key registry's per-user entries are not kept alive and do not
need to be: senders resolve a recipient's keys from the registry's events, and a user who
re-registers after their entry has archived restores it through the SDK.

## The governance manifest block

`deploy.sh` writes this block when it is given the governance flags, and sets the manifest's
`admin` field to the governor id:

```json
{
  "governance": {
    "governor": "C...",
    "council": "G...",
    "operator": "G...",
    "guardian": "G...",
    "recovery": "G...",
    "ttlKeeper": "G...",
    "delay": 360,
    "recoveryDelay": 720,
    "grace": 17280,
    "guardianPause": 720
  }
}
```

A manifest with no `governance` block describes a deployment with no governor, which the SDK, the
admin page, and the keeper all handle. `deployments/scripts/verify-deployment.sh <network>` checks
a manifest that has one against the chain: that every enabled pool and both ASPs name the
governor as their admin, that each of the four holders holds its own role and that the council
does not hold the operator role, that `get_delays` matches the block, and that the three ASP
write rows map to the operator role while no target's `update_admin` does.
