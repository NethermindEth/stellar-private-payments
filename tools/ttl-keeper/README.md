# ttl-keeper

Soroban archives persistent contract data that nobody touches. This service walks a
deployment's ledger entries on a schedule, extends the lifetime of anything close to expiry,
and restores what has already been archived.

Every transaction follows from what the RPC reports. `getLedgerEntries` returns an archived
entry with a `liveUntilLedgerSeq` of `0` and leaves out a key that was never written, so the
keeper restores exactly the keys reported archived, extends the live keys inside the
threshold, and never names a key the RPC did not return. It keeps no list of which keys a
contract writes only under some conditions; the pause state, the governor's queue index, and
the permission table rows are enumerated like every other key and come back when the RPC says
they are gone. An archived pause entry does not reopen a pool: a call whose footprint touches
it fails until the entry is restored, which the SDK does for the next user and the keeper
does on its next round.

The RPC has reported entry state this way since protocol 23. The keeper refuses to start
against an older one, because such an RPC omits archived entries the way it omits never
written ones and nothing would ever be restored.

## Run it

```bash
TTL_KEEPER_SECRET=S... cargo run -p ttl-keeper -- \
  --deployment deployments/testnet/deployments.json \
  --rpc-url https://soroban-testnet.stellar.org \
  --bootnode-url https://bootnode.example.com \
  --state-file keeper-state.json
```

That runs one round an hour. Pass `--once` to run a single round and exit, which is what a
cron job or a one-off check wants. Pass `--dry-run` to measure, log every key the round would
restore or extend, and exit without submitting anything, which is what a new manifest or a
new RPC endpoint wants first.

The defaults extend an entry once fewer than 518,400 ledgers remain, ask for one ledger below
the network's maximum entry lifetime, and put at most 100 keys in one transaction. The keeper
reads that maximum from the state archival settings each round, because the network rejects
an extension to the maximum itself and the simulation does not. `--threshold-ledgers`,
`--extend-to-ledgers`, and `--batch` change those; a target above the cap is lowered to it.
`--interval-secs` changes the gap between rounds.

## What it needs

A funded Stellar account, whose address the deployment manifest records as
`governance.ttlKeeper`. The account pays the resource fee for every extension and restore, so
it needs a balance that covers a round at the interval you choose. `--keeper-secret-env`
names the environment variable holding its secret key; the key is never read from a flag or a
file.

The keeper reads pool events through the bootnode first, because public RPC keeps events for
about a week and a pool's history is longer than that. It falls back to the RPC endpoint when
the bootnode refuses a range.

## The state file

Nullifier ledger entries cannot be derived from the manifest, so the keeper accumulates them
from the `new_nullifier_event` a pool publishes on every spend. `--state-file` holds those
nullifiers and the event cursor the next round resumes from:

```json
{
  "cursor": "0004669736471235-0000000000",
  "nullifiers": {
    "CBQH...": ["1f8a...", "77c2..."]
  }
}
```

The file is written through a temporary file and a rename, so a round that dies mid-write
leaves either the previous state or the new one. Delete it to re-read every pool's events
from its deployment ledger.

## Metrics

`--metrics-bind 127.0.0.1:9095` serves Prometheus metrics on that address. Without the flag
the keeper records nothing.

| Metric | Type | Meaning |
| --- | --- | --- |
| `ttl_keeper_min_ttl_ledgers{contract}` | gauge | Ledgers left on the shortest-lived entry of a contract |
| `ttl_keeper_keeper_balance_stroops` | gauge | Balance of the keeper account |
| `ttl_keeper_extended_total` | counter | Keys whose lifetime the keeper has extended |
| `ttl_keeper_restored_total` | counter | Keys the keeper has restored from the archive |
| `ttl_keeper_round_errors_total` | counter | Rounds that ended in an error |
| `ttl_keeper_classification_mismatch_total` | counter | Keys the RPC's simulation called archived after its ledger-state answer called them live |

The minimum-lifetime gauge reports an archived entry the round did not restore as zero, so
the expiry alert stays raised until a restore lands.

`alerts.yml` holds four Prometheus rules. One fires when a round ends in an error, which is
the first thing to know because every other rule reads a gauge a failed round never updated.
One fires on a classification mismatch: an entry expired between the read and the
simulation, which a keeper that was down past the threshold sees once, or the RPC no longer
reports entry state the way the keeper relies on, which repeats. The other two fire when a
contract sits inside the extension threshold for an hour and when the keeper account drops
below 100 XLM. Load them with:

```bash
promtool check rules tools/ttl-keeper/alerts.yml
```

## What it does not do

The keeper touches only the keys it can enumerate, which are the ones the manifest names plus
the ones a contract's own state reveals: the pool root ring, the association set trees, the
governor's queue, and the role table for the four roles in the governance block.

A permission table row added after deployment is not one of those. Until the manifest names
its target and function, that row stays alive only through use, and a row nobody calls for
long enough is archived. The same holds for any contract added to the deployment without
being written into the manifest.

The non-membership tree's nodes are named only inside their parents' stored values, so the
walk cannot descend past an archived node. A subtree archived several levels deep is restored
one level per round, which at the default interval is one hour per level.

The public key registry's per-user entries, one `Registration(address)` per user, are not kept
alive, and do not need to be. Senders resolve a recipient's keys from the registry's events,
which the indexer and the bootnode store, and the only contract code that reads the entry is
`register` itself, as the check that suppresses a duplicate event. A user who re-registers
after the entry has archived restores it through the SDK, which honors the simulation's
restore preamble, at the cost of one small transaction. A client syncing without the bootnode
sees only the registrations inside the RPC's retention window, which is a bootnode dependency
rather than a lifetime one.

A restore and an extend are independent phases. A restore that fails, for want of fee or
balance or an RPC that is down, is logged and counted, and the extend phase still runs; the
round reports the first error once both have finished.

The keeper never changes contract state. Its transactions carry one `ExtendFootprintTtl` or
`RestoreFootprint` operation and nothing else.
