# Bootnode (RPC retention bypass)

Stellar RPC nodes typically expose contract events only for a limited **retention window**. PoolStellar’s indexer needs to fetch historical `getEvents` back to the **contract deployment ledger** to rebuild local state. If a user joins later (or loses local data), onboarding can fail with an `RPC_SYNC_GAP` error.

The **bootnode** is a narrow, public service that:

- Implements only `getEvents` and `getLatestLedger` (JSON-RPC compatible request/response shape).
- Caches historical contract events from the deployment ledger onward in Postgres.
- Serves paginated `getEvents` for all events with `ledger < tip − 5 days`.
- Once a request enters the retention window (`startLedger` or cursor at/after the cutoff), returns a JSON-RPC **handoff** error (`-32002`) with `fromLedger` so the app indexer continues on the user's configured main RPC.

The app uses the bootnode **only for the indexer** (event ingestion). Wallet RPC usage for transaction submission / contract state reads is separate. The bootnode does not redirect HTTP clients; handoff is signaled in the JSON-RPC response.

## Bootnode-specific JSON-RPC errors

`getEvents` may return two application-defined error codes (in addition to standard JSON-RPC errors such as `-32602` invalid params):

| Code | Meaning | Client action |
|------|---------|---------------|
| `-32004` | **Warming up** — ledger tip unknown or pre-cutoff archive not ready. | Retry with backoff (`bootnode warming up; retry later`). |
| `-32002` | **Retention handoff** — the requested range is within the retention window. | Stop using the bootnode and continue `getEvents` on the wallet's main RPC from `error.data.fromLedger`. |

Handoff response shape:

```json
{
  "code": -32002,
  "message": "Continue syncing on your RPC endpoint",
  "data": {
    "reason": "retention_threshold",
    "fromLedger": 2913600
  }
}
```

The web platform orchestrator treats `-32002` as an archive handoff and resumes on the wallet RPC at `fromLedger`.

## Add an allowlist

The bootnode keeps its archive under a namespace built from the earliest pool deployment ledger and the IDs of the manifest's enabled pools, `asp_membership`, and `public_key_registry`. The namespace leaves out the allowlists in `added_asp_memberships`, so adding one to the manifest keeps the archive. A bootnode rebuilt with that manifest ingests and serves the allowlist's events, but its indexer resumes from the stored cursor, so the archive lacks the allowlist's events from before that cursor.

To fill in those events:

1. Rebuild the bootnode with the manifest that names the allowlist.
2. Start it with `--rescan-from`, or the `BOOTNODE_RESCAN_FROM` environment variable, set to the allowlist's deployment ledger. Indexing replays from that ledger instead of the stored cursor until one round succeeds, and later rounds continue from the cursor that round stored. Events already in the archive are skipped, so the replay costs only time. The ledger must not be later than the last ledger the bootnode ingested before it stopped: the rescan drops the stored cursor, so the archive never receives the events between that cursor and the rescan ledger. A bootnode that was in sync with its upstream when it stopped meets this condition.
3. Remove the option before the next restart. Left set, every restart replays from that ledger again.

Run the rescan while the upstream RPC still holds the allowlist's deployment ledger. Once that ledger falls outside the upstream's retention window, the rescan's requests fail and the indexer stops advancing until you restart without the option.

## Trust assumptions

Using a bootnode adds additional trust and privacy considerations:

- **Integrity risk:** the bootnode can serve incorrect history, omit events, or selectively censor data.
- **Availability risk:** the bootnode can be down or rate limit users.
- **Privacy risk:** the bootnode operator can observe client IP addresses and request timing/volume.
- **Handoff integrity risk:** a malicious bootnode could return an incorrect `fromLedger`, causing the indexer to skip or replay the wrong ledger range on the main RPC.

## Attack vectors

Non-exhaustive list of things a malicious or compromised bootnode could do:

- Serve a forged event history that causes an incorrect local reconstruction.
- Return stale data to delay catch-up.
- Censor specific contract IDs/events (selective omission).
- Use timing/IP correlation to fingerprint user activity.
- Signal a misleading `fromLedger` at handoff to steer catch-up onto the wrong ledger range.

## Mitigations / best practices

- The bootnode restricts the JSON-RPC surface area (only `getEvents`, `getLatestLedger`) and rejects all other methods.
- The service is intended to be **HTTPS-only** in production and includes basic security headers and IP rate limiting.
- Users who need stronger trust guarantees should self-host a bootnode and/or cross-check history using multiple RPC providers.

