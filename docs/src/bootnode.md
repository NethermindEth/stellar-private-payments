# Bootnode (RPC retention bypass)

Stellar RPC nodes typically expose contract events only for a limited **retention window**. PoolStellar’s indexer needs to fetch historical `getEvents` back to the **contract deployment ledger** to rebuild local state. If a user joins later (or loses local data), onboarding can fail with an `RPC_SYNC_GAP` error.

The **bootnode** is a narrow, public service that:

- Implements only `getEvents` and `getLatestLedger` (JSON-RPC compatible request/response shape).
- Caches historical `getEvents` pages from the contract deployment ledger onward.
- Once a request is safely within the retention window buffer (currently **tip − 5 days**), returns a JSON-RPC **handoff** error (`-32005`) with `fromLedger` so the app indexer continues on the user's configured main RPC.

The app uses the bootnode **only for the indexer** (event ingestion). Wallet RPC usage for transaction submission / contract state reads is separate. The bootnode does not redirect HTTP clients; handoff is signaled in the JSON-RPC response.

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

