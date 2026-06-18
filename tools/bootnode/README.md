# Bootnode

Bootnode is a narrow HTTPS JSON-RPC service that supports only:

- `getEvents`
- `getLatestLedger`

It caches historical `getEvents` pages into Postgres (starting at the compiled-in deployment ledger). Once a request is safely within the retention window buffer (tip − 5 days by default), it returns a JSON-RPC handoff error (`-32002` with `fromLedger`) so the app indexer resumes on the user's configured main RPC.

## Local development (HTTP, loopback only)

```bash
cargo build --manifest-path tools/bootnode/Cargo.toml
export DATABASE_URL='postgres://postgres:postgres@127.0.0.1:5432/bootnode'
./tools/bootnode/target/debug/bootnode --dev --insecure-http --bind 127.0.0.1:8080 --upstream-rpc-url https://soroban-testnet.stellar.org --database-url "$DATABASE_URL"
```

## Production (HTTPS + ACME)

Set `--domain` / `--acme-email` / `--acme-cache-dir`, and bind to `:443`.

