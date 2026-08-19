# Bootnode

Bootnode is a narrow HTTPS JSON-RPC service that supports only:

- `getEvents`
- `getLatestLedger`

It ingests contract events from upstream Stellar RPC into Postgres (one row per
event), namespaced by deployment (min deployment ledger + sorted 4-char contract
prefixes) so redeployments can share one DB.

Clients paginate through the archive with bootnode-managed cursors (`event.id`).
All events with `ledger < tip − 5 days` are served; the next request that enters
the retention window returns JSON-RPC handoff (`-32002` with `fromLedger`) so the
app indexer resumes on the user's configured main RPC.

Schema changes are versioned SQL files in `src/storage/migrations/` (tracked in
`bootnode_schema_migrations`).

## Local development

```bash
cargo build --manifest-path tools/bootnode/Cargo.toml
export DATABASE_URL='postgres://postgres:postgres@127.0.0.1:5432/bootnode'
./tools/bootnode/target/debug/bootnode --dev --insecure-http --bind 127.0.0.1:8080 --upstream-rpc-url https://soroban-testnet.stellar.org --database-url "$DATABASE_URL"
```

### Docker

Use the `docker-compose.no-https.yml` override with the base compose file:

```bash
cd tools/bootnode
docker compose -f docker-compose.yml -f docker-compose.no-https.yml up --build
```

Bootnode URL for the app: `http://127.0.0.1:8080`

```bash
curl http://127.0.0.1:8080/healthz
```

The override binds `0.0.0.0:8080` inside the container (required for Docker port
publishing) and skips ACME/TLS. Use the base `docker-compose.yml` alone for
production HTTPS on `:443`.

## Production (HTTPS + ACME)

Set `--domain` / `--acme-email` / `--acme-cache-dir`, and bind to `:443`.
