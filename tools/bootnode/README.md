# Bootnode

Bootnode is a narrow HTTPS JSON-RPC service that supports only:

- `getEvents`
- `getLatestLedger`

It caches historical `getEvents` pages into Postgres, namespaced by deployment
(min deployment ledger + sorted 4-char contract prefixes) so redeployments can
share one DB.
Empty pages are stored so upstream cursor chains stay intact. Once at tip, a
daily compressor collapses recent empty spans near tip (within the handoff
window); historical pages below the cutoff stay intact for client catch-up.
Schema changes apply via versioned migrations in `schema_migrations`.
Indexing starts at the compiled-in deployment ledger. Once a request is safely
within the retention window buffer, it returns a JSON-RPC handoff error
(`-32002` with `fromLedger`) so the app indexer resumes on the user's
configured main RPC.

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

