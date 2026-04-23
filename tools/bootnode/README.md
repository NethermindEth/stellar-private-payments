# Bootnode

Bootnode is a narrow HTTPS JSON-RPC service that supports only:

- `getEvents`
- `getLatestLedger`

It caches historical `getEvents` pages into Postgres (starting at the compiled-in deployment ledger) and issues **HTTP 307 redirects** to a configured upstream RPC once requests are safely within the retention window buffer (tip − 5 days by default).

## Local development (HTTP, loopback only)

```bash
export DATABASE_URL='postgres://postgres:postgres@127.0.0.1:5432/bootnode'
bootnode --dev --insecure-http --bind 127.0.0.1:8080 --upstream-rpc-url https://soroban-testnet.stellar.org --database-url "$DATABASE_URL"
```

## Production (HTTPS + ACME)

Set `--domain` / `--acme-email` / `--acme-cache-dir`, and bind to `:443`.

