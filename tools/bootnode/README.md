# Bootnode

Bootnode is a narrow HTTPS JSON-RPC service that supports only:

- `getEvents`
- `getLatestLedger`

It ingests contract events from upstream Stellar RPC into Postgres (one row per
event), namespaced by network passphrase, minimum deployment ledger, and full
contract IDs so deployments can share one DB.

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
./tools/bootnode/target/debug/bootnode --deployment deployments/testnet/deployments.json --dev --insecure-http --bind 127.0.0.1:8080 --upstream-rpc-url https://soroban-testnet.stellar.org --database-url "$DATABASE_URL"
```

Supply a deployment directory containing `deployments.json`, or the JSON file
itself, through `--deployment` or `BOOTNODE_DEPLOYMENT`, matching the CLI.
The default RPC comes from that file; an override must report the same network
passphrase. No deployment or circuit keys are embedded in the binary.

### Docker

Use the `docker-compose.no-https.yml` override with the base compose file:

```bash
cd tools/bootnode
docker compose -f docker-compose.yml -f docker-compose.no-https.yml up --build
```

Compose mounts the testnet deployment file by default. Set `SPP_DEPLOYMENT_FILE`
to an absolute path to use another deployment with the same image.

Bootnode URL for the app: `http://127.0.0.1:8080`

```bash
curl http://127.0.0.1:8080/healthz
```

The override binds `0.0.0.0:8080` inside the container (required for Docker port
publishing) and skips ACME/TLS. Use the base `docker-compose.yml` alone for
production HTTPS on `:443`.

## Production (HTTPS + ACME)

Set `--domain` / `--acme-email` / `--acme-cache-dir`, and bind to `:443`.

### systemd deployment configuration

The [service unit](systemd/stellar-bootnode.service) loads
`/etc/stellar-bootnode/bootnode.env`. Copy the
[environment template](systemd/bootnode.env.example) there and edit it for your
installation. Before starting the service, copy your deployment's
`deployments.json` to `/etc/stellar-bootnode/deployments.json`, readable by the
`bootnode` service user, or set `BOOTNODE_DEPLOYMENT` to another absolute path.
Keep the file outside home directories because the unit uses `ProtectHome=true`.

The deployment file supplies the default RPC URL. Set
`BOOTNODE_UPSTREAM_RPC_URL` only to override it with an RPC for the same network.

### Upstream unavailable during startup

Before opening the database or serving requests, the bootnode checks the upstream
network passphrase against its deployment. Failed requests retry automatically,
with a delay increasing from one second to a maximum of 30 seconds. Each request
has a 30-second timeout. Startup continues when the RPC recovers; a confirmed
passphrase mismatch stops startup immediately. Retry failures are logged, and
Ctrl-C cancels the wait. Cached history is not served during this initial check.
