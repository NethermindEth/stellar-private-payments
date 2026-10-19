# Run it locally

This page brings up a full deployment on your machine: a local Stellar network, one native XLM
pool with the blocklist policy, the web app, and the CLI.

## Install the prerequisites

You need the following tools:

- Docker, which runs the local network.
- Rust through `rustup`. The repository's `rust-toolchain.toml` file pins the version.
- The [Stellar CLI](https://developers.stellar.org/docs/tools/cli/install-cli).
- `jq`.
- Node.js and npm, for the web app.

`make serve` installs Trunk and the WebAssembly target on first use. For the full list of build
tools, see [Contributing](../contributing.md).

## Start the network and deploy

Run these four commands from the repository root:

```bash
bash deployments/scripts/localnet.sh start
bash deployments/scripts/deploy-local.sh
make circuits
SPP_NETWORK=local make serve PORT=8080
```

They do the following:

1. `localnet.sh start` runs the `stellar/quickstart` container with its RPC at
   `http://localhost:8000/rpc`.
2. `deploy-local.sh` creates and funds a deployer, deploys the contracts with that deployer as the
   admin, and writes the manifest to `deployments/local/deployments.json`. It links the testnet
   circuit keys into `deployments/local/` and keeps the deployer's key in
   `deployments/local/.config`, away from your own Stellar CLI keys.
3. `make circuits` compiles the circuits into `target/circuits-artifacts/`. The app and the CLI
   prove with them. The first build takes several minutes.
4. `make serve` builds the web app for the `local` manifest and serves it at
   `http://localhost:8080/`. Port 8080 avoids the network's port 8000.

## Use the web app

The app signs with Freighter. In Freighter, add a custom network with these settings and allow
HTTP connections:

| Setting | Value |
| --- | --- |
| Horizon RPC URL | `http://localhost:8000` |
| Soroban RPC URL | `http://localhost:8000/rpc` |
| Passphrase | `Standalone Network ; February 2017` |
| Friendbot URL | `http://localhost:8000/friendbot` |

Fund the account you connect with from Freighter's friendbot button, then open
`http://localhost:8080/` to deposit, transfer, and withdraw.

The admin page is at `http://localhost:8080/admin.html`. Its writes need the admin, which is the
local deployer. To sign as the deployer, import its secret key into Freighter:

```bash
XDG_CONFIG_HOME=deployments/local/.config stellar keys secret spp-e2e-local-deployer
```

## Use the CLI

Build the CLI, then create and fund two users:

```bash
cargo build --release -p stellar-private-payments-cli
stellar keys generate alice --network local --fund
stellar keys generate bob --network local --fund
```

Onboard each user. Onboarding accepts the disclaimer, derives the user's keys, and registers them
in the public key registry so others can pay their address. Each user gets their own data
directory, and a local network has no explorer or bootnode:

```bash
spp() { ./target/release/spp --deployment deployments/local "$@"; }
spp --data-dir alice-data onboard --account alice --accept --register \
  --no-bootnode --explorer-url ''
spp --data-dir bob-data onboard --account bob --accept --register \
  --no-bootnode --explorer-url ''
```

Then move value through the pool:

```bash
POOL=$(jq -r '.pools[0].poolContractId' deployments/local/deployments.json)
spp --data-dir alice-data deposit "$POOL" 10 --account alice
spp --data-dir alice-data transfer "$POOL" 4 --to "$(stellar keys address bob)" --account alice
spp --data-dir bob-data withdraw "$POOL" 4 --account bob
spp --data-dir alice-data notes "$POOL" --account alice
```

Amounts are in token units, so `10` is 10 XLM. Alice ends with one spent 10 XLM note and one
unspent 6 XLM change note. `spp --help` lists the other commands.

## Stop the network

```bash
bash deployments/scripts/localnet.sh stop
```

Stopping the container discards the chain. After a restart, run `deploy-local.sh` again, and
delete the CLI data directories and the app's site data in the browser, since both hold the old
chain's state.
