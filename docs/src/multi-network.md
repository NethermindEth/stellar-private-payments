# Deployment configuration and networks

The Rust SDK, NPM package, CLI, and bootnode are network-independent. Choose the
network by supplying a deployment configuration at runtime. The CLI and bootnode
binaries do not embed a deployment or circuit fingerprint file. The native SDK
examples still embed `sdk/native/circuits.json`, the testnet circuit lock, for
their example proving setup; they do not demonstrate runtime lock selection.

## CLI

Build once, then select a deployment directory or JSON file for each invocation:

```sh
cargo build --release -p stellar-private-payments-cli
./target/release/spp --deployment deployments/testnet config show
./target/release/spp --deployment /path/to/another-deployment config show
```

Save `deployment = "/path/to/deployment"` under `[defaults]` in
`~/.config/spp/config.toml` to avoid repeating the flag. `spp config init` creates
a template without requiring a deployment first. A deployment provisioned as
`<data_dir>/deployments.json` is also accepted. Missing configuration is an error;
there is no embedded testnet fallback.

The directory contains `deployments.json` and `circuits.json`. Proof operations
prefer an adjacent `circuits/` bundle. For a repository deployment under
`deployments/<network>/`, the default instead reads `target/circuits-artifacts/`
for R1CS output. Run `make circuits` to generate those files. Missing artifacts
fall back per file to the selected deployment's `circuit_keys/`, which supplies
the committed witness graphs and proving keys. No manual merging is required.
For other layouts without `circuits/`, the primary directory is `circuit_keys/`.

`--circuits-dir` overrides the primary directory and retains the same per-file
fallback. A complete bundle works on its own. Every artifact is checked against
the selected deployment's runtime `circuits.json`. An existing file with a wrong
fingerprint is rejected, never silently replaced by a fallback. Missing-file
errors list the searched paths and explain `make circuits` and `--circuits-dir`.
Commands that do not prove need no circuit artifacts.

The CLI resolves RPC and passphrase through the named Stellar CLI network and
rejects a passphrase different from the deployment configuration.

## Bootnode

The bootnode requires `--deployment` or `BOOTNODE_DEPLOYMENT`. Both accept a
directory containing `deployments.json` or a JSON file, just like the CLI.
It reads the default RPC from that file; an explicit RPC
override must still report the same network passphrase. It validates the upstream
before opening its database. If the RPC is unavailable, startup retries with
exponential backoff from one second up to 30 seconds between attempts. A confirmed
passphrase mismatch still stops startup immediately. The HTTP service starts only
after validation succeeds, so cached history is not served during this initial
wait. It does not need proving artifacts.

```sh
cargo build --release --manifest-path tools/bootnode/Cargo.toml
# Also supply the database and HTTP/TLS options described in tools/bootnode/README.md.
BOOTNODE_DEPLOYMENT=/path/to/deployments.json ./tools/bootnode/target/release/bootnode

docker build -f tools/bootnode/Dockerfile -t spp-bootnode .
# Mount a readable deployment file and supply the remaining service settings.
docker run --mount type=bind,src=/absolute/path/deployments.json,dst=/deployment.json,readonly \
  -e BOOTNODE_DEPLOYMENT=/deployment.json -e DATABASE_URL spp-bootnode
```

Bootnode storage IDs start with `v2` and hash the network passphrase and full
sorted contract IDs. Existing v1 data is not migrated: the bootnode re-indexes.
`BOOTNODE_DELETE_OTHER_DEPLOYMENTS` controls whether old namespaces are deleted.

## SDK consumers

The Rust SDK accepts a `ContractConfig` and a caller-supplied `CircuitLockfile`.
Parse your trusted `circuits.json` with `circuit_lock(&json)`, then pass that lock
to `CircuitStore::open(artifacts_dir, lock)`. Separate stores can use different
bundles in the same process. `ensure()` retains its optional download behavior;
local `artifacts()` reads and verifies files without downloading.

For the browser SDK, pass `contractConfig`, `circuitsBaseUrl`, and `circuitLock`
(the parsed `circuits.json` object) to `Client.new`. Walletless disclosure
verification takes the same bundle settings. A supplied, already-configured
prover can be reused without configuring it again. Each prover worker is bound
to one bundle; create another worker for another deployment. The NPM package's
bundled artifacts are conveniences, not a restriction on supported deployments.

The application/operator chooses the trusted configuration and fingerprints.
Hashes detect mismatched artifacts; they do not authenticate a manifest supplied
by an untrusted server. No configuration hosting service is required.

## Website packaging

`SPP_NETWORK` remains a website/package-artifact selection setting. It selects
`deployments/<network>/` and defaults to `testnet`:

```sh
SPP_NETWORK=local trunk build
```

Each folder needs `deployments.json`, `circuits.json`, and matching `circuit_keys/`.
Trunk embeds the selected circuit lock in the website JavaScript and supplies it
to the network-independent SDK at runtime. Opening a client does not fetch a
lock from the artifact server. Artifact hashes are pinned to that app build;
this still requires trusting the app itself and its delivery. This remains one
deployment per hosted build, without a live switcher.

CI builds the SDK and full testnet app once, then runs the shared deployment
staging and JS bundling script against a temporary `local` configuration using
the standalone network passphrase and testnet circuit artifacts. This checks deployment selection
without starting a network or deploying contracts; no synthetic deployment is
committed. Runtime integration tests continue to use the existing localnet setup.

Deployment JSON requires `networkPassphrase` and `rpcUrl` for new deployments.
Network labels and explorer defaults come from a shared mapping keyed by
passphrase, not deployment JSON. Unknown networks use their folder name as a
label and have no default explorer; users can configure an explorer separately.
Disclaimer acceptance is required on every network.
Old files still deserialize, but network validation rejects missing passphrases.
The website compares Freighter's passphrase with the configuration; wallet RPC
overrides remain supported.

`deploy.sh` resolves identity and RPC with `stellar network ls --long`. Downstream
operators provide contract deployments and matching circuit artifacts. Mainnet deployments and ceremonies remain out
of scope.
