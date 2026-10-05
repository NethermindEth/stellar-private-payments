# Deployment configuration and networks

The Rust SDK, NPM package, CLI, and bootnode are network-independent. Choose the
network by supplying a deployment configuration at runtime; native binaries do
not embed a deployment or circuit fingerprint file.

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
read artifacts from `circuit_keys/` (or `circuits/` for installed bundles).
`--circuits-dir` selects an alternative complete artifact directory. It must
contain matching `.r1cs`, `.graph.bin`, and `_proving_key.bin` files. For repository
development, assemble these files from `target/circuits-artifacts` and the
selected deployment's `circuit_keys` into that directory. All artifacts are
checked against the runtime `circuits.json`; changing directories never bypasses
fingerprint validation. Commands that do not prove need no circuit artifacts.

The CLI resolves RPC and passphrase through the named Stellar CLI network and
rejects a passphrase different from the deployment configuration.

## Bootnode

The bootnode requires `--deployment /path/to/deployments.json` or
`BOOTNODE_DEPLOYMENT`. It reads the default RPC from that file; an explicit RPC
override must still report the same network passphrase. It validates the upstream
before opening its database. It does not need proving artifacts.

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
The website supplies the staged circuit lock to the network-independent SDK at
runtime. This remains one deployment per hosted build, without a live switcher.
`ci-test-network` is synthetic test data, not a live deployment.

Deployment JSON requires `networkPassphrase` and `rpcUrl` for new deployments.
Optional presentation fields are `displayName`, `explorerUrl`, and `isTestnet`.
Old files still deserialize, but network validation rejects missing passphrases.
The website compares Freighter's passphrase with the configuration; wallet RPC
overrides remain supported.

`deploy.sh` resolves identity and RPC with `stellar network ls --long`. Override
presentation using `SPP_DISPLAY_NAME`, `SPP_EXPLORER_URL`, and
`SPP_IS_TESTNET=true|false`. Downstream operators provide contract deployments
and matching circuit artifacts. Mainnet deployments and ceremonies remain out
of scope.
