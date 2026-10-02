# Network-specific builds

`SPP_NETWORK` selects `deployments/<network>/` at build time and defaults to `testnet`:

```sh
SPP_NETWORK=local trunk build
SPP_NETWORK=local cargo build -p stellar-private-payments-cli
SPP_NETWORK=local cargo build --manifest-path tools/bootnode/Cargo.toml
docker build --build-arg SPP_NETWORK=local -f tools/bootnode/Dockerfile .
```

Each folder needs `deployments.json`, `circuits.json` (the artifact hash lock), and `circuit_keys/`. `deploy-local.sh` prepares local development with testnet circuit artifacts. `ci-test-network` exists only for build tests. Mainnet keys and deployment are out of scope and require a ceremony.

Deployment JSON requires `networkPassphrase` and `rpcUrl` for new deployments. Optional presentation fields are `displayName`, `explorerUrl`, and `isTestnet`. Old files still deserialize, but network validation rejects missing/empty passphrases. The CLI retains Stellar CLI network-name resolution and rejects a different passphrase. Wallet RPC overrides remain supported. Bootnode checks `getNetwork` before opening its database.

`deploy.sh` resolves identity and RPC with `stellar network ls --long`. Override presentation with `SPP_DISPLAY_NAME`, `SPP_EXPLORER_URL`, and `SPP_IS_TESTNET=true|false` when deploying custom networks.

Bootnode storage IDs now start with `v2` and hash both the network passphrase and full sorted contract IDs. Existing v1 data is not migrated: the bootnode re-indexes. The existing `BOOTNODE_DELETE_OTHER_DEPLOYMENTS` setting controls whether old namespaces are deleted. Plan for a re-sync after upgrading testnet.
