//! Shared bootstrap helpers for the `sdk/native` examples.
//!
//! Centralizes env-var handling, deployment/artifact loading, client
//! construction, and signer setup so each example can focus on the API it
//! demonstrates.
//!
//! # Env-var contract
//!
//! | Variable | Default | Required by |
//! | --- | --- | --- |
//! | `SPP_RPC_URL` | `https://soroban-testnet.stellar.org` | all examples |
//! | `SPP_NETWORK_PASSPHRASE` | derived from `network` in deployments.json | account/pool/transact examples |
//! | `SPP_BOOTNODE_URL` | `https://bootnode.dev-nethermind.xyz` | all examples |
//! | `SPP_WALLET_PATH` | `./spp-example-wallet.sqlite` | all examples |
//! | `SPP_DEPLOYMENT_JSON` | `<CARGO_MANIFEST_DIR>/../../deployments/testnet/deployments.json` | all examples |
//! | `SPP_POOL_CONTRACT_ID` | first enabled pool from deployment config | account/pool/transact examples |
//! | `SPP_AMOUNT_STROOPS` | `10000000` (1 XLM) | estimate/transact examples |
//! | `STELLAR_SECRET_KEY` | — | account/pool/transact examples |
//!
//! Four prerequisite classes print a skip message and exit with code 0: a
//! missing `STELLAR_SECRET_KEY` ([`require_env`]), a wallet without privacy
//! keys ([`require_onboarded`]), an underfunded account
//! ([`require_funded_for_pool`]), and an RPC retention gap
//! ([`skip_on_retention_gap`]). Other misconfiguration returns `Err` and
//! surfaces as a hard failure — an unreadable `SPP_DEPLOYMENT_JSON`, an
//! unopenable `SPP_WALLET_PATH`, or a `SPP_POOL_CONTRACT_ID` that is not in the
//! deployment config. Missing circuit artifacts also return `Err`, which the
//! transact examples convert into a skip by matching the message.

#![allow(dead_code)] // shared module: each helper is used by some example

use std::path::PathBuf;

use stellar_private_payments::{
    CircuitStore, Handle, LocalProver, LocalSigner, LocalStorage, Prover, Signer,
    blocking::{Account, Client, PrivatePool},
    chain::LocalSigner as StellarSigner,
    types::{AssetDescriptor, ContractConfig, NoteAmount, PoolConfigEntry, ProverArtifacts},
};

/// Initialize a `tracing_subscriber` formatter driven by `RUST_LOG`.
///
/// Defaults to `info` level when `RUST_LOG` is unset.
pub fn init_tracing() -> Result<(), String> {
    let filter = match tracing_subscriber::EnvFilter::try_from_default_env() {
        Ok(filter) => filter,
        Err(_) => tracing_subscriber::EnvFilter::new("info"),
    };
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .try_init()
        .map_err(|e| format!("failed to initialize tracing subscriber: {e}"))?;
    Ok(())
}

/// Return `var(name)` if set and non-empty, otherwise `default`.
pub fn env_or(name: &str, default: impl Into<String>) -> String {
    match std::env::var(name) {
        Ok(value) if !value.is_empty() => value,
        Ok(_) | Err(_) => default.into(),
    }
}

/// Require an environment variable; if missing, print instructions and exit 0.
pub fn require_env(name: &str, purpose: &str) -> String {
    match std::env::var(name) {
        Ok(value) if !value.is_empty() => value,
        Ok(_) | Err(_) => {
            eprintln!("Skipping: {name} is required {purpose}.");
            eprintln!("Set {name} and re-run this example.");
            std::process::exit(0);
        }
    }
}

/// Return the Stellar network passphrase to use.
///
/// Honors `SPP_NETWORK_PASSPHRASE` if set, otherwise maps the deployment
/// `network` value from `deployments.json`.
pub fn network_passphrase(network: &str) -> Option<String> {
    if let Ok(value) = std::env::var("SPP_NETWORK_PASSPHRASE")
        && !value.is_empty()
    {
        return Some(value);
    }
    match network {
        "testnet" => Some("Test SDF Network ; September 2015".to_string()),
        "public" => Some("Public Global Stellar Network ; September 2015".to_string()),
        "futurenet" => Some("Test SDF Future Network ; December 2023".to_string()),
        _ => None,
    }
}

/// Bootnode archive URL for historical event catch-up.
///
/// Defaults to the project bootnode used by the web app. Set
/// `SPP_BOOTNODE_URL` to override, or to an empty string to disable it.
///
/// Reads the variable directly rather than through [`env_or`], which treats an
/// empty value as unset and would make the disable case unreachable.
pub fn bootnode_url() -> Option<String> {
    match std::env::var("SPP_BOOTNODE_URL") {
        // Explicitly set to empty: disable the bootnode fallback.
        Ok(value) if value.is_empty() => None,
        Ok(value) => Some(value),
        Err(_) => Some("https://bootnode.dev-nethermind.xyz".to_string()),
    }
}

/// Default path to the SQLite wallet file.
pub fn default_wallet_path() -> String {
    "./spp-example-wallet.sqlite".to_string()
}

/// Directory containing `Cargo.toml` for the `sdk/native` crate.
fn manifest_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

/// Default `deployments.json` path (testnet deployment).
pub fn default_deployment_path() -> PathBuf {
    manifest_dir().join("../../deployments/testnet/deployments.json")
}

/// Load the deployment config from `SPP_DEPLOYMENT_JSON` or the default testnet
/// file.
pub fn load_contract_config() -> Result<ContractConfig, String> {
    let path = env_or(
        "SPP_DEPLOYMENT_JSON",
        default_deployment_path().to_string_lossy().into_owned(),
    );
    let contents = std::fs::read_to_string(&path)
        .map_err(|e| format!("read deployment config from {path}: {e}"))?;
    serde_json::from_str(&contents).map_err(|e| format!("parse deployment config from {path}: {e}"))
}

/// Open the SQLite wallet from `SPP_WALLET_PATH` or the default file.
pub fn open_storage() -> Result<LocalStorage, String> {
    let path = env_or("SPP_WALLET_PATH", default_wallet_path());
    LocalStorage::open(&path).map_err(|e| format!("open wallet at {path}: {e}"))
}

/// Select the pool to use: `SPP_POOL_CONTRACT_ID`, or the first enabled pool.
pub fn select_pool(config: &ContractConfig) -> Result<&PoolConfigEntry, String> {
    let id = env_or("SPP_POOL_CONTRACT_ID", "");
    if id.is_empty() {
        config
            .enabled_pools()
            .next()
            .ok_or_else(|| "no enabled pools in deployment config".to_string())
    } else {
        config.pool(&id).map_err(|e| e.to_string())
    }
}

/// Read proving key, graph, and r1cs for `pool`'s policy flags.
///
/// Uses in-repo `target/circuits-artifacts` (same dir as `make circuits`).
/// Downloads the hashed GitHub release there when needed.
pub fn read_artifacts_for_pool(pool: &PoolConfigEntry) -> Result<ProverArtifacts, String> {
    let stem = pool.policy_flags.circuit_stem();
    let store = CircuitStore::open(manifest_dir().join("../../target/circuits-artifacts"));
    store
        .ensure_blocking()
        .map_err(|e| format!("circuit artifacts: {e}"))?;
    store
        .artifacts(&stem)
        .map_err(|e| format!("circuit artifacts: {e}"))
}

/// Build a read-only client (sync, balance, notes, portfolio, estimates).
pub fn build_readonly_client(
    storage: LocalStorage,
    config: ContractConfig,
) -> Result<Client, String> {
    let rpc_url = env_or("SPP_RPC_URL", "https://soroban-testnet.stellar.org");
    Client::init_readonly(&rpc_url, storage, config, bootnode_url())
        .map_err(|e| format!("init readonly client: {e}"))
}

/// Build a full client with a [`LocalProver`] configured for `pool`.
pub fn build_client_for_pool(
    storage: LocalStorage,
    config: ContractConfig,
    pool: &PoolConfigEntry,
) -> Result<Client, String> {
    let rpc_url = env_or("SPP_RPC_URL", "https://soroban-testnet.stellar.org");
    let artifacts = read_artifacts_for_pool(pool)?;
    let prover = Handle::from_box(Box::new(
        LocalProver::from_artifacts(&[(pool.policy_flags, artifacts)])
            .map_err(|e| format!("init local prover: {e}"))?,
    ) as Box<dyn Prover>);
    Client::init(&rpc_url, storage, prover, config, bootnode_url())
        .map_err(|e| format!("init client: {e}"))
}

/// Derive the Stellar address that corresponds to `STELLAR_SECRET_KEY`.
pub fn user_address_from_secret(secret_key: &str) -> Result<String, String> {
    Ok(StellarSigner::from_secret(secret_key)
        .map_err(|e| format!("invalid STELLAR_SECRET_KEY: {e}"))?
        .public_key()
        .to_string())
}

/// Build a signer handle from a raw secret key, network passphrase, and user
/// address.
pub fn build_signer(
    secret_key: &str,
    network_passphrase: &str,
    user_address: &str,
) -> Result<Handle<dyn Signer>, String> {
    let signer = LocalSigner::new(secret_key, network_passphrase, user_address)
        .map_err(|e| format!("build signer: {e}"))?;
    Ok(Handle::from_box(Box::new(signer) as Box<dyn Signer>))
}

/// Build an account session from `STELLAR_SECRET_KEY`.
///
/// Exits 0 if the secret key is missing.
pub fn build_account(client: &Client) -> Result<Account, String> {
    let secret = require_env("STELLAR_SECRET_KEY", "to sign transactions");
    let user_address = user_address_from_secret(&secret)?;
    let network = client.contract_config().network.as_str();
    let passphrase = network_passphrase(network).ok_or_else(|| {
        format!("unknown network '{network}'; set SPP_NETWORK_PASSPHRASE explicitly")
    })?;
    let signer = build_signer(&secret, &passphrase, &user_address)?;
    client
        .account(&user_address, signer)
        .map_err(|e| format!("open account session: {e}"))
}

/// Open the pool selected by `SPP_POOL_CONTRACT_ID` for `account`.
pub fn open_account_pool<'a>(
    account: &'a Account,
    config: &'a ContractConfig,
) -> Result<(PrivatePool, &'a PoolConfigEntry), String> {
    let pool = select_pool(config)?;
    let pool_session = account
        .pool(&pool.pool_contract_id)
        .map_err(|e| format!("open pool {}: {e}", pool.pool_contract_id))?;
    Ok((pool_session, pool))
}

/// Check that the wallet has been onboarded (privacy keys exist in storage).
///
/// If not, prints instructions and exits 0.
pub fn require_onboarded(account: &Account) -> Result<(), String> {
    match account.user_public_keys() {
        Ok(_) => Ok(()),
        Err(e) => {
            let wallet = env_or("SPP_WALLET_PATH", default_wallet_path());
            eprintln!(
                "Skipping: wallet at {wallet} does not contain privacy keys for {}: {e}",
                account.user_address(),
            );
            eprintln!("Onboard the wallet first (e.g. with the `spp` CLI) and re-run.");
            std::process::exit(0);
        }
    }
}

/// Check whether an error is the RPC retention gap reported by the indexer.
///
/// The public Soroban RPC retention window can be shorter than the deployment
/// history, and the default bootnode handoff can be stale. This detector is
/// used by examples to turn the failure into a graceful skip message.
///
/// Two distinct failure shapes mean "the required history is unavailable":
///
/// 1. No bootnode configured: the SDK reports `RPC sync gap: main RPC lacks
///    history ...`, matched by `sync gap`.
/// 2. A bootnode is configured but cannot serve the requested range either. The
///    SDK wraps the indexer's JSON-RPC failure as `bootnode indexer: jsonrpc
///    error: -32602 - unsupported filters (requested startLedger=...)`, which
///    contains neither `sync gap` nor `retention`.
///
/// Shape 2 is the default path, because the examples configure a bootnode
/// unless one is explicitly disabled, so it must be matched too or an aged
/// deployment surfaces a raw JSON-RPC error instead of the skip message.
///
/// Matching on message text is unavoidably brittle. The robust alternative is a
/// dedicated error variant in the SDK, which is deliberately out of scope here:
/// these examples are fixed without touching production code.
pub fn is_retention_gap_error(e: &dyn std::error::Error) -> bool {
    is_retention_gap_message(&e.to_string())
}

/// Substring test behind [`is_retention_gap_error`], also usable for errors
/// that have already been flattened to a `String`.
pub fn is_retention_gap_message(msg: &str) -> bool {
    let msg = msg.to_lowercase();
    msg.contains("sync gap")
        || msg.contains("retention")
        || msg.contains("unsupported filters")
        || msg.contains("bootnode indexer")
}

/// Print the retention-gap skip message and exit 0.
///
/// Call this only after [`is_retention_gap_error`] returns true; the function
/// never returns to the caller.
pub fn skip_on_retention_gap(e: &dyn std::error::Error) -> ! {
    eprintln!("Skipping: the wallet's required history is older than the RPC retention window.");
    eprintln!("The configured bootnode's handoff point may also be stale.");
    eprintln!("Remedies:");
    eprintln!("  - Set SPP_BOOTNODE_URL to a bootnode with a fresher handoff point,");
    eprintln!("  - Set SPP_RPC_URL to a full-history RPC endpoint, or");
    eprintln!("  - Retry later.");
    eprintln!();
    eprintln!("Underlying error: {e}");
    std::process::exit(0);
}

/// Parse `SPP_AMOUNT_STROOPS` as a [`NoteAmount`] (default: 1 XLM).
pub fn amount() -> Result<NoteAmount, String> {
    let raw = env_or("SPP_AMOUNT_STROOPS", "10000000");
    let stroops: u128 = raw
        .parse()
        .map_err(|e| format!("invalid SPP_AMOUNT_STROOPS `{raw}`: {e}"))?;
    if stroops == 0 {
        return Err("invalid SPP_AMOUNT_STROOPS `0`: amount must be greater than zero".to_string());
    }
    Ok(NoteAmount::from(stroops))
}

/// Load a full transact-ready client, account, and pool in one call.
///
/// Use this from deposit/transfer/withdraw examples.
pub fn init_transact_session() -> Result<
    (
        Client,
        Account,
        PrivatePool,
        ContractConfig,
        PoolConfigEntry,
    ),
    String,
> {
    let config = load_contract_config()?;
    let pool = select_pool(&config)?.clone();
    let storage = open_storage()?;
    let client = build_client_for_pool(storage, config.clone(), &pool)?;
    let account = build_account(&client)?;
    require_onboarded(&account)?;
    let pool_session = account
        .pool(&pool.pool_contract_id)
        .map_err(|e| format!("open pool {}: {e}", pool.pool_contract_id))?;
    Ok((client, account, pool_session, config, pool))
}

/// Verify that the wallet account can cover a deposit of `amount` for `pool`.
///
/// Only native (XLM) balances are checked automatically; for other assets the
/// caller must ensure the account holds enough tokens. If the balance is
/// insufficient, prints the user address and amount and exits 0.
pub fn require_funded_for_pool(
    client: &Client,
    account: &Account,
    pool: &PoolConfigEntry,
    amount: NoteAmount,
) -> Result<(), String> {
    let address = account.user_address();
    match &pool.asset {
        AssetDescriptor::Native => {
            let fetcher = client
                .state_fetcher()
                .map_err(|e| format!("state fetcher: {e}"))?;
            let runtime =
                tokio::runtime::Runtime::new().map_err(|e| format!("tokio runtime: {e}"))?;
            let entry = match runtime.block_on(fetcher.rpc().get_account(address)) {
                Ok(entry) => entry,
                Err(e) => {
                    let msg = e.to_string();
                    if msg.to_lowercase().contains("not found") {
                        eprintln!(
                            "Skipping: account {address} was not found on-chain; fund it with XLM on testnet and re-run this example."
                        );
                    } else {
                        eprintln!(
                            "Skipping: could not verify funding for {address}: {msg}\nFund the account with XLM on testnet and re-run this example."
                        );
                    }
                    std::process::exit(0);
                }
            };
            let balance = i128::from(entry.balance);
            // A deposit also pays base/resource fees; require a margin so an
            // exactly-funded account does not pass this precheck and then fail
            // on-chain. 0.1 XLM is far above typical Soroban fees.
            const FEE_BUFFER_STROOPS: i128 = 1_000_000;
            let needed = i128::try_from(u128::from(amount))
                .map_err(|_| format!("deposit amount {amount} exceeds native balance range"))?
                .saturating_add(FEE_BUFFER_STROOPS);
            if balance < needed {
                eprintln!(
                    "Skipping: account {address} has {balance} stroops but needs at least {needed} stroops to deposit (amount plus a {FEE_BUFFER_STROOPS}-stroop fee buffer)."
                );
                eprintln!("Fund the account with XLM on testnet and re-run this example.");
                std::process::exit(0);
            }
        }
        _ => {
            println!(
                "Note: automatic funding check is not implemented for asset {}; ensure {} is funded.",
                pool.token_label(),
                address
            );
        }
    }
    Ok(())
}
