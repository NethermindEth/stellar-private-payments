//! Live testnet: a withdrawal whose recipient cannot receive the asset.
//!
//! The pool pays its recipient inside the contract, with
//! `token_client.transfer(&this, &ext_data.recipient, &amount)`
//! (`contracts/pool/src/pool.rs:535`). If that traps, it traps after the
//! nullifiers have been marked spent, at the end of a full proof cycle.
//!
//! The recorded decision was to build no preflight machinery, because
//! `simulate` runs immediately before `sign` on every operation
//! (`sdk/native/src/pool.rs:462` then `:465`) and simulation executes contract
//! code, so an undeliverable payout *should* already fail there, before anyone
//! is asked to sign. This test turns that "should" into a result: it stops at
//! `simulate` and never signs.
//!
//! The native asset needs the recipient to exist as an account; a classic asset
//! additionally needs a trustline. Both trap in that same one call, so the
//! native pool exercises the path without an issued asset in play.
//!
//! Needs a funded, registered testnet account:
//!
//! ```sh
//! deployments/scripts/e2e-accounts-setup.sh --accounts a
//! set -a; . deployments/testnet/.e2e-accounts.env; set +a
//! cargo test -p sdk-tests -- --ignored recipient
//! ```

use anyhow::{Context, Result, bail};
use stellar_private_payments::{
    CircuitStore, Error, Handle, LocalProver, LocalSigner, LocalStorage, Prover, Signer,
    blocking::{Client, PrivatePool},
    chain::LocalSigner as StellarSigner,
    types::{ContractConfig, NoteAmount, NoteOwnerAddress, SignerAddress},
};

/// Withdrawn by the test, in stroops (0.05 XLM). Never actually submitted:
/// every path here stops at simulation.
const WITHDRAW_STROOPS: u128 = 500_000;

/// Deposited when the account has nothing spendable, in stroops (0.2 XLM).
/// Large enough to leave change, so the withdrawal is a two-output spend.
const SEED_DEPOSIT_STROOPS: u128 = 2_000_000;

const TESTNET_PASSPHRASE: &str = "Test SDF Network ; September 2015";

/// Everything the live run needs, read from the environment the provisioning
/// script writes.
struct LiveEnv {
    network: String,
    rpc_url: String,
    bootnode_url: Option<String>,
    pool_contract: String,
    address: String,
    secret: String,
}

fn live_env() -> Result<LiveEnv> {
    let var = |name: &str| -> Result<String> {
        std::env::var(name).with_context(|| {
            format!("{name} is unset; source deployments/testnet/.e2e-accounts.env")
        })
    };
    Ok(LiveEnv {
        network: var("E2E_NETWORK")?,
        rpc_url: var("E2E_RPC_URL")?,
        bootnode_url: std::env::var("E2E_BOOTNODE_URL").ok(),
        pool_contract: var("E2E_POOL_CONTRACT")?,
        address: var("E2E_ACCOUNT_A_ADDRESS")?,
        secret: var("E2E_ACCOUNT_A_SECRET")?,
    })
}

/// The wallet the provisioning script onboarded into.
///
/// It holds the privacy keys derived for the test account — a fresh database
/// would have none, and the account's keys cannot be re-derived here without
/// the wallet signature that produced them.
fn wallet_path(env: &LiveEnv) -> String {
    std::env::var("SPP_WALLET_PATH").unwrap_or_else(|_| {
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join(format!(
                "../../deployments/scripts/.e2e-wallet-{}/spp.db",
                env.network
            ))
            .to_string_lossy()
            .into_owned()
    })
}

fn deployment_config() -> Result<ContractConfig> {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../deployments/testnet/deployments.json");
    let contents = std::fs::read_to_string(&path)
        .with_context(|| format!("read deployment config {}", path.display()))?;
    serde_json::from_str(&contents).context("parse deployment config")
}

/// A session on the live pool, signing and owning notes as the same account.
fn live_pool(env: &LiveEnv) -> Result<(Client, PrivatePool)> {
    let config = deployment_config()?;
    let pool_entry = config
        .pool(&env.pool_contract)
        .context("the configured pool is not in the deployment")?;
    let stem = pool_entry.circuit_stem();

    let store = CircuitStore::open(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/circuits-artifacts"),
    );
    store.ensure_blocking().context("circuit artifacts")?;
    let artifacts = store
        .artifacts(&stem.to_string())
        .context("circuit artifacts for the pool's stem")?;
    let prover = Handle::from_box(Box::new(
        LocalProver::from_artifacts(&[(stem, artifacts)]).context("local prover")?,
    ) as Box<dyn Prover>);

    let storage = LocalStorage::open(&wallet_path(env)).context("open storage")?;

    let client = Client::init(
        &env.rpc_url,
        storage,
        prover,
        config,
        env.bootnode_url.clone(),
    )
    .context("init client")?;

    let signer = Handle::from_box(Box::new(
        LocalSigner::new(
            &env.secret,
            TESTNET_PASSPHRASE,
            SignerAddress::new(env.address.as_str()),
        )
        .context("build signer")?,
    ) as Box<dyn Signer>);

    let account = client
        .account(
            NoteOwnerAddress::new(env.address.as_str()),
            SignerAddress::new(env.address.as_str()),
            signer,
        )
        .context("open account")?;
    let pool = account.pool(&env.pool_contract).context("open pool")?;
    Ok((client, pool))
}

/// An address that is not an account on testnet, so the native asset has
/// nowhere to land. Derived from a fixed seed, so the test names the same
/// unreachable recipient on every run.
fn unreceivable_recipient() -> String {
    StellarSigner::from_seed([0x5A; 32])
        .public_key()
        .to_string()
}

/// Deposit once if the account has nothing to spend, so the test can be run
/// repeatedly against the same provisioned account.
fn ensure_spendable(pool: &PrivatePool, needed: NoteAmount) -> Result<()> {
    let balance = pool.balance().context("read balance")?;
    if balance >= needed {
        return Ok(());
    }
    eprintln!("seeding: balance {balance:?} is below {needed:?}, depositing");
    pool.deposit(NoteAmount::from(SEED_DEPOSIT_STROOPS))
        .context("seed deposit")?;
    Ok(())
}

/// Prove a withdrawal to `recipient` and simulate it, stopping there.
///
/// Signing is the next step in the real flow and is deliberately not taken:
/// what this test is about is whether the failure arrives before it.
fn simulate_withdrawal_to(
    pool: &PrivatePool,
    recipient: &str,
) -> Result<(), stellar_private_payments::Error> {
    let wallet = pool.spendable_notes()?;
    let mut plan = pool.prepare_withdraw(&wallet, NoteAmount::from(WITHDRAW_STROOPS), recipient)?;
    let mut prepared = pool.prove_next(&mut plan)?;
    pool.simulate(&mut prepared)
}

/// A recipient that cannot receive must stop the withdrawal at simulation.
///
/// The control half matters as much as the assertion: the same spend, proved
/// the same way, simulates cleanly when the owner is the recipient. Without it
/// a failure here would only mean "something is wrong".
#[test]
#[ignore = "needs a funded testnet account; see the module docs"]
fn a_withdrawal_to_an_unreceivable_recipient_fails_at_simulation() -> Result<()> {
    let env = live_env()?;
    let (client, pool) = live_pool(&env)?;
    client.sync().context("sync")?;
    ensure_spendable(&pool, NoteAmount::from(WITHDRAW_STROOPS))?;
    client.sync().context("sync after seeding")?;

    simulate_withdrawal_to(&pool, &env.address)
        .context("the control withdrawal, back to the owner, must simulate cleanly")?;

    let recipient = unreceivable_recipient();
    let error = match simulate_withdrawal_to(&pool, &recipient) {
        Err(error) => error,
        Ok(()) => bail!(
            "simulation accepted a withdrawal to {recipient}, which cannot receive the asset: \
             the premise that simulation catches this is wrong, and a preflight is needed"
        ),
    };

    match &error {
        Error::RecipientCannotReceive {
            recipient: named,
            simulation,
        } => {
            assert_eq!(named, &recipient, "the error must name the recipient");
            assert!(
                !simulation.is_empty(),
                "the raw simulation output must be kept for debugging",
            );
        }
        other => bail!("expected RecipientCannotReceive, got {other:?}"),
    }

    // The app classifies a wallet cancellation by substring; an undeliverable
    // payout is not one, and the message must not read like one.
    let rendered = error.to_string().to_ascii_lowercase();
    for word in ["rejected", "denied", "cancelled", "canceled"] {
        assert!(
            !rendered.contains(word),
            "{word:?} would be read as a wallet cancellation: {rendered}"
        );
    }
    eprintln!("rendered for a user: {error}");
    Ok(())
}
