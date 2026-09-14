use crate::types::{
    ContractConfig, NoteOwnerAddress, OperationalFeedItem, RecipientLookup, SignerAddress,
};

use crate::{
    Account, Error, Handle, Prover, Signer, Storage, SyncMode,
    chain::{RpcClient, StateFetcher},
    correlation::correlation_id_or_new,
    prover::NoopProver,
    sync::{BackgroundSync, SyncHandle, catch_up},
};

/// Top-level SDK client for a privacy pools deployment.
///
/// Configure with local storage, a prover, and RPC; then sync and open
/// [`Account`] sessions. Starts in [`SyncMode::Inline`]; call
/// [`Self::background_sync`] to switch to background indexing.
pub struct Client<S: Storage> {
    rpc: RpcClient,
    storage: S,
    prover: Handle<dyn Prover>,
    sync: SyncHandle,
    contract_config: ContractConfig,
}

impl<S: Storage> Client<S> {
    #[tracing::instrument(
        name = "client_init",
        skip_all,
        fields(correlation_id = %correlation_id_or_new())
    )]
    pub fn init(
        rpc_url: impl AsRef<str>,
        storage: S,
        prover: Handle<dyn Prover>,
        contract_config: ContractConfig,
        bootnode_url: Option<String>,
    ) -> Result<Self, Error> {
        let rpc = RpcClient::new(rpc_url.as_ref())
            .map_err(|e| Error::Other(format!("rpc error: {e:#}")))?;
        Ok(Self {
            rpc,
            storage,
            prover,
            sync: SyncHandle::inline(bootnode_url),
            contract_config,
        })
    }

    /// Read-only client with a no-op prover (balance, notes, sync, portfolio).
    pub fn init_readonly(
        rpc_url: impl AsRef<str>,
        storage: S,
        contract_config: ContractConfig,
        bootnode_url: Option<String>,
    ) -> Result<Self, Error> {
        Self::init(
            rpc_url,
            storage,
            Handle::from_box(Box::new(NoopProver) as Box<dyn Prover>),
            contract_config,
            bootnode_url,
        )
    }

    pub fn storage(&self) -> &S {
        &self.storage
    }

    pub fn prover(&self) -> &Handle<dyn Prover> {
        &self.prover
    }

    pub fn contract_config(&self) -> &ContractConfig {
        &self.contract_config
    }

    /// Shared Stellar RPC client (cheap to clone).
    pub fn rpc(&self) -> &RpcClient {
        &self.rpc
    }

    /// Catch local storage up to the current chain tip for the deployment.
    ///
    /// Uses the bootnode URL from [`Self::init`] when the wallet RPC has a
    /// retention gap.
    pub async fn sync(&self) -> Result<(), Error> {
        catch_up(
            &self.rpc,
            &self.storage,
            &self.contract_config,
            self.sync.bootnode_url(),
        )
        .await
    }

    /// Keep client synced in [`SyncMode::Background`] mode.
    ///
    /// Uses the bootnode URL from [`Self::init`] when the wallet RPC has a
    /// retention gap. Does not spawn — call/spawn [`BackgroundSync::run`] on
    /// your runtime.
    #[must_use = "client sync is now in background mode; call/spawn BackgroundSync::run to keep the client up-to-date"]
    pub fn background_sync(&mut self) -> Result<BackgroundSync<S>, Error> {
        self.sync.set_mode(SyncMode::Background);
        Ok(BackgroundSync::new(
            self.rpc.clone(),
            self.storage.fork()?,
            self.contract_config.clone(),
            self.sync.bootnode_url().map(Into::into),
            self.sync.kick.clone(),
        ))
    }

    /// Recent deployment activity (pool events, registry registrations, ASP
    /// updates).
    ///
    /// With [`SyncMode::Inline`], local storage is synced before reading.
    pub async fn operational_feed(&self, limit: u32) -> Result<Vec<OperationalFeedItem>, Error> {
        self.ensure_synced().await?;
        self.storage
            .operational_feed(limit, &self.contract_config)
            .await
    }

    /// Look up a Stellar address in the on-chain public key registry index.
    ///
    /// With [`SyncMode::Inline`], local storage is synced before reading.
    pub async fn recipient_lookup(
        &self,
        address: impl AsRef<str>,
    ) -> Result<RecipientLookup, Error> {
        self.ensure_synced().await?;
        self.storage
            .recipient_lookup(address.as_ref(), &self.contract_config)
            .await
    }

    /// Create an [`Account`] session. When `signer_address` is `user_address`
    /// and privacy keys are not yet stored, derives and persists them first.
    ///
    /// `signer_address` need not be `user_address`: the signer pays and
    /// sources every envelope, the owner holds the notes. Delegated sessions
    /// skip key derivation — see [`Account::register_public_keys`] and
    /// [`Error::SignerIsNotNoteOwner`].
    ///
    /// # Errors
    /// Returns a storage error if the session's storage handle cannot be
    /// forked, or an error from key derivation.
    #[tracing::instrument(
        name = "client_account",
        skip_all,
        fields(correlation_id = %correlation_id_or_new())
    )]
    pub async fn account(
        &self,
        user_address: NoteOwnerAddress,
        signer_address: SignerAddress,
        signer: Handle<dyn Signer>,
    ) -> Result<Account<S>, Error> {
        Account::open(
            self.rpc.clone(),
            self.storage.fork()?,
            self.prover.clone(),
            user_address,
            signer_address,
            signer,
            self.sync.clone(),
            self.contract_config.clone(),
        )
        .await
    }

    /// Chain-state accessor for this deployment.
    pub fn state_fetcher(&self) -> Result<StateFetcher, Error> {
        StateFetcher::new(self.rpc.clone(), self.contract_config.clone())
            .map_err(|e| Error::Other(format!("state fetcher: {e:#}")))
    }

    async fn ensure_synced(&self) -> Result<(), Error> {
        self.sync
            .ensure_synced(&self.rpc, &self.storage, &self.contract_config)
            .await
    }
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod divergent_session_tests {
    use super::*;
    use crate::{LocalSigner, LocalStorage};

    const OWNER: &str = "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF";
    const DELEGATE: &str = "GBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB6BQ";
    /// Ed25519 secret for `SigningKey::from_bytes(&[7u8; 32])`.
    const SECRET: &str = "SADQOBYHA4DQOBYHA4DQOBYHA4DQOBYHA4DQOBYHA4DQOBYHA4DQP54X";
    const PASSPHRASE: &str = "Test SDF Network ; September 2015";

    fn test_client() -> Client<LocalStorage> {
        static RUN: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        let db = std::env::temp_dir().join(format!(
            "spp-signer-owner-{}-{}.sqlite",
            std::process::id(),
            RUN.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        let _ = std::fs::remove_file(&db);
        Client::init_readonly(
            "https://soroban-testnet.stellar.org",
            LocalStorage::open(db.to_string_lossy().as_ref()).expect("open storage"),
            ContractConfig {
                network: PASSPHRASE.to_string(),
                deployer: String::new(),
                admin: String::new(),
                asp_membership: String::new(),
                asp_non_membership: String::new(),
                verifiers: Default::default(),
                public_key_registry: String::new(),
                pools: Vec::new(),
            },
            None,
        )
        .expect("init client")
    }

    fn test_signer(address: &str) -> Handle<dyn Signer> {
        Handle::from_box(Box::new(
            LocalSigner::new(SECRET, PASSPHRASE, SignerAddress::new(address))
                .expect("build signer"),
        ) as Box<dyn Signer>)
    }

    // A delegated session signs and pays as one account and owns notes as
    // another; it skips key derivation entirely, so it opens even with no
    // keys stored for the owner.
    #[tokio::test]
    async fn client_account_opens_a_divergent_pair() {
        let account = test_client()
            .account(
                NoteOwnerAddress::new(OWNER),
                SignerAddress::new(DELEGATE),
                test_signer(DELEGATE),
            )
            .await
            .expect("a payer that is not the note owner must still open a session");
        assert_eq!(account.user_address().as_str(), OWNER);
        assert_eq!(account.signer_address().as_str(), DELEGATE);
    }

    #[tokio::test]
    async fn client_account_opens_when_the_owner_signs_for_itself() {
        let account = test_client()
            .account(
                NoteOwnerAddress::new(OWNER),
                SignerAddress::new(OWNER),
                test_signer(OWNER),
            )
            .await
            .expect("the owner signing for itself must open a session");
        assert_eq!(account.user_address().as_str(), OWNER);
        assert_eq!(account.signer_address().as_str(), OWNER);
    }
}
