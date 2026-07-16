use types::{
    ContractConfig, EncryptionPublicKey, Field, NotePublicKey, PortfolioBalance, UserNoteSummary,
};

use prover::crypto::asp_membership_leaf;

use stellar::{Limits, ReadXdr, StateFetcher, TransactionEnvelope, submit_tx};

use crate::{
    Error, Handle, PrivatePool, PrivatePoolConfig, Prover, Signer, Storage, SyncMode,
    chain::RpcClient,
    sync::{Sync, catch_up, confirm_tx},
    types::TransactionResult,
};

/// Stellar account session
///
/// Construct via [`crate::Client::account`].
pub struct Account<S: Storage> {
    rpc: RpcClient,
    storage: S,
    prover: Handle<dyn Prover>,
    user_address: String,
    signer: Handle<dyn Signer>,
    sync: Sync,
    contract_config: ContractConfig,
}

impl<S: Storage> Account<S> {
    pub(crate) fn new(
        rpc: RpcClient,
        storage: S,
        prover: Handle<dyn Prover>,
        user_address: String,
        signer: Handle<dyn Signer>,
        sync: Sync,
        contract_config: ContractConfig,
    ) -> Self {
        Self {
            rpc,
            storage,
            prover,
            user_address,
            signer,
            sync,
            contract_config,
        }
    }

    pub fn user_address(&self) -> &str {
        &self.user_address
    }

    pub fn signer(&self) -> &Handle<dyn Signer> {
        &self.signer
    }

    pub fn storage(&self) -> &S {
        &self.storage
    }

    /// Catch local storage up to the current chain tip for the deployment.
    pub async fn sync(&self) -> Result<(), Error> {
        catch_up(
            &self.rpc,
            &self.storage,
            &self.contract_config,
            self.sync.bootnode_url.as_deref(),
        )
        .await
    }

    /// Portfolio balances across all enabled pools in the deployment.
    ///
    /// With [`SyncMode::Inline`], local storage is synced before reading.
    pub async fn portfolio(&self) -> Result<Vec<PortfolioBalance>, Error> {
        self.ensure_synced().await?;
        self.storage
            .list_portfolio_balances(&self.user_address, &self.contract_config)
            .await
    }

    /// Locally derived note and encryption public keys for this account.
    pub async fn user_public_keys(&self) -> Result<(NotePublicKey, EncryptionPublicKey), Error> {
        self.storage.user_public_keys(&self.user_address).await
    }

    /// Locally derived ASP membership blinding for this account.
    pub async fn asp_secret(&self) -> Result<Field, Error> {
        self.storage.asp_secret(&self.user_address).await
    }

    /// Derive the ASP membership tree leaf for this account's note public key.
    pub async fn derive_asp_user_leaf(
        &self,
        note_public_key: Option<NotePublicKey>,
        membership_blinding: Option<Field>,
    ) -> Result<Field, Error> {
        let note = match note_public_key {
            Some(note) => note,
            None => self.storage.user_public_keys(&self.user_address).await?.0,
        };
        let blinding = match membership_blinding {
            Some(blinding) => blinding,
            None => self.storage.asp_secret(&self.user_address).await?,
        };
        asp_membership_leaf(&note, &blinding).map_err(|e| Error::Other(e.to_string()))
    }

    /// Notes for this account across all pools (newest first).
    ///
    /// With [`SyncMode::Inline`], local storage is synced before reading.
    pub async fn user_notes(&self, limit: u32) -> Result<Vec<UserNoteSummary>, Error> {
        self.ensure_synced().await?;
        self.storage
            .list_user_notes(&self.user_address, limit)
            .await
    }

    /// Whether this account's public keys are registered on-chain.
    ///
    /// With [`SyncMode::Inline`], local storage is synced before reading.
    pub async fn is_registered(&self) -> Result<bool, Error> {
        self.ensure_synced().await?;
        Ok(self
            .storage
            .recipient_lookup(&self.user_address, &self.contract_config)
            .await?
            .entry
            .is_some())
    }

    /// Register this account's public keys on the deployment-wide registry.
    pub async fn register_public_keys(
        &self,
        note_public_key: Option<NotePublicKey>,
        encryption_public_key: Option<EncryptionPublicKey>,
    ) -> Result<TransactionResult, Error> {
        let (note_pk, enc_pk) = match (note_public_key, encryption_public_key) {
            (Some(note), Some(enc)) => (note, enc),
            (None, None) => self.storage().user_public_keys(&self.user_address).await?,
            _ => {
                return Err(Error::Other(
                    "note and encryption public keys must both be provided or both omitted".into(),
                ));
            }
        };

        let fetcher = StateFetcher::new(self.rpc.clone(), self.contract_config.clone())
            .map_err(|e| Error::Other(format!("state fetcher: {e:#}")))?;
        let prepared = fetcher
            .prepare_register(&self.user_address, note_pk.0, enc_pk.0)
            .await
            .map_err(|e| Error::Other(format!("prepare register: {e:#}")))?;
        let signed = self.signer.sign_soroban_transaction(&prepared).await?;
        let envelope = TransactionEnvelope::from_xdr_base64(&signed.signed_xdr, Limits::none())
            .map_err(|e| Error::Other(format!("invalid signed transaction xdr: {e}")))?;
        let hash = submit_tx(fetcher.rpc(), &envelope)
            .await
            .map_err(|e| Error::Other(format!("submit register: {e:#}")))?;
        confirm_tx(fetcher.rpc(), hash).await
    }

    /// Create an owned pool session for `pool_contract_id`.
    pub fn pool(&self, pool_contract_id: impl Into<String>) -> Result<PrivatePool<S>, Error> {
        let cfg = PrivatePoolConfig {
            contract_config: self.contract_config.clone(),
            pool_contract_id: pool_contract_id.into(),
            user_address: self.user_address.clone(),
        };

        PrivatePool::init(
            self.rpc.clone(),
            cfg,
            self.storage.fork()?,
            self.signer.clone(),
            self.prover.clone(),
            self.sync.clone(),
        )
    }

    async fn ensure_synced(&self) -> Result<(), Error> {
        match self.sync.mode() {
            SyncMode::Inline => self.sync().await?,
            SyncMode::Background => self.sync.kick(),
        }
        Ok(())
    }
}
