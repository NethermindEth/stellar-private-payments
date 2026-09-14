use crate::types::{
    ContractConfig, EncryptionPublicKey, Field, NoteOwnerAddress, NotePublicKey, PortfolioBalance,
    SignerAddress, UserNoteSummary,
};

use crate::chain::{Limits, ReadXdr, StateFetcher, TransactionEnvelope, submit_tx};

use crate::{
    Error, Handle, PrivatePool, Prover, Signer, Storage,
    chain::RpcClient,
    sync::{SyncHandle, catch_up, confirm_tx},
    types::{PrivatePoolConfig, TransactionResult},
};

/// Stellar account session
///
/// Construct via [`crate::Client::account`].
pub struct Account<S: Storage> {
    rpc: RpcClient,
    storage: S,
    prover: Handle<dyn Prover>,
    user_address: NoteOwnerAddress,
    signer_address: SignerAddress,
    signer: Handle<dyn Signer>,
    sync: SyncHandle,
    contract_config: ContractConfig,
}

impl<S: Storage> Account<S> {
    // Bundling these into a struct would trade the lint for an indirection at
    // the only two call sites, both of which name every field explicitly.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        rpc: RpcClient,
        storage: S,
        prover: Handle<dyn Prover>,
        user_address: NoteOwnerAddress,
        signer_address: SignerAddress,
        signer: Handle<dyn Signer>,
        sync: SyncHandle,
        contract_config: ContractConfig,
    ) -> Self {
        Self {
            rpc,
            storage,
            prover,
            user_address,
            signer_address,
            signer,
            sync,
            contract_config,
        }
    }

    /// The account that owns the notes.
    pub fn user_address(&self) -> &NoteOwnerAddress {
        &self.user_address
    }

    /// The account that signs and pays. A distinct type from
    /// [`Self::user_address`] so the two cannot be confused.
    pub fn signer_address(&self) -> &SignerAddress {
        &self.signer_address
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
            self.sync.bootnode_url(),
        )
        .await
    }

    /// Portfolio balances across all enabled pools in the deployment.
    ///
    /// With [`SyncMode::Inline`], local storage is synced before reading.
    pub async fn portfolio(&self) -> Result<Vec<PortfolioBalance>, Error> {
        self.ensure_synced().await?;
        self.storage
            .list_portfolio_balances(
                self.user_address.as_str(),
                &self.contract_config.portfolio_pools(),
            )
            .await
    }

    /// Locally derived note and encryption public keys for this account.
    pub async fn user_public_keys(&self) -> Result<(NotePublicKey, EncryptionPublicKey), Error> {
        self.storage
            .user_public_keys(self.user_address.as_str())
            .await
    }

    /// Locally derived ASP membership blinding for this account.
    pub async fn asp_secret(&self) -> Result<Field, Error> {
        self.storage.asp_secret(self.user_address.as_str()).await
    }

    /// Derive the ASP membership tree leaf for this account's note public key.
    pub async fn derive_asp_user_leaf(&self) -> Result<Field, Error> {
        let note = self
            .storage
            .user_public_keys(self.user_address.as_str())
            .await?
            .0;
        let blinding = self.storage.asp_secret(self.user_address.as_str()).await?;
        crate::crypto::derive_asp_user_leaf(&note, &blinding)
    }

    /// Notes for this account across all pools (newest first).
    ///
    /// With [`SyncMode::Inline`], local storage is synced before reading.
    pub async fn user_notes(&self, limit: u32) -> Result<Vec<UserNoteSummary>, Error> {
        self.ensure_synced().await?;
        self.storage
            .list_user_notes(self.user_address.as_str(), limit)
            .await
    }

    /// Whether this account's public keys are registered on-chain.
    ///
    /// With [`SyncMode::Inline`], local storage is synced before reading.
    pub async fn is_registered(&self) -> Result<bool, Error> {
        self.ensure_synced().await?;
        Ok(self
            .storage
            .recipient_lookup(self.user_address.as_str(), &self.contract_config)
            .await?
            .entry
            .is_some())
    }

    /// Register this account's public keys on the deployment-wide registry.
    ///
    /// # Errors
    /// Returns [`Error::SignerIsNotNoteOwner`] on a delegated session. The
    /// registry entry is the owner's, so simulation returns an auth entry
    /// keyed to the owner; the payer's wallet is only asked to sign for its
    /// own account and has nothing to put there. Checked before the call so a
    /// delegated session stops here rather than at an unfillable auth entry.
    pub async fn register_public_keys(
        &self,
        note_public_key: Option<NotePublicKey>,
        encryption_public_key: Option<EncryptionPublicKey>,
    ) -> Result<TransactionResult, Error> {
        ensure_signer_is_note_owner(&self.user_address, &self.signer_address)?;

        let (note_pk, enc_pk) = match (note_public_key, encryption_public_key) {
            (Some(note), Some(enc)) => (note, enc),
            (None, None) => {
                self.storage()
                    .user_public_keys(self.user_address.as_str())
                    .await?
            }
            _ => {
                return Err(Error::Other(
                    "note and encryption public keys must both be provided or both omitted".into(),
                ));
            }
        };

        let fetcher = StateFetcher::new(self.rpc.clone(), self.contract_config.clone())
            .map_err(|e| Error::Other(format!("state fetcher: {e:#}")))?;
        let prepared = fetcher
            // The owner is the registration; the signer only pays for it.
            // Both are the owner here, per the check above.
            .prepare_register(
                &self.user_address,
                &self.signer_address,
                note_pk.0,
                enc_pk.0,
            )
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
            signer_address: self.signer_address.clone(),
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
        self.sync
            .ensure_synced(&self.rpc, &self.storage, &self.contract_config)
            .await
    }
}

/// Refuse an operation that needs the note owner's own signature when the
/// session signs with a different account.
///
/// Call this only from the steps whose signature the owner alone can produce.
/// Opening a session and spending from it are not among them: both run
/// entirely on the payer's signature.
pub(crate) fn ensure_signer_is_note_owner(
    user_address: &NoteOwnerAddress,
    signer_address: &SignerAddress,
) -> Result<(), Error> {
    if signer_address.as_str() == user_address.as_str() {
        return Ok(());
    }
    Err(Error::SignerIsNotNoteOwner {
        owner: user_address.as_str().to_string(),
        signer: signer_address.as_str().to_string(),
    })
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod signer_is_note_owner_tests {
    use super::*;

    const OWNER: &str = "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF";
    const DELEGATE: &str = "GBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB6BQ";

    #[test]
    fn the_owner_signing_for_itself_is_accepted() {
        let result =
            ensure_signer_is_note_owner(&NoteOwnerAddress::new(OWNER), &SignerAddress::new(OWNER));
        assert!(result.is_ok());
    }

    #[test]
    fn a_delegate_signing_for_the_owner_is_refused() {
        let error = ensure_signer_is_note_owner(
            &NoteOwnerAddress::new(OWNER),
            &SignerAddress::new(DELEGATE),
        )
        .expect_err("a payer that is not the note owner must not produce an owner signature");

        match &error {
            Error::SignerIsNotNoteOwner { owner, signer } => {
                assert_eq!(owner, OWNER);
                assert_eq!(signer, DELEGATE);
            }
            other => panic!("expected SignerIsNotNoteOwner, got {other:?}"),
        }

        // Both addresses stay available to code; the rendered string redacts
        // them. Not asserted here: the reveal flag is a process global that
        // logging.rs's own tests toggle under a mutex this module cannot reach.
    }

    /// The app classifies a wallet cancellation by substring. An
    /// owner-signature refusal is not one, and must not read like one.
    #[test]
    fn the_refusal_does_not_read_as_a_wallet_cancellation() {
        let rendered = ensure_signer_is_note_owner(
            &NoteOwnerAddress::new(OWNER),
            &SignerAddress::new(DELEGATE),
        )
        .expect_err("a divergent pair must be refused")
        .to_string()
        .to_ascii_lowercase();

        for word in ["rejected", "denied", "cancelled", "canceled"] {
            assert!(
                !rendered.contains(word),
                "{word:?} would be read as a wallet cancellation: {rendered}"
            );
        }
    }

    #[test]
    fn the_comparison_is_exact() {
        // Strkeys are canonical; near-misses are different accounts.
        let owner = NoteOwnerAddress::new(OWNER);
        for near_miss in [
            OWNER.to_ascii_lowercase(),
            format!(" {OWNER}"),
            String::new(),
        ] {
            assert!(
                ensure_signer_is_note_owner(&owner, &SignerAddress::new(near_miss.as_str()))
                    .is_err(),
                "near-miss signer {near_miss:?} must be refused"
            );
        }
    }
}
