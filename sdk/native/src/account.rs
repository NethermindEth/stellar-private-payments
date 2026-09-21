use anyhow::Context;

use crate::types::{
    AssetDescriptor, ContractConfig, EncryptionPublicKey, Field, NoteOwnerAddress, NotePublicKey,
    PortfolioBalance, SignerAddress, UserNoteSummary,
};

use crate::chain::{Limits, ReadXdr, RpcError, StateFetcher, TransactionEnvelope, submit_tx};

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

    /// This account's classical on-chain balance of `asset`, in its smallest
    /// unit (stroops for native XLM).
    ///
    /// This is the classical account balance, not the
    /// shielded balance held in a pool — see [`crate::PrivatePool::balance`]
    /// for that.
    pub async fn balance(&self, asset: &AssetDescriptor) -> Result<u128, Error> {
        match asset {
            AssetDescriptor::Native => {
                match self.rpc.get_account(self.user_address.as_str()).await {
                    Ok(entry) => u128::try_from(entry.balance).map_err(|_| {
                        Error::Other(anyhow::anyhow!(
                            "negative account balance: {}",
                            entry.balance
                        ))
                    }),
                    Err(RpcError::NotFound("Account", _)) => Err(Error::AccountNotFound {
                        address: self.user_address.as_str().to_string(),
                    }),
                    Err(e) => Err(e.into()),
                }
            }
            AssetDescriptor::Classic { code, issuer } => Ok(self
                .rpc
                .get_trustline_balance(self.user_address.as_str(), code, issuer)
                .await?),
            AssetDescriptor::Contract { contract_id, .. } => Ok(self
                .rpc
                .get_token_balance(contract_id, self.user_address.as_str())
                .await?),
        }
    }

    /// Locally derived note and encryption public keys for this account.
    pub async fn privacy_keys(&self) -> Result<(NotePublicKey, EncryptionPublicKey), Error> {
        self.storage.privacy_keys(self.user_address.as_str()).await
    }

    /// Derive this account's privacy keys from the owner's wallet signature
    /// and persist them. Idempotent: returns the existing keys unchanged if
    /// already derived. Fails if `signer_address` is not `user_address` — see
    /// [`Error::SignerIsNotNoteOwner`] — and again if the returned signature
    /// was not made by the owner's key (a signer may claim an address without
    /// actually holding it).
    pub async fn derive_privacy_keys(&self) -> Result<(NotePublicKey, EncryptionPublicKey), Error> {
        if self
            .storage
            .privacy_keys_exist(self.user_address.as_str())
            .await?
        {
            return self.privacy_keys().await;
        }
        ensure_signer_is_note_owner(&self.user_address, &self.signer_address)?;

        let signature = self
            .signer
            .sign_message(crate::zk::encryption::KEY_DERIVATION_MESSAGE)
            .await?;
        // The signer only promises to sign *as* `signer_address`; a wallet
        // implementation can still return a signature made with a different
        // key. Verify it against the owner before it is trusted to derive
        // and persist keys under `user_address`.
        crate::zk::encryption::verify_owner_signature(
            self.user_address.as_str(),
            crate::zk::encryption::KEY_DERIVATION_MESSAGE,
            &signature,
        )?;
        let (note_keypair, encryption_keypair) =
            crate::zk::encryption::derive_encryption_and_note_keypairs(signature.clone())
                .context("derive privacy keypairs")?;
        let membership_blinding = crate::zk::encryption::derive_membership_blinding(
            &signature,
            &self.contract_config.network,
        )
        .context("derive membership blinding")?;

        self.storage
            .save_private_keys(
                self.user_address.as_str(),
                &note_keypair,
                &encryption_keypair,
                &membership_blinding,
            )
            .await?;

        Ok((note_keypair.public, encryption_keypair.public))
    }

    /// Locally derived ASP membership blinding for this account.
    pub async fn asp_secret(&self) -> Result<Field, Error> {
        self.storage.asp_secret(self.user_address.as_str()).await
    }

    /// Derive the ASP membership tree leaf for this account's note public key.
    pub async fn derive_asp_user_leaf(&self) -> Result<Field, Error> {
        let note = self
            .storage
            .privacy_keys(self.user_address.as_str())
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
    pub async fn register_public_keys(&self) -> Result<TransactionResult, Error> {
        ensure_signer_is_note_owner(&self.user_address, &self.signer_address)?;

        let (note_pk, enc_pk) = self
            .storage()
            .privacy_keys(self.user_address.as_str())
            .await?;

        let fetcher = StateFetcher::new(self.rpc.clone(), self.contract_config.clone())
            .context("state fetcher")?;
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
            .context("prepare register")?;
        let signed = self.signer.sign_soroban_transaction(&prepared).await?;
        let envelope = TransactionEnvelope::from_xdr_base64(&signed.signed_xdr, Limits::none())
            .context("invalid signed transaction xdr")?;
        let hash = submit_tx(fetcher.rpc(), &envelope)
            .await
            .context("submit register")?;
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

#[cfg(all(test, not(target_arch = "wasm32")))]
mod derive_privacy_keys_tests {
    use super::*;
    use crate::{Client, LocalSigner, LocalStorage, types::ContractConfig};

    /// The real Stellar address for `SigningKey::from_bytes(&[7u8; 32])` —
    /// must match `SECRET` for `verify_owner_signature` to accept it.
    const OWNER: &str = "GDVEU3DD4KOFECV66VIHWEZOYX4ZKR3WV27L464SIIPOU2IUI3JCZA57";
    /// Ed25519 secret for `SigningKey::from_bytes(&[7u8; 32])`.
    const SECRET: &str = "SADQOBYHA4DQOBYHA4DQOBYHA4DQOBYHA4DQOBYHA4DQOBYHA4DQP54X";
    const PASSPHRASE: &str = "Test SDF Network ; September 2015";

    fn test_client() -> Client<LocalStorage> {
        static RUN: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        let db = std::env::temp_dir().join(format!(
            "spp-derive-privacy-keys-{}-{}.sqlite",
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

    fn test_signer(address: &str) -> Handle<dyn crate::Signer> {
        Handle::from_box(Box::new(
            LocalSigner::new(SECRET, PASSPHRASE, SignerAddress::new(address))
                .expect("build signer"),
        ) as Box<dyn crate::Signer>)
    }

    /// A signer whose `sign_message` panics: proves a code path never asks it
    /// to sign.
    struct PanicOnMessageSigner(Handle<dyn crate::Signer>);

    #[async_trait::async_trait(?Send)]
    impl crate::Signer for PanicOnMessageSigner {
        async fn sign_transaction(
            &self,
            prepared: &crate::PreparedTransaction,
        ) -> Result<crate::types::SignedTransaction, Error> {
            self.0.sign_transaction(prepared).await
        }

        async fn sign_message(
            &self,
            _message: &str,
        ) -> Result<crate::types::KeyDerivationSignature, Error> {
            panic!("derive_privacy_keys() must not re-derive when keys already exist");
        }
    }

    #[tokio::test]
    async fn derive_privacy_keys_derives_and_persists_privacy_keys_for_the_owner() {
        let account = test_client()
            .account(
                NoteOwnerAddress::new(OWNER),
                SignerAddress::new(OWNER),
                test_signer(OWNER),
            )
            .expect("open account");

        account.derive_privacy_keys().await.expect("derive keys");

        account
            .privacy_keys()
            .await
            .expect("keys were derived and stored");
    }

    #[tokio::test]
    async fn derive_privacy_keys_does_not_re_derive_when_keys_already_exist() {
        let client = test_client();
        let account = client
            .account(
                NoteOwnerAddress::new(OWNER),
                SignerAddress::new(OWNER),
                test_signer(OWNER),
            )
            .expect("open account");
        account.derive_privacy_keys().await.expect("derive keys");

        let account = client
            .account(
                NoteOwnerAddress::new(OWNER),
                SignerAddress::new(OWNER),
                Handle::from_box(
                    Box::new(PanicOnMessageSigner(test_signer(OWNER))) as Box<dyn crate::Signer>
                ),
            )
            .expect("open account");

        account
            .derive_privacy_keys()
            .await
            .expect("re-deriving with existing keys must not re-sign");
    }

    /// `signer_address` is a claim the signer makes about itself, not a proof.
    /// A session opened with `user_address == signer_address == DELEGATE`
    /// passes [`ensure_signer_is_note_owner`], but if the signer actually
    /// signs with OWNER's key underneath, the returned signature was not made
    /// by DELEGATE's key and must be refused before anything is derived or
    /// saved under DELEGATE.
    #[tokio::test]
    async fn derive_privacy_keys_refuses_a_signature_not_made_by_the_claimed_address() {
        /// A different, validly-formed owner address — not derived from
        /// `SECRET`, so `OWNER`'s real signature must not verify against it.
        const DELEGATE: &str = "GD6ROJBYLKQMOW3E7N4M2YBPUHMZD7PL65VRHRMO24BOVSBV5H3BQRSL";

        let account = test_client()
            .account(
                NoteOwnerAddress::new(DELEGATE),
                SignerAddress::new(DELEGATE),
                test_signer(OWNER),
            )
            .expect("open account");

        let error = account
            .derive_privacy_keys()
            .await
            .expect_err("a signature made by another key must be refused")
            .to_string();
        assert!(
            error.contains("not made by the note owner"),
            "expected a signature-verification failure, got {error:?}"
        );

        account
            .privacy_keys()
            .await
            .expect_err("nothing must be persisted under DELEGATE after a refused signature");
    }
}
