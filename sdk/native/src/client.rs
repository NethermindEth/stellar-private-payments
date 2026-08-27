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

    /// Create an [`Account`] session.
    #[tracing::instrument(
        name = "client_account",
        skip_all,
        fields(correlation_id = %correlation_id_or_new())
    )]
    pub fn account(
        &self,
        user_address: NoteOwnerAddress,
        signer_address: SignerAddress,
        signer: Handle<dyn Signer>,
    ) -> Result<Account<S>, Error> {
        ensure_signer_is_note_owner(&user_address, &signer_address)?;
        Ok(Account::new(
            self.rpc.clone(),
            self.storage.fork()?,
            self.prover.clone(),
            user_address,
            signer_address,
            signer,
            self.sync.clone(),
            self.contract_config.clone(),
        ))
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

/// Reject a session whose signing account is not the note owner.
///
/// The two are separate types, but nothing downstream honours them differing:
/// the envelope source, the pool contract's `sender`, the sequence number and
/// the auth entries are all built from the owner. A divergent pair would ask a
/// wallet to sign, as B, a transaction assembled for A — so it is refused
/// rather than collapsed to the owner.
///
/// A free function so it can be unit-tested without an RPC endpoint, storage
/// or a prover.
fn ensure_signer_is_note_owner(
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

#[cfg(test)]
mod signer_is_note_owner_tests {
    use super::*;

    const OWNER: &str = "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF";
    const DELEGATE: &str = "GBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB6BQ";

    #[test]
    fn the_owner_signing_for_itself_is_accepted() {
        // Every caller in the workspace today: the CLI, the examples, the
        // fixtures and the browser SDK all pass the same address twice.
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
        .expect_err("a signer that is not the note owner must not open a session");

        match &error {
            Error::SignerIsNotNoteOwner { owner, signer } => {
                assert_eq!(owner, OWNER);
                assert_eq!(signer, DELEGATE);
            }
            other => panic!("expected SignerIsNotNoteOwner, got {other:?}"),
        }

        // The message must name both, so an operator reading a log can see
        // which pair was rejected without reaching for a debugger.
        let rendered = error.to_string();
        assert!(
            rendered.contains(OWNER) && rendered.contains(DELEGATE),
            "refusal must name both identities: {rendered}"
        );
    }

    #[test]
    fn the_comparison_is_exact() {
        // Guards against anyone later relaxing this to a case-insensitive or
        // trimmed match. Strkeys are already canonical; near-misses are
        // different accounts, not the same one spelled differently.
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
