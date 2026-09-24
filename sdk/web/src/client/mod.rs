//! Wasm [`Client`] — thin browser wrapper around the native SDK
//! [`Client`](NativeClient).

mod account;
#[cfg(all(test, target_arch = "wasm32"))]
mod e2e_tests;
mod execute;
mod gvk;
mod pool;

use std::{rc::Rc, str::FromStr};

use stellar_private_payments::{
    Account as NativeAccount, BackgroundSyncStop, Client as NativeClient, Error,
    chain::{RpcClient, StateFetcher},
    crypto::derive_asp_user_leaf as derive_asp_user_leaf_native,
    disclosure::verify_disclosure_receipt,
    types::{ContractConfig, DisclosureReceipt, Field, NoteOwnerAddress, NotePublicKey},
};
use wasm_bindgen::prelude::*;

use crate::{
    correlation::{new_correlation_id, with_correlation_id},
    deployment::parse_contract_config,
    models::{
        ContractConfig as JsContractConfig, ContractsStateData, DisclosureVerificationReport,
        OperationalFeedItem, RecipientLookup, VerifyDisclosureOptions, operational_feed_items,
    },
    signer::SignerHandle,
    workers::{ProverHandle, StorageHandle},
};

pub use account::Account;
pub use gvk::GvkAudit;
pub use pool::PrivatePool;

pub(crate) fn pool_err(error: Error) -> JsError {
    use stellar_private_payments::types::AspMembershipSync;

    let cause = match &error {
        Error::PlanExecution(plan) => plan.cause(),
        other => other,
    };
    match cause {
        Error::MembershipSync(AspMembershipSync::RegisterAtASP) => {
            JsError::new("register at ASP before transacting")
        }
        Error::MembershipSync(AspMembershipSync::SyncRequired(_)) => {
            JsError::new("indexer sync in progress; try again shortly")
        }
        _ => JsError::new(&error.to_string()),
    }
}

/// Deployment-scoped browser SDK runtime: native [`NativeClient`] plus worker
/// handles.
#[wasm_bindgen]
pub struct Client {
    inner: NativeClient,
    contract_config: ContractConfig,
    background_sync_stop: Option<BackgroundSyncStop>,
}

#[wasm_bindgen]
impl Client {
    /// Build the client from an already spawned, configured and pinged
    /// prover, and a storage handle.
    #[wasm_bindgen(js_name = new)]
    pub async fn new(
        rpc_url: String,
        storage: &StorageHandle,
        prover: &ProverHandle,
        contract_config: JsValue,
        bootnode_url: Option<String>,
    ) -> Result<Client, JsError> {
        Self::new_inner(rpc_url, storage, prover, contract_config, bootnode_url).await
    }

    #[tracing::instrument(
        name = "web_client_new",
        skip_all,
        fields(correlation_id = %new_correlation_id())
    )]
    async fn new_inner(
        rpc_url: String,
        storage: &StorageHandle,
        prover: &ProverHandle,
        contract_config: JsValue,
        bootnode_url: Option<String>,
    ) -> Result<Client, JsError> {
        crate::wasm_start();

        let contract_config = parse_contract_config(contract_config)?;

        let inner = NativeClient::init(
            rpc_url,
            storage.inner(),
            prover.inner(),
            contract_config.clone(),
            bootnode_url,
        )
        .map_err(pool_err)?;

        Ok(Self {
            inner,
            contract_config,
            background_sync_stop: None,
        })
    }

    /// Deployment config used by this client (contract addresses, pools,
    /// network).
    #[wasm_bindgen(js_name = contractConfig)]
    pub fn contract_config(&self) -> JsContractConfig {
        JsContractConfig::from(self.contract_config.clone())
    }

    /// Start background contract-event sync into local storage.
    ///
    /// No-op if already started on this instance. After
    /// [`Self::stop_background_sync`], call again to respawn. A fatal indexer
    /// exit leaves the slot set — use a new [`Client`] to recover.
    #[wasm_bindgen(js_name = backgroundSync)]
    pub async fn background_sync(&mut self) -> Result<(), JsError> {
        with_correlation_id(new_correlation_id(), async {
            if self.background_sync_stop.is_some() {
                return Ok(());
            }
            let sync = self.inner.background_sync().map_err(pool_err)?;
            self.background_sync_stop = Some(sync.stop_handle());
            wasm_bindgen_futures::spawn_local(async move {
                if let Err(e) = sync.run().await {
                    tracing::error!("background sync stopped: {e}");
                }
            });
            Ok(())
        })
        .await
    }

    /// Request the background indexer to exit (wakes its idle wait).
    ///
    /// Call before rebuilding this [`Client`] so a new instance does not race
    /// the old loop on the same storage DB. Also runs from [`Drop`].
    #[wasm_bindgen(js_name = stopBackgroundSync)]
    pub fn stop_background_sync(&mut self) {
        if let Some(stop) = self.background_sync_stop.take() {
            stop.request();
        }
    }

    /// Bind a wallet signer and return an [`Account`] session.
    ///
    /// `signer` may sign for an account other than the note owner
    /// (`user_address`); that session signs and pays while the owner holds
    /// the notes — build it with the desired `signerAddress` beforehand.
    /// Call [`Account::derive_privacy_keys`] to derive and store the owner's
    /// privacy keys.
    pub async fn account(
        &self,
        user_address: String,
        signer: &SignerHandle,
    ) -> Result<Account, JsError> {
        with_correlation_id(new_correlation_id(), async {
            let native_account = self.open_native_account(signer, user_address)?;
            Ok(Account::new(Rc::new(native_account)))
        })
        .await
    }

    /// Catch local storage up to the current chain tip for the deployment.
    #[wasm_bindgen(js_name = sync)]
    pub async fn sync(&self) -> Result<(), JsError> {
        self.inner.sync().await.map_err(pool_err)
    }

    /// Recent deployment activity (pool events, registry registrations, ASP
    /// updates).
    #[wasm_bindgen(js_name = operationalFeed)]
    pub async fn operational_feed(&self, limit: u32) -> Result<Vec<OperationalFeedItem>, JsError> {
        let feed = self.inner.operational_feed(limit).await.map_err(pool_err)?;
        Ok(operational_feed_items(feed))
    }

    /// Look up a recipient's registered note and encryption public keys.
    #[wasm_bindgen(js_name = recipientLookup)]
    pub async fn recipient_lookup(&self, address: String) -> Result<RecipientLookup, JsError> {
        let lookup = self
            .inner
            .recipient_lookup(&address)
            .await
            .map_err(pool_err)?;
        Ok(RecipientLookup::from(lookup))
    }

    /// On-chain ASP membership and non-membership state.
    #[wasm_bindgen(js_name = aspState)]
    pub async fn asp_state(&self) -> Result<ContractsStateData, JsError> {
        let fetcher = self.state_fetcher()?;
        let data = fetcher
            .asp_state()
            .await
            .map_err(|e| JsError::new(&e.to_string()))?;
        Ok(ContractsStateData::from(data))
    }

    /// On-chain state for all enabled pools plus shared ASP contracts.
    #[wasm_bindgen(js_name = allContractsData)]
    pub async fn all_contracts_data(&self) -> Result<ContractsStateData, JsError> {
        let fetcher = self.state_fetcher()?;
        let data = fetcher
            .all_contracts_data()
            .await
            .map_err(|e| JsError::new(&e.to_string()))?;
        Ok(ContractsStateData::from(data))
    }

    /// Verify a selective-disclosure receipt without a wallet session.
    #[wasm_bindgen(js_name = verifySelectiveDisclosure)]
    pub async fn verify_selective_disclosure(
        &self,
        receipt_json: String,
        expected_vk_hash: String,
    ) -> Result<DisclosureVerificationReport, JsError> {
        let receipt: DisclosureReceipt = serde_json::from_str(&receipt_json)
            .map_err(|e| JsError::new(&format!("invalid receipt JSON: {e}")))?;

        let fetcher = self.state_fetcher()?;
        let report =
            verify_disclosure_receipt(&fetcher, self.inner.prover(), &receipt, &expected_vk_hash)
                .await
                .map_err(pool_err)?;
        Ok(DisclosureVerificationReport::from(report))
    }
}

impl Drop for Client {
    fn drop(&mut self) {
        if let Some(stop) = self.background_sync_stop.take() {
            stop.request();
        }
    }
}

/// Derive the ASP membership tree leaf from explicit public inputs.
#[wasm_bindgen(js_name = deriveAspUserLeaf)]
pub fn derive_asp_user_leaf(
    note_public_key: String,
    membership_blinding: String,
) -> Result<String, JsError> {
    crate::wasm_start();

    let note = NotePublicKey::parse(&note_public_key).map_err(|e| JsError::new(&e.to_string()))?;
    let blinding =
        Field::from_str(&membership_blinding).map_err(|e| JsError::new(&e.to_string()))?;
    let leaf = derive_asp_user_leaf_native(&note, &blinding).map_err(pool_err)?;
    Ok(leaf.to_string())
}

/// Verify a selective-disclosure receipt with no wallet, no local storage,
/// and no [`Client`] instance — just an RPC URL and an already-configured
/// [`ProverHandle`]. Skips the OPFS/SQLite storage worker entirely, since
/// verification never reads local state.
#[wasm_bindgen(js_name = verifySelectiveDisclosure)]
pub async fn verify_selective_disclosure_standalone(
    rpc_url: String,
    prover: &ProverHandle,
    receipt_json: String,
    expected_vk_hash: String,
    options: JsValue,
) -> Result<DisclosureVerificationReport, JsError> {
    with_correlation_id(new_correlation_id(), async {
        crate::wasm_start();

        let receipt: DisclosureReceipt = serde_json::from_str(&receipt_json)
            .map_err(|e| JsError::new(&format!("invalid receipt JSON: {e}")))?;
        let opts = VerifyDisclosureOptions::from_value(options)?;
        let contract_config = opts.contract_config().native().clone();
        let rpc = RpcClient::new(&rpc_url).map_err(|e| JsError::new(&e.to_string()))?;
        let fetcher =
            StateFetcher::new(rpc, contract_config).map_err(|e| JsError::new(&e.to_string()))?;

        let report =
            verify_disclosure_receipt(&fetcher, &prover.inner(), &receipt, &expected_vk_hash)
                .await
                .map_err(pool_err)?;
        Ok(DisclosureVerificationReport::from(report))
    })
    .await
}

impl Client {
    fn state_fetcher(&self) -> Result<StateFetcher, JsError> {
        self.inner
            .state_fetcher()
            .map_err(|e| JsError::new(&e.to_string()))
    }

    fn open_native_account(
        &self,
        signer: &SignerHandle,
        user_address: String,
    ) -> Result<NativeAccount, JsError> {
        self.inner
            .account(NoteOwnerAddress::new(user_address), signer.inner())
            .map_err(pool_err)
    }
}
