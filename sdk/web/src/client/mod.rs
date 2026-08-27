//! Wasm [`Client`] — thin browser wrapper around the native SDK
//! [`Client`](NativeClient).

mod account;
#[cfg(all(test, target_arch = "wasm32"))]
mod e2e_tests;
mod execute;
mod pool;
mod transact;

use std::{rc::Rc, str::FromStr};

use serde::Deserialize;
use stellar_private_payments::{
    Account as NativeAccount, BackgroundSyncStop, Client as NativeClient, Error, Handle,
    chain::{RpcClient, StateFetcher},
    crypto::derive_asp_user_leaf as derive_asp_user_leaf_native,
    disclosure::verify_disclosure_receipt,
    types::{
        DisclosureReceipt, Field, KeyDerivationSignature, NoteOwnerAddress, NotePublicKey,
        SignerAddress,
    },
};
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::JsFuture;

use crate::{
    correlation::{new_correlation_id, with_correlation_id},
    deployment::deployment_config,
    protocol::{StorageWorkerRequest, StorageWorkerResponse},
    signer::{SEP43_USER_REJECTED_CODE, WalletSigner},
    storage::Storage,
    workers::{
        prover::{ProverBridge, ProverWorker},
        storage::StorageBridge,
    },
};
use gloo_worker::Spawnable;

pub use account::Account;
pub use pool::PrivatePool;

/// Set `code` on a JsError so it survives the wasm boundary without relying
/// on message wording — the same pattern sdk/web/src/signer.rs uses for
/// wallet-side errors it builds directly.
fn js_error_with_code(message: &str, code: f64) -> JsError {
    let err = JsError::new(message);
    let value = JsValue::from(err.clone());
    let _ = js_sys::Reflect::set(&value, &JsValue::from_str("code"), &JsValue::from_f64(code));
    err
}

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
        // Without this, pool_err's fallback rebuilds a bare JsError from
        // Display alone, so cancellation detection on the JS side has
        // nothing but the message text to go on — carry the SEP-0043 code
        // through explicitly instead, matching cause (not error) so a
        // rejection wrapped inside Error::PlanExecution is caught here too.
        Error::UserRejected(_) => js_error_with_code(&cause.to_string(), SEP43_USER_REJECTED_CODE),
        _ => JsError::new(&error.to_string()),
    }
}

pub(crate) fn pool_err_message(error: Error) -> String {
    match &error {
        Error::PlanExecution(plan) => plan.cause().to_string(),
        other => other.to_string(),
    }
}

/// Deployment-scoped browser SDK runtime: native [`NativeClient`] plus worker
/// handles.
#[wasm_bindgen]
pub struct Client {
    storage: Storage,
    inner: NativeClient<StorageBridge>,
    prover: ProverBridge,
    background_sync_stop: Option<BackgroundSyncStop>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct AccountOptions {
    network_passphrase: String,
    user_address: Option<String>,
    /// The account that signs and pays. Optional; defaults to `user_address`.
    signer_address: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
struct VerifyDisclosureOptions {
    prover_worker_url: Option<String>,
}

#[wasm_bindgen]
impl Client {
    /// Build the client and spawn the prover worker
    #[wasm_bindgen(js_name = new)]
    pub async fn new(
        rpc_url: String,
        storage: &Storage,
        prover_worker_url: String,
        bootnode_url: Option<String>,
    ) -> Result<Client, JsError> {
        Self::new_inner(rpc_url, storage, prover_worker_url, bootnode_url).await
    }

    #[tracing::instrument(
        name = "web_client_new",
        skip_all,
        fields(correlation_id = %new_correlation_id())
    )]
    async fn new_inner(
        rpc_url: String,
        storage: &Storage,
        prover_worker_url: String,
        bootnode_url: Option<String>,
    ) -> Result<Client, JsError> {
        crate::wasm_start();

        if prover_worker_url.trim().is_empty() {
            return Err(JsError::new(
                "proverWorkerUrl is required (absolute URL to prover-worker.js)",
            ));
        }

        let storage = storage.fork();
        let storage_bridge = storage.bridge();
        storage_bridge
            .ping()
            .await
            .map_err(|e| JsError::new(&e.to_string()))?;

        let contract_config = deployment_config()?;
        let prover = ProverBridge::new(
            ProverWorker::spawner()
                .with_loader(true)
                .as_module(true)
                .spawn(&prover_worker_url),
        );
        let prover_handle: Handle<dyn stellar_private_payments::Prover> =
            Handle::from_box(Box::new(prover.clone()) as Box<dyn stellar_private_payments::Prover>);

        let inner = NativeClient::init(
            rpc_url,
            storage_bridge,
            prover_handle,
            (*contract_config).clone(),
            bootnode_url,
        )
        .map_err(pool_err)?;

        // Let telemetry config pushes and log dumps reach the worker isolates.
        crate::telemetry::register_worker_sinks(Some(storage.bridge()), Some(prover.clone()));

        Ok(Self {
            storage,
            inner,
            prover,
            background_sync_stop: None,
        })
    }

    /// Bundled deployment config (contract addresses, pools, network).
    #[wasm_bindgen(js_name = contractConfig)]
    pub fn contract_config() -> Result<JsValue, JsError> {
        Ok(serde_wasm_bindgen::to_value(deployment_config()?)?)
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

    /// Bind a wallet signer, derive privacy keys when missing, and return an
    /// [`Account`] session.
    pub async fn account(&self, options: JsValue, signer: JsValue) -> Result<Account, JsError> {
        with_correlation_id(new_correlation_id(), async {
            let opts: AccountOptions = serde_wasm_bindgen::from_value(options)?;
            let user_address = resolve_user_address(&signer, opts.user_address).await?;
            // Defaults to the note owner. The wallet signs with this account.
            let signer_address =
                SignerAddress::new(opts.signer_address.unwrap_or_else(|| user_address.clone()));
            let wallet_signer = WalletSigner::new(signer, opts.network_passphrase, signer_address)?;

            self.ensure_prover().await?;

            // Bind the storage worker before anything touches key material.
            // The existence probe, the derivation, and every later call the
            // returned Account makes are served by the worker only while this
            // account is the bound one - see
            // StorageWorkerRequest::requires_bound_session.
            self.bind_storage_session(&user_address).await?;

            // A session that fails to open must not leave the worker bound to
            // its account: a refused configuration would otherwise still have
            // handed the page the capability it was denied.
            match self.open_bound_session(wallet_signer, user_address).await {
                Ok(account) => Ok(account),
                Err(e) => {
                    // The release is best-effort. If it fails the binding
                    // outlives the failed open, which grants nothing on its
                    // own - the privileged requests are unreachable without an
                    // Account - but the original error is what the caller
                    // needs to see, so it is not replaced by this one.
                    let _ = self.release_storage_session().await;
                    Err(e)
                }
            }
        })
        .await
    }

    /// Derive keys if this is the account's first session, then open it.
    ///
    /// Split out of [`Self::account`] so that every failure between binding
    /// the storage worker and holding a usable [`Account`] flows through one
    /// place, where the binding can be released.
    async fn open_bound_session(
        &self,
        wallet_signer: WalletSigner,
        user_address: String,
    ) -> Result<Account, JsError> {
        if !self.user_keys_exist(&user_address).await? {
            // Before the wallet is asked for anything: refuse to derive
            // one account's privacy keys from another account's
            // signature. See ensure_derivation_identity.
            ensure_derivation_identity(&user_address, wallet_signer.signer_address())?;
            let message =
                stellar_private_payments::zk::encryption::KEY_DERIVATION_MESSAGE.to_string();
            let sig_hex = wallet_signer.sign_wallet_message(&message).await?;
            let signature = crate::signer::wallet_message_signature_to_bytes(&sig_hex)?;
            self.derive_save_user_keys(user_address.clone(), signature)
                .await?;
        }

        Ok(Account::new(Rc::new(
            self.open_native_account(wallet_signer, user_address)?,
        )))
    }

    /// Release the storage worker's session binding.
    ///
    /// Call on disconnect. This revokes the capability to read or write this
    /// account's privacy keys; it deliberately does not delete anything, so
    /// reconnecting restores the session rather than re-onboarding it.
    #[wasm_bindgen(js_name = releaseStorageSession)]
    pub async fn release_storage_session_js(&self) -> Result<(), JsError> {
        self.release_storage_session().await
    }

    /// Catch local storage up to the current chain tip for the deployment.
    #[wasm_bindgen(js_name = sync)]
    pub async fn sync(&self) -> Result<(), JsError> {
        self.inner.sync().await.map_err(pool_err)
    }

    /// Recent deployment activity (pool events, registry registrations, ASP
    /// updates).
    #[wasm_bindgen(js_name = operationalFeed)]
    pub async fn operational_feed(&self, limit: u32) -> Result<JsValue, JsError> {
        let feed = self.inner.operational_feed(limit).await.map_err(pool_err)?;
        Ok(serde_wasm_bindgen::to_value(&feed)?)
    }

    /// Look up a recipient's registered note and encryption public keys.
    #[wasm_bindgen(js_name = recipientLookup)]
    pub async fn recipient_lookup(&self, address: String) -> Result<JsValue, JsError> {
        let lookup = self
            .inner
            .recipient_lookup(&address)
            .await
            .map_err(pool_err)?;
        Ok(serde_wasm_bindgen::to_value(&lookup)?)
    }

    /// On-chain ASP membership and non-membership state.
    #[wasm_bindgen(js_name = aspState)]
    pub async fn asp_state(&self) -> Result<JsValue, JsError> {
        let fetcher = self.state_fetcher()?;
        let data = fetcher
            .asp_state()
            .await
            .map_err(|e| JsError::new(&e.to_string()))?;
        Ok(serde_wasm_bindgen::to_value(&data)?)
    }

    /// On-chain state for all enabled pools plus shared ASP contracts.
    #[wasm_bindgen(js_name = allContractsData)]
    pub async fn all_contracts_data(&self) -> Result<JsValue, JsError> {
        let fetcher = self.state_fetcher()?;
        let data = fetcher
            .all_contracts_data()
            .await
            .map_err(|e| JsError::new(&e.to_string()))?;
        Ok(serde_wasm_bindgen::to_value(&data)?)
    }

    /// Verify a selective-disclosure receipt without a wallet session.
    #[wasm_bindgen(js_name = verifySelectiveDisclosure)]
    pub async fn verify_selective_disclosure(
        &self,
        receipt_json: String,
        expected_vk_hash: String,
    ) -> Result<JsValue, JsError> {
        let receipt: DisclosureReceipt = serde_json::from_str(&receipt_json)
            .map_err(|e| JsError::new(&format!("invalid receipt JSON: {e}")))?;

        self.ensure_prover().await?;
        let fetcher = self.state_fetcher()?;
        let report = verify_disclosure_receipt(&fetcher, &self.prover, &receipt, &expected_vk_hash)
            .await
            .map_err(pool_err)?;
        Ok(serde_wasm_bindgen::to_value(&report)?)
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
/// and no [`Client`] instance — just an RPC URL. Skips the OPFS/SQLite
/// storage worker entirely, since verification never reads local state.
#[wasm_bindgen(js_name = verifySelectiveDisclosure)]
pub async fn verify_selective_disclosure_standalone(
    rpc_url: String,
    receipt_json: String,
    expected_vk_hash: String,
    options: JsValue,
) -> Result<JsValue, JsError> {
    with_correlation_id(new_correlation_id(), async {
        crate::wasm_start();

        let receipt: DisclosureReceipt = serde_json::from_str(&receipt_json)
            .map_err(|e| JsError::new(&format!("invalid receipt JSON: {e}")))?;
        let opts: VerifyDisclosureOptions = if options.is_null() || options.is_undefined() {
            VerifyDisclosureOptions::default()
        } else {
            serde_wasm_bindgen::from_value(options)?
        };

        let prover_worker_url = opts
            .prover_worker_url
            .filter(|url| !url.trim().is_empty())
            .ok_or_else(|| {
                JsError::new("proverWorkerUrl is required (absolute URL to prover-worker.js)")
            })?;

        let contract_config = deployment_config()?;
        let rpc = RpcClient::new(&rpc_url).map_err(|e| JsError::new(&e.to_string()))?;
        let fetcher = StateFetcher::new(rpc, (*contract_config).clone())
            .map_err(|e| JsError::new(&e.to_string()))?;
        let prover = ProverBridge::new(
            ProverWorker::spawner()
                .with_loader(true)
                .as_module(true)
                .spawn(&prover_worker_url),
        );
        prover
            .ping()
            .await
            .map_err(|e| JsError::new(&format!("failed to load prover: {e:?}")))?;

        let report = verify_disclosure_receipt(&fetcher, &prover, &receipt, &expected_vk_hash)
            .await
            .map_err(pool_err)?;
        Ok(serde_wasm_bindgen::to_value(&report)?)
    })
    .await
}

impl Client {
    fn state_fetcher(&self) -> Result<StateFetcher, JsError> {
        self.inner
            .state_fetcher()
            .map_err(|e| JsError::new(&e.to_string()))
    }

    async fn ensure_prover(&self) -> Result<(), JsError> {
        self.prover
            .ping()
            .await
            .map_err(|e| JsError::new(&format!("failed to load prover: {e:?}")))
    }

    fn open_native_account(
        &self,
        wallet_signer: WalletSigner,
        user_address: String,
    ) -> Result<NativeAccount<StorageBridge>, JsError> {
        // Read back off the signer rather than from AccountOptions: this is the
        // address the wallet will actually be asked to sign with, so it is the
        // one the native client must validate.
        let signer_address = wallet_signer.signer_address().clone();
        let signer: Handle<dyn stellar_private_payments::Signer> =
            Handle::from_box(Box::new(wallet_signer) as Box<dyn stellar_private_payments::Signer>);
        self.inner
            .account(NoteOwnerAddress::new(user_address), signer_address, signer)
            .map_err(pool_err)
    }

    async fn user_keys_exist(&self, address: &str) -> Result<bool, JsError> {
        let req = StorageWorkerRequest::UserKeys(address.to_string());
        match self.storage_request(req, 1_000).await? {
            StorageWorkerResponse::UserKeys(Some(_)) => Ok(true),
            StorageWorkerResponse::UserKeys(None) => Ok(false),
            other => Err(JsError::new(&format!("unexpected response: {other:?}"))),
        }
    }

    async fn bind_storage_session(&self, address: &str) -> Result<(), JsError> {
        let req = StorageWorkerRequest::BindSession(address.to_string());
        match self.storage_request(req, 2_000).await? {
            StorageWorkerResponse::Saved => Ok(()),
            other => Err(JsError::new(&format!("unexpected response: {other:?}"))),
        }
    }

    async fn release_storage_session(&self) -> Result<(), JsError> {
        match self
            .storage_request(StorageWorkerRequest::UnbindSession, 2_000)
            .await?
        {
            StorageWorkerResponse::Saved => Ok(()),
            other => Err(JsError::new(&format!("unexpected response: {other:?}"))),
        }
    }

    async fn derive_save_user_keys(
        &self,
        address: String,
        signature: Vec<u8>,
    ) -> Result<(), JsError> {
        let config = deployment_config()?;
        let req = StorageWorkerRequest::DeriveSaveUserKeys(
            address,
            KeyDerivationSignature(signature),
            config.network.clone(),
        );
        match self.storage_request(req, 5_000).await? {
            StorageWorkerResponse::Saved => Ok(()),
            other => Err(JsError::new(&format!("unexpected response: {other:?}"))),
        }
    }

    async fn storage_request(
        &self,
        req: StorageWorkerRequest,
        timeout_ms: u32,
    ) -> Result<StorageWorkerResponse, JsError> {
        self.storage
            .bridge()
            .call(req, timeout_ms)
            .await
            .map_err(|e| JsError::new(&format!("storage worker error: {e}")))
    }
}

/// Refuse to derive one account's privacy keys from another account's
/// signature.
///
/// Derivation signs [`KEY_DERIVATION_MESSAGE`] with `signerAddress` and files
/// the result under `userAddress`. If those differ, the owner's keys are a
/// function of a delegate's signature and nothing downstream can tell. What
/// should happen instead is an open design question; this only makes the case
/// loud rather than silent.
///
/// Runs before the wallet is prompted, so a rejected configuration costs no
/// signature request.
///
/// [`KEY_DERIVATION_MESSAGE`]: stellar_private_payments::KEY_DERIVATION_MESSAGE
fn ensure_derivation_identity(
    user_address: &str,
    signer_address: &SignerAddress,
) -> Result<(), JsError> {
    if signer_address.as_str() == user_address {
        return Ok(());
    }
    Err(JsError::new(&format!(
        "refusing to derive privacy keys for {user_address} from a signature by \
         {signer_address}: userAddress and signerAddress must be the same account \
         the first time keys are derived",
    )))
}

async fn resolve_user_address(
    signer: &JsValue,
    options_address: Option<String>,
) -> Result<String, JsError> {
    if let Some(addr) = options_address {
        return Ok(addr);
    }

    let get_pk = js_sys::Reflect::get(signer, &JsValue::from_str("getPublicKey"))
        .map_err(|_| JsError::new("userAddress required or signer.getPublicKey"))?;
    if !get_pk.is_function() {
        return Err(JsError::new(
            "userAddress required or signer must implement getPublicKey",
        ));
    }

    let func = get_pk.dyn_ref::<js_sys::Function>().ok_or_else(|| {
        JsError::new("userAddress required or signer must implement getPublicKey")
    })?;

    let value = func
        .call0(signer)
        .map_err(|_| JsError::new("getPublicKey failed"))?;

    let resolved = if value.is_instance_of::<js_sys::Promise>() {
        JsFuture::from(
            value
                .dyn_into::<js_sys::Promise>()
                .map_err(|_| JsError::new("getPublicKey failed"))?,
        )
        .await
        .map_err(|_| JsError::new("getPublicKey failed"))?
    } else {
        value
    };

    resolved
        .as_string()
        .ok_or_else(|| JsError::new("getPublicKey did not return a string"))
}

/// Acceptance tests for [`pool_err`]'s coded and uncoded paths.
#[cfg(all(test, target_arch = "wasm32"))]
mod pool_err_tests {
    #![allow(clippy::unwrap_used)]

    use super::*;
    use wasm_bindgen_test::*;

    fn code_of(error: &JsError) -> Option<f64> {
        js_sys::Reflect::get(&JsValue::from(error.clone()), &JsValue::from_str("code"))
            .ok()
            .and_then(|code| code.as_f64())
    }

    #[wasm_bindgen_test]
    fn pool_err_carries_the_sep43_code_for_a_user_rejection() {
        let error = pool_err(Error::UserRejected("stub decline".to_string()));
        assert_eq!(
            code_of(&error),
            Some(SEP43_USER_REJECTED_CODE),
            "a rejection crossing the wasm boundary via pool_err must carry \
             the SEP-0043 code, not rely on the JS side substring-matching \
             the message"
        );
        let message = js_sys::Reflect::get(&JsValue::from(error), &JsValue::from_str("message"))
            .unwrap()
            .as_string()
            .unwrap();
        assert!(
            message.contains("stub decline"),
            "the wallet's own rejection message must still be preserved: {message}"
        );
    }

    #[wasm_bindgen_test]
    fn pool_err_leaves_other_errors_uncoded() {
        let error = pool_err(Error::Other("some other failure".to_string()));
        assert_eq!(
            code_of(&error),
            None,
            "only a genuine SEP-0043 rejection should carry code -4"
        );
    }
}

/// Acceptance tests for [`ensure_derivation_identity`].
#[cfg(all(test, target_arch = "wasm32"))]
mod derivation_identity_tests {
    #![allow(clippy::unwrap_used)]

    use super::*;
    use wasm_bindgen_test::*;

    const OWNER: &str = "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF";
    const DELEGATE: &str = "GBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB6BQ";

    fn message_of(error: &JsError) -> String {
        js_sys::Reflect::get(&JsValue::from(error.clone()), &JsValue::from_str("message"))
            .unwrap()
            .as_string()
            .unwrap()
    }

    #[wasm_bindgen_test]
    fn derivation_is_allowed_when_the_owner_signs_for_itself() {
        // The only configuration any caller uses today, and the one the
        // signerAddress default produces.
        assert!(ensure_derivation_identity(OWNER, &SignerAddress::new(OWNER)).is_ok());
    }

    #[wasm_bindgen_test]
    fn derivation_is_refused_when_a_delegate_signs_for_the_owner() {
        let error = ensure_derivation_identity(OWNER, &SignerAddress::new(DELEGATE))
            .expect_err("keys for one account must not be derived from another's signature");
        let message = message_of(&error);
        assert!(
            message.contains(OWNER) && message.contains(DELEGATE),
            "the refusal must name both identities so the caller can see which \
             pair was rejected: {message}"
        );
    }

    #[wasm_bindgen_test]
    fn the_comparison_is_exact() {
        // Guards against anyone later "helpfully" relaxing this to a prefix,
        // case-insensitive, or trimmed comparison. Strkeys are exact.
        let mut lowercased = OWNER.to_ascii_lowercase();
        assert!(
            ensure_derivation_identity(OWNER, &SignerAddress::new(lowercased.as_str())).is_err()
        );
        lowercased = format!(" {OWNER}");
        assert!(
            ensure_derivation_identity(OWNER, &SignerAddress::new(lowercased.as_str())).is_err()
        );
        assert!(ensure_derivation_identity(OWNER, &SignerAddress::new("")).is_err());
    }
}
