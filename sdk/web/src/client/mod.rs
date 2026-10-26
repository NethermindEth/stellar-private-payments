//! Wasm [`Client`] — thin browser wrapper around the native SDK
//! [`Client`](NativeClient).

mod account;
mod execute;
mod gvk;
mod pool;

use std::{rc::Rc, str::FromStr};

use js_sys::Reflect;
use stellar_private_payments::{
    Account as NativeAccount, BackgroundSyncStop, Client as NativeClient, Error,
    chain::{RpcClient, StateFetcher},
    crypto::derive_asp_user_leaf as derive_asp_user_leaf_native,
    disclosure::verify_disclosure_receipt,
    planner::PlanError,
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

    match error.root_cause() {
        Error::MembershipSync(AspMembershipSync::RegisterAtASP) => {
            JsError::new("register at ASP before transacting")
        }
        Error::MembershipSync(AspMembershipSync::SyncRequired(_)) => {
            JsError::new("indexer sync in progress; try again shortly")
        }
        cause => {
            let js_error = JsError::new(&error.to_string());
            if let Some((code, amounts)) = refusal(cause) {
                let value = JsValue::from(js_error.clone());
                let _ = Reflect::set(&value, &"code".into(), &code.into());
                for (key, amount) in &amounts {
                    let _ = Reflect::set(&value, &(*key).into(), &amount.as_str().into());
                }
            }
            js_error
        }
    }
}

/// Returns the code a client reads from an SDK refusal, with the amounts it
/// names as decimal strings of base units.
fn refusal(cause: &Error) -> Option<(&'static str, Vec<(&'static str, String)>)> {
    let refusal = match cause {
        Error::DepositsPaused { .. } => ("DEPOSITS_PAUSED", Vec::new()),
        Error::DepositBelowMinimum { minimum } => (
            "DEPOSIT_BELOW_MINIMUM",
            vec![("minimum", minimum.to_string())],
        ),
        Error::DepositAboveMaximum {
            maximum,
            largest_deposit,
        } => (
            "DEPOSIT_ABOVE_MAXIMUM",
            vec![
                ("maximum", maximum.to_string()),
                ("largestDeposit", largest_deposit.to_string()),
            ],
        ),
        Error::NotBalanced { gap } => ("NOT_BALANCED", vec![("gap", gap.to_string())]),
        _ => match cause.plan_error()? {
            PlanError::NoSpendableNotes => ("NO_SPENDABLE_NOTES", Vec::new()),
            PlanError::NoCombination { max_spend } => {
                ("NO_COMBINATION", vec![("maxSpend", max_spend.to_string())])
            }
            _ => return None,
        },
    };
    Some(refusal)
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
        let report = verify_disclosure_receipt(
            &fetcher,
            self.inner.prover(),
            &receipt,
            &expected_vk_hash,
            None,
            None,
        )
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

        let report = verify_disclosure_receipt(
            &fetcher,
            &prover.inner(),
            &receipt,
            &expected_vk_hash,
            None,
            None,
        )
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

#[cfg(all(test, target_arch = "wasm32"))]
mod tests {
    use super::*;
    use stellar_private_payments::{
        PlanExecutionError,
        planner::SpendSessionError,
        types::{ExtAmount, NoteAmount, TransactionResult},
    };
    use wasm_bindgen_test::*;

    use crate::models::ExecuteOutcome;

    fn property(error: &JsError, key: &str) -> Option<String> {
        Reflect::get(&JsValue::from(error.clone()), &JsValue::from_str(key))
            .ok()
            .and_then(|value| value.as_string())
    }

    fn completed() -> Vec<TransactionResult> {
        vec![TransactionResult {
            tx_hash: "abc".into(),
        }]
    }

    #[wasm_bindgen_test]
    fn a_paused_pool_error_carries_its_code() {
        let error = pool_err(Error::DepositsPaused {
            pool: "CPOOL".into(),
        });
        assert_eq!(property(&error, "code").as_deref(), Some("DEPOSITS_PAUSED"));
    }

    #[wasm_bindgen_test]
    fn a_deposit_below_the_minimum_names_the_minimum() {
        let error = pool_err(Error::DepositBelowMinimum {
            minimum: NoteAmount::from(10_000u128),
        });
        assert_eq!(
            property(&error, "code").as_deref(),
            Some("DEPOSIT_BELOW_MINIMUM")
        );
        assert_eq!(property(&error, "minimum").as_deref(), Some("10000"));
    }

    #[wasm_bindgen_test]
    fn a_deposit_above_the_maximum_names_the_maximum() {
        let error = pool_err(Error::DepositAboveMaximum {
            maximum: ExtAmount::from(1_000_000_000i128),
            largest_deposit: NoteAmount::from(999_000_000u128),
        });
        assert_eq!(
            property(&error, "code").as_deref(),
            Some("DEPOSIT_ABOVE_MAXIMUM")
        );
        assert_eq!(property(&error, "maximum").as_deref(), Some("1000000000"));
        assert_eq!(
            property(&error, "largestDeposit").as_deref(),
            Some("999000000")
        );
        assert_eq!(
            property(&error, "message").as_deref(),
            Some(
                "deposit sends more than the pool maximum of 1000000000 base units, pool fee included"
            )
        );
    }

    #[wasm_bindgen_test]
    fn an_unbalanced_transaction_carries_its_code_and_gap() {
        let error = pool_err(Error::NotBalanced {
            gap: ExtAmount::from(-1_000i128),
        });
        assert_eq!(property(&error, "code").as_deref(), Some("NOT_BALANCED"));
        assert_eq!(property(&error, "gap").as_deref(), Some("-1000"));
        assert_eq!(
            property(&error, "message").as_deref(),
            Some(
                "transaction does not balance: the private outputs, withdrawal and pool fee exceed the input notes and deposit"
            )
        );
    }

    /// An estimate fails bare, a spend through its session, and a later step
    /// under the steps already confirmed.
    #[wasm_bindgen_test]
    fn a_failed_plan_names_the_most_it_can_send() {
        let no_combination = || PlanError::NoCombination {
            max_spend: NoteAmount::from(99_000u128),
        };
        for error in [
            Error::Plan(no_combination()),
            Error::SpendSession(SpendSessionError::Plan(no_combination())),
            PlanExecutionError::into_error(
                completed(),
                Error::SpendSession(SpendSessionError::Plan(no_combination())),
            ),
        ] {
            let error = pool_err(error);
            assert_eq!(property(&error, "code").as_deref(), Some("NO_COMBINATION"));
            assert_eq!(property(&error, "maxSpend").as_deref(), Some("99000"));
        }
    }

    #[wasm_bindgen_test]
    fn an_empty_wallet_has_its_own_code_and_no_amount() {
        for error in [
            Error::Plan(PlanError::NoSpendableNotes),
            Error::SpendSession(SpendSessionError::Plan(PlanError::NoSpendableNotes)),
        ] {
            let error = pool_err(error);
            assert_eq!(
                property(&error, "code").as_deref(),
                Some("NO_SPENDABLE_NOTES")
            );
            assert_eq!(property(&error, "maxSpend"), None);
        }
    }

    /// A refusal before any step confirmed throws its code, and a wallet
    /// rejection resolves with its own. A refusal under a confirmed step
    /// resolves, so the step's hash is kept.
    #[wasm_bindgen_test]
    fn a_flow_throws_a_refusal_only_before_its_first_step() {
        let error = execute::execute_result(ExecuteOutcome::Failed(Error::DepositsPaused {
            pool: "CPOOL".into(),
        }))
        .err()
        .expect("a refusal before any submission throws");
        assert_eq!(property(&error, "code").as_deref(), Some("DEPOSITS_PAUSED"));

        let rejected =
            execute::execute_result(ExecuteOutcome::Failed(Error::UserRejected("stub".into())))
                .expect("a wallet rejection resolves");
        assert_eq!(rejected.code(), Some(-4));

        let no_combination =
            Error::SpendSession(SpendSessionError::Plan(PlanError::NoCombination {
                max_spend: NoteAmount::from(99_000u128),
            }));
        let result = execute::execute_result(ExecuteOutcome::plan(completed(), no_combination))
            .expect("a failure after a confirmed step resolves");
        assert_eq!(result.hashes(), ["abc"]);
    }
}
