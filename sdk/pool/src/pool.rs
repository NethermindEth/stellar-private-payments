//! Per-pool private payments API.

use prover::notes::try_decrypt_and_derive_user_note;
use state::{
    AccountKeys, DerivedUserNoteRow, PoolCommitmentRow, Storage, process_events, process_notes,
};
use tx_planner::{SpendSession, SpendTarget, SpendableNote, Transact};
use types::{ExtAmount, NoteAmount};

use crate::{
    PreparedTransaction,
    error::PoolError,
    plan::PreparedTransactionPlan,
    prover::ProverEngine,
    transact::{
        BuildTransactParams, TransactRequest, build_transact_params, load_user_key_material,
        transact_request_from_step,
    },
    types::{
        Estimate, PrivatePoolConfig, SignedTransaction, SyncResult, TransactChainContext,
        TransactionResult, TransferRecipient,
    },
};

#[cfg(not(target_arch = "wasm32"))]
use crate::indexer::Indexer;

#[cfg(not(target_arch = "wasm32"))]
use stellar::blocking::{Client as BlockingClient, StateFetcher, confirm_tx, submit_tx};
#[cfg(not(target_arch = "wasm32"))]
use stellar::{Limits, PoolTransactInput, ReadXdr, TransactionEnvelope, TxConfirmStatus};

use types::{AspNonMembershipProof, ContractsStateData, SMT_DEPTH};

#[cfg(target_arch = "wasm32")]
use crate::wasm_indexer::{SharedStorage, WasmPoolState};

#[cfg(target_arch = "wasm32")]
use stellar::{
    Client, Indexer as AsyncIndexer, Limits, PoolTransactInput, ReadXdr, StateFetcher,
    TransactionEnvelope, TxConfirmStatus, confirm_tx, submit_tx,
};

/// Main entry point for a single privacy pool.
pub struct PrivatePool {
    config: PrivatePoolConfig,
    #[cfg(not(target_arch = "wasm32"))]
    indexer: Option<Indexer>,
    #[cfg(target_arch = "wasm32")]
    wasm_state: Option<WasmPoolState>,
    prover: Option<ProverEngine>,
    chain: Option<TransactChainContext>,
}

impl PrivatePool {
    pub fn new(config: PrivatePoolConfig) -> Result<Self, PoolError> {
        if config.pool_contract_id.is_empty() {
            return Err(PoolError::InvalidConfig(
                "pool_contract_id must not be empty".into(),
            ));
        }
        if config.user_address.is_empty() {
            return Err(PoolError::InvalidConfig(
                "user_address must not be empty".into(),
            ));
        }
        Ok(Self {
            config,
            #[cfg(not(target_arch = "wasm32"))]
            indexer: None,
            #[cfg(target_arch = "wasm32")]
            wasm_state: None,
            prover: None,
            chain: None,
        })
    }

    pub fn initialize(&mut self) -> Result<(), PoolError> {
        #[cfg(not(target_arch = "wasm32"))]
        {
            let storage = Storage::connect_file(&self.config.storage_path)
                .map_err(|e| PoolError::Other(format!("open storage: {e:#}")))?;
            self.indexer = Some(
                Indexer::new(&self.config.rpc_url, storage, &self.config.contract_config)
                    .map_err(|e| PoolError::Other(format!("open indexer: {e:#}")))?,
            );
        }
        #[cfg(target_arch = "wasm32")]
        {
            let storage = Storage::connect_file(&self.config.storage_path)
                .map_err(|e| PoolError::Other(format!("open storage: {e:#}")))?;
            self.wasm_state = Some(WasmPoolState {
                storage: std::rc::Rc::new(std::cell::RefCell::new(storage)),
                indexer: None,
            });
        }
        Ok(())
    }

    /// Fetch on-chain events, refresh local pool state, and update chain
    /// snapshot.
    #[cfg(not(target_arch = "wasm32"))]
    pub fn sync(&mut self) -> Result<SyncResult, PoolError> {
        let indexer = self.indexer.as_mut().ok_or(PoolError::NotInitialized)?;
        let from_ledger = indexer
            .storage()
            .get_sync_metadata()
            .map_err(|e| PoolError::Other(e.to_string()))?
            .into_iter()
            .map(|meta| meta.last_indexed_ledger)
            .min()
            .unwrap_or(0);

        while indexer
            .fetch_contract_events()
            .map_err(|e| PoolError::Other(format!("fetch events: {e:#}")))?
        {}

        process_local_state(indexer.storage_mut())?;
        self.refresh_chain_context()?;

        let to_ledger = self
            .indexer
            .as_ref()
            .ok_or(PoolError::NotInitialized)?
            .storage()
            .get_sync_metadata()
            .map_err(|e| PoolError::Other(e.to_string()))?
            .into_iter()
            .map(|meta| meta.last_indexed_ledger)
            .max()
            .unwrap_or(from_ledger);

        Ok(SyncResult {
            from_ledger,
            to_ledger,
            new_commitments: 0,
            new_nullifiers: 0,
            new_membership_leaves: 0,
        })
    }

    #[cfg(target_arch = "wasm32")]
    pub async fn sync(&mut self) -> Result<SyncResult, PoolError> {
        let from_ledger = self
            .wasm_state
            .as_ref()
            .ok_or(PoolError::NotInitialized)?
            .storage
            .borrow()
            .get_sync_metadata()
            .map_err(|e| PoolError::Other(e.to_string()))?
            .into_iter()
            .map(|meta| meta.last_indexed_ledger)
            .min()
            .unwrap_or(0);

        {
            let wasm = self.wasm_state.as_mut().ok_or(PoolError::NotInitialized)?;

            if wasm.indexer.is_none() {
                let shared = SharedStorage(std::rc::Rc::clone(&wasm.storage));
                wasm.indexer = Some(
                    AsyncIndexer::init(&self.config.rpc_url, shared, &self.config.contract_config)
                        .await
                        .map_err(|e| PoolError::Other(format!("open indexer: {e:#}")))?,
                );
            }

            let indexer = wasm.indexer.as_ref().expect("indexer initialized");
            while indexer
                .fetch_contract_events()
                .await
                .map_err(|e| PoolError::Other(format!("fetch events: {e:#}")))?
            {}

            process_local_state(&mut *wasm.storage.borrow_mut())?;
        }

        self.refresh_chain_context().await?;

        let to_ledger = self
            .wasm_state
            .as_ref()
            .ok_or(PoolError::NotInitialized)?
            .storage
            .borrow()
            .get_sync_metadata()
            .map_err(|e| PoolError::Other(e.to_string()))?
            .into_iter()
            .map(|meta| meta.last_indexed_ledger)
            .max()
            .unwrap_or(from_ledger);

        Ok(SyncResult {
            from_ledger,
            to_ledger,
            new_commitments: 0,
            new_nullifiers: 0,
            new_membership_leaves: 0,
        })
    }

    /// Chain snapshot from the last successful [`Self::sync`].
    pub fn chain_context(&self) -> Result<&TransactChainContext, PoolError> {
        self.chain.as_ref().ok_or(PoolError::NotSynced)
    }

    /// Install chain snapshot without RPC (tests / offline wallets).
    pub fn set_chain_context(&mut self, chain: TransactChainContext) {
        self.chain = Some(chain);
    }

    pub fn get_balance(&self) -> Result<NoteAmount, PoolError> {
        let notes = self.spendable_wallet()?;
        let balance = notes.iter().fold(NoteAmount::ZERO, |mut acc, note| {
            acc += note.amount;
            acc
        });
        Ok(balance)
    }

    pub fn prepare_deposit(
        &mut self,
        amount: NoteAmount,
    ) -> Result<PreparedTransactionPlan, PoolError> {
        if amount.is_zero() {
            return Err(PoolError::InvalidConfig("amount must be > 0".into()));
        }
        Ok(PreparedTransactionPlan::deposit(amount))
    }

    pub fn prepare_transfer(
        &mut self,
        recipient: TransferRecipient,
        amount: NoteAmount,
    ) -> Result<PreparedTransactionPlan, PoolError> {
        if amount.is_zero() {
            return Err(PoolError::InvalidConfig("amount must be > 0".into()));
        }
        let wallet = self.spendable_wallet()?;
        let session = SpendSession::setup(
            wallet,
            amount,
            self.config.pool_contract_id.clone(),
            SpendTarget::transfer(recipient.note_public_key, recipient.encryption_public_key),
        )?;
        PreparedTransactionPlan::from_session(session).map_err(PoolError::from)
    }

    pub fn prepare_withdraw(
        &mut self,
        amount: NoteAmount,
    ) -> Result<PreparedTransactionPlan, PoolError> {
        if amount.is_zero() {
            return Err(PoolError::InvalidConfig("amount must be > 0".into()));
        }
        let wallet = self.spendable_wallet()?;
        let session = SpendSession::setup(
            wallet,
            amount,
            self.config.pool_contract_id.clone(),
            SpendTarget::withdraw(self.config.user_address.clone()),
        )?;
        PreparedTransactionPlan::from_session(session).map_err(PoolError::from)
    }

    pub fn estimate(&self, amount: NoteAmount) -> Result<Estimate, PoolError> {
        let wallet = self.spendable_wallet()?;
        let plan = tx_planner::plan(amount, &wallet)?;
        Ok(Estimate {
            tx_count: u32::try_from(plan.len()).unwrap_or(u32::MAX),
        })
    }

    /// Build witness inputs from local storage and produce a Groth16 proof.
    pub fn prepare_transact(
        &mut self,
        req: TransactRequest,
    ) -> Result<PreparedTransaction, PoolError> {
        let params = {
            #[cfg(not(target_arch = "wasm32"))]
            {
                let storage = self.storage()?;
                match build_transact_params(storage, &req)
                    .map_err(|e| PoolError::Other(e.to_string()))?
                {
                    BuildTransactParams::Ready(params) => params,
                    BuildTransactParams::MembershipSync(status) => {
                        return Err(PoolError::MembershipSync(status));
                    }
                }
            }
            #[cfg(target_arch = "wasm32")]
            {
                let wasm = self.wasm_state.as_ref().ok_or(PoolError::NotInitialized)?;
                let storage = wasm.storage.borrow();
                match build_transact_params(&storage, &req)
                    .map_err(|e| PoolError::Other(e.to_string()))?
                {
                    BuildTransactParams::Ready(params) => params,
                    BuildTransactParams::MembershipSync(status) => {
                        return Err(PoolError::MembershipSync(status));
                    }
                }
            }
        };

        self.ensure_prover()?;

        self.prover()?
            .prove_transact(params)
            .map_err(|e| PoolError::Other(format!("prove: {e:#}")))
    }

    /// Prove the current plan step, advance the plan, and return the prepared
    /// transaction.
    pub fn next_prepared_transaction(
        &mut self,
        plan: &mut PreparedTransactionPlan,
    ) -> Result<PreparedTransaction, PoolError> {
        if plan.is_complete() {
            return Err(PoolError::Other("transaction plan is complete".into()));
        }

        let chain = self.chain_context()?;
        let step = self.transact_step_for_plan(plan)?;
        let req = transact_request_from_step(
            &step,
            &self.config.user_address,
            &self.config.pool_contract_id,
            chain,
        );

        let prepared = self.prepare_transact(req)?;
        let output_commitments = prepared.prepared.output_commitments;
        plan.finish_proved_tx(&output_commitments)?;

        Ok(prepared)
    }

    /// Simulate the pool `transact` invocation and fill
    /// [`PreparedTransaction::soroban_tx`] with unsigned XDR and auth
    /// entries for signing.
    #[cfg(not(target_arch = "wasm32"))]
    pub fn simulate(&self, prepared: &mut PreparedTransaction) -> Result<(), PoolError> {
        let fetcher = StateFetcher::new(&self.config.rpc_url, self.config.contract_config.clone())
            .map_err(|e| PoolError::Other(format!("state fetcher: {e:#}")))?;

        prepared.soroban_tx = fetcher
            .prepare_pool_transact(
                &self.config.pool_contract_id,
                &pool_transact_input(prepared),
                &self.config.user_address,
            )
            .map_err(|e| PoolError::Other(format!("simulate transaction: {e:#}")))?;

        Ok(())
    }

    /// Simulate the pool `transact` invocation and fill
    /// [`PreparedTransaction::soroban_tx`] with unsigned XDR and auth
    /// entries for signing.
    #[cfg(target_arch = "wasm32")]
    pub async fn simulate(&self, prepared: &mut PreparedTransaction) -> Result<(), PoolError> {
        let fetcher = StateFetcher::new(&self.config.rpc_url, self.config.contract_config.clone())
            .map_err(|e| PoolError::Other(format!("state fetcher: {e:#}")))?;

        prepared.soroban_tx = fetcher
            .prepare_pool_transact(
                &self.config.pool_contract_id,
                &pool_transact_input(prepared),
                &self.config.user_address,
            )
            .await
            .map_err(|e| PoolError::Other(format!("simulate transaction: {e:#}")))?;

        Ok(())
    }

    pub fn config(&self) -> &PrivatePoolConfig {
        &self.config
    }

    #[cfg(not(target_arch = "wasm32"))]
    pub fn submit(&mut self, signed_tx: SignedTransaction) -> Result<TransactionResult, PoolError> {
        const CONFIRM_POLL_ATTEMPTS: u32 = 30;
        const CONFIRM_POLL_INTERVAL: std::time::Duration = std::time::Duration::from_secs(1);

        let envelope = TransactionEnvelope::from_xdr_base64(&signed_tx.signed_xdr, Limits::none())
            .map_err(|e| PoolError::Other(format!("invalid signed transaction xdr: {e}")))?;

        let rpc = BlockingClient::new(&self.config.rpc_url)
            .map_err(|e| PoolError::Other(format!("rpc client: {e:#}")))?;

        let hash = submit_tx(&envelope, &rpc)
            .map_err(|e| PoolError::Other(format!("submit transaction: {e:#}")))?;

        for attempt in 1..=CONFIRM_POLL_ATTEMPTS {
            if attempt > 1 {
                std::thread::sleep(CONFIRM_POLL_INTERVAL);
            }
            match confirm_tx(&hash, &rpc)
                .map_err(|e| PoolError::Other(format!("confirm transaction: {e:#}")))?
            {
                TxConfirmStatus::Success => return Ok(TransactionResult { tx_hash: hash }),
                TxConfirmStatus::Failed { detail } => {
                    return Err(PoolError::Other(format!("transaction failed{detail}")));
                }
                TxConfirmStatus::Pending if attempt == CONFIRM_POLL_ATTEMPTS => {
                    return Err(PoolError::Other(format!(
                        "transaction confirmation timed out after 30s (hash: {hash})"
                    )));
                }
                TxConfirmStatus::Pending => {}
            }
        }

        Err(PoolError::Other(format!(
            "transaction confirmation failed (hash: {hash})"
        )))
    }

    #[cfg(target_arch = "wasm32")]
    pub async fn submit(
        &mut self,
        signed_tx: SignedTransaction,
    ) -> Result<TransactionResult, PoolError> {
        use gloo_timers::future::TimeoutFuture;

        const CONFIRM_POLL_ATTEMPTS: u32 = 30;
        const CONFIRM_POLL_INTERVAL_MS: u32 = 1_000;

        let envelope = TransactionEnvelope::from_xdr_base64(&signed_tx.signed_xdr, Limits::none())
            .map_err(|e| PoolError::Other(format!("invalid signed transaction xdr: {e}")))?;

        let rpc = Client::new(&self.config.rpc_url)
            .map_err(|e| PoolError::Other(format!("rpc client: {e:#}")))?;

        let hash = submit_tx(&envelope, &rpc)
            .await
            .map_err(|e| PoolError::Other(format!("submit transaction: {e:#}")))?;

        for attempt in 1..=CONFIRM_POLL_ATTEMPTS {
            if attempt > 1 {
                TimeoutFuture::new(CONFIRM_POLL_INTERVAL_MS).await;
            }
            match confirm_tx(&hash, &rpc)
                .await
                .map_err(|e| PoolError::Other(format!("confirm transaction: {e:#}")))?
            {
                TxConfirmStatus::Success => return Ok(TransactionResult { tx_hash: hash }),
                TxConfirmStatus::Failed { detail } => {
                    return Err(PoolError::Other(format!("transaction failed{detail}")));
                }
                TxConfirmStatus::Pending if attempt == CONFIRM_POLL_ATTEMPTS => {
                    return Err(PoolError::Other(format!(
                        "transaction confirmation timed out after 30s (hash: {hash})"
                    )));
                }
                TxConfirmStatus::Pending => {}
            }
        }

        Err(PoolError::Other(format!(
            "transaction confirmation failed (hash: {hash})"
        )))
    }

    #[cfg(not(target_arch = "wasm32"))]
    pub fn storage(&self) -> Result<&Storage, PoolError> {
        Ok(self
            .indexer
            .as_ref()
            .ok_or(PoolError::NotInitialized)?
            .storage())
    }

    #[cfg(not(target_arch = "wasm32"))]
    fn refresh_chain_context(&mut self) -> Result<(), PoolError> {
        let storage = self.storage()?;
        let (_, note_pub, ..) = load_user_key_material(storage, &self.config.user_address)
            .map_err(|e| PoolError::Other(e.to_string()))?;

        let fetcher = StateFetcher::new(&self.config.rpc_url, self.config.contract_config.clone())
            .map_err(|e| PoolError::Other(format!("state fetcher: {e:#}")))?;
        let data = fetcher
            .contracts_data_for_pool(&self.config.pool_contract_id)
            .map_err(|e| PoolError::Other(format!("fetch pool state: {e:#}")))?;
        let non_membership_proof = fetcher
            .get_nonmembership_proof(
                &note_pub,
                data.asp_non_membership.root,
                SMT_DEPTH as usize,
                &self.config.user_address,
            )
            .map_err(|e| PoolError::Other(format!("non-membership proof: {e:#}")))?;

        self.chain = Some(chain_context_from_fetched_state(
            data,
            &self.config.pool_contract_id,
            non_membership_proof,
        )?);
        Ok(())
    }

    #[cfg(target_arch = "wasm32")]
    async fn refresh_chain_context(&mut self) -> Result<(), PoolError> {
        let (_, note_pub, ..) = {
            let wasm = self.wasm_state.as_ref().ok_or(PoolError::NotInitialized)?;
            let storage = wasm.storage.borrow();
            load_user_key_material(&storage, &self.config.user_address)
                .map_err(|e| PoolError::Other(e.to_string()))?
        };

        let fetcher = StateFetcher::new(&self.config.rpc_url, self.config.contract_config.clone())
            .map_err(|e| PoolError::Other(format!("state fetcher: {e:#}")))?;
        let data = fetcher
            .contracts_data_for_pool(&self.config.pool_contract_id)
            .await
            .map_err(|e| PoolError::Other(format!("fetch pool state: {e:#}")))?;
        let non_membership_proof = fetcher
            .get_nonmembership_proof(
                &note_pub,
                data.asp_non_membership.root,
                SMT_DEPTH as usize,
                &self.config.user_address,
            )
            .await
            .map_err(|e| PoolError::Other(format!("non-membership proof: {e:#}")))?;

        self.chain = Some(chain_context_from_fetched_state(
            data,
            &self.config.pool_contract_id,
            non_membership_proof,
        )?);
        Ok(())
    }

    fn prover(&mut self) -> Result<&mut ProverEngine, PoolError> {
        self.prover.as_mut().ok_or(PoolError::NotInitialized)
    }

    fn ensure_prover(&mut self) -> Result<(), PoolError> {
        if self.prover.is_some() {
            return Ok(());
        }

        let artifacts = &self.config.prover_artifacts;

        self.prover = Some(
            ProverEngine::new(
                &artifacts.proving_key,
                &artifacts.circuit_wasm,
                &artifacts.circuit_r1cs,
            )
            .map_err(|e| PoolError::Other(format!("init prover: {e:#}")))?,
        );

        Ok(())
    }

    fn transact_step_for_plan(
        &self,
        plan: &PreparedTransactionPlan,
    ) -> Result<Transact, PoolError> {
        if let Some(amount) = plan.deposit_amount() {
            return self.deposit_transact_step(amount);
        }

        plan.current_spend_step()?
            .ok_or_else(|| PoolError::Other("plan tx missing".into()))
    }

    fn deposit_transact_step(&self, amount: NoteAmount) -> Result<Transact, PoolError> {
        let ext_amount = ExtAmount::try_from(amount)
            .map_err(|_| PoolError::Other("deposit amount exceeds ext_amount range".into()))?;
        let (_, note_pub, enc_pub, _) = {
            #[cfg(not(target_arch = "wasm32"))]
            {
                let storage = self.storage()?;
                load_user_key_material(storage, &self.config.user_address)
                    .map_err(|e| PoolError::Other(e.to_string()))?
            }
            #[cfg(target_arch = "wasm32")]
            {
                let wasm = self.wasm_state.as_ref().ok_or(PoolError::NotInitialized)?;
                let storage = wasm.storage.borrow();
                load_user_key_material(&storage, &self.config.user_address)
                    .map_err(|e| PoolError::Other(e.to_string()))?
            }
        };

        Ok(Transact::new(
            Vec::new(),
            [amount, NoteAmount::ZERO],
            ext_amount,
            self.config.pool_contract_id.clone(),
            [Some(note_pub.clone()), Some(note_pub)],
            [Some(enc_pub.clone()), Some(enc_pub)],
        ))
    }

    fn spendable_wallet(&self) -> Result<Vec<SpendableNote>, PoolError> {
        let pool_contract_id = &self.config.pool_contract_id;
        let user_address = &self.config.user_address;
        let spendable_notes = {
            #[cfg(not(target_arch = "wasm32"))]
            {
                let storage = self.storage()?;
                storage
                    .list_unspent_user_notes(pool_contract_id, user_address)
                    .map_err(|e| PoolError::Other(e.to_string()))?
            }
            #[cfg(target_arch = "wasm32")]
            {
                let wasm = self.wasm_state.as_ref().ok_or(PoolError::NotInitialized)?;
                let storage = wasm.storage.borrow();
                storage
                    .list_unspent_user_notes(pool_contract_id, user_address)
                    .map_err(|e| PoolError::Other(e.to_string()))?
            }
        }
        .into_iter()
        .map(|n| SpendableNote {
            commitment: n.id,
            amount: n.amount,
        })
        .collect();
        Ok(spendable_notes)
    }
}

fn process_local_state(storage: &mut Storage) -> Result<(), PoolError> {
    while process_local_state_batch(storage).map_err(|e| PoolError::Other(e.to_string()))? {}
    Ok(())
}

fn pool_transact_input(prepared: &PreparedTransaction) -> PoolTransactInput {
    PoolTransactInput {
        proof_uncompressed: prepared.proof_uncompressed.clone(),
        ext_data: prepared.ext_data.clone(),
        public: (&prepared.prepared).into(),
    }
}

fn chain_context_from_fetched_state(
    data: ContractsStateData,
    pool_contract_id: &str,
    non_membership_proof: AspNonMembershipProof,
) -> Result<TransactChainContext, PoolError> {
    let pool =
        data.pools.into_iter().next().ok_or_else(|| {
            PoolError::Other(format!("pool data not fetched for {pool_contract_id}"))
        })?;
    let pool_root = pool
        .merkle_root
        .ok_or_else(|| PoolError::Other("pool merkle_root not fetched".into()))?;
    let pool_next_index = pool
        .merkle_next_index
        .parse::<u32>()
        .map_err(|e| PoolError::Other(format!("invalid pool merkle_next_index: {e}")))?;

    Ok(TransactChainContext {
        pool_root,
        pool_next_index,
        pool_merkle_levels: pool.merkle_levels,
        asp_membership_root: data.asp_membership.root,
        asp_membership_contract_id: data.asp_membership.contract_id,
        asp_membership_ledger: data.asp_membership.ledger,
        non_membership_proof,
    })
}

const PROCESS_FETCH_LIMIT: u32 = 50;

fn derive_user_note(
    account: &AccountKeys,
    row: &PoolCommitmentRow,
) -> anyhow::Result<Option<DerivedUserNoteRow>> {
    let opt = try_decrypt_and_derive_user_note(
        &account.note_keypair,
        &account.encryption_keypair.private,
        &row.commitment,
        row.leaf_index,
        &row.encrypted_output,
    )?;
    Ok(opt.map(|d| DerivedUserNoteRow {
        amount: d.amount,
        blinding: d.blinding,
        expected_nullifier: d.expected_nullifier,
    }))
}

/// Process one batch of raw events and note derivation. Returns `true` when
/// more work may remain.
pub fn process_local_state_batch(storage: &mut Storage) -> anyhow::Result<bool> {
    let did_raw = process_events(storage, PROCESS_FETCH_LIMIT)?;
    let mut derive = derive_user_note;
    let did_notes = process_notes(storage, PROCESS_FETCH_LIMIT, &mut derive)?;
    Ok(did_raw || did_notes)
}
