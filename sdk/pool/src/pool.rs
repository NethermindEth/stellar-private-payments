//! Per-pool private payments API.

use state::Storage;
use tx_planner::{SpendSession, SpendTarget, SpendableNote, Transact};
use types::{ExtAmount, NoteAmount};

use crate::{
    error::PoolError,
    plan::PreparedTransactionPlan,
    prover::ProverEngine,
    storage::{
        BuildTransactParams, PreparedProverTx, TransactRequest, build_transact_params,
        load_user_key_material, transact_request_from_step,
    },
    types::{
        Estimate, PreparedTransaction, PrivatePoolConfig, SignedTransaction, SyncResult,
        TransactChainContext, TransactionResult, TransferRecipient,
    },
};

/// Main entry point for a single privacy pool.
pub struct PrivatePool {
    config: PrivatePoolConfig,
    storage: Option<Storage>,
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
            storage: None,
            prover: None,
            chain: None,
        })
    }

    pub fn initialize(&mut self) -> Result<(), PoolError> {
        let storage_path = &self.config.storage_path;
        self.storage = Some(
            Storage::connect_file(storage_path)
                .map_err(|e| PoolError::Other(format!("open storage: {e}")))?,
        );
        Ok(())
    }

    /// Fetch on-chain events, refresh local pool state, and update chain
    /// snapshot.
    pub fn sync(&mut self) -> Result<SyncResult, PoolError> {
        Err(PoolError::NotImplemented)
    }

    /// Chain snapshot from the last successful [`Self::sync`].
    pub fn chain_context(&self) -> Result<&TransactChainContext, PoolError> {
        self.chain.as_ref().ok_or(PoolError::NotSynced)
    }

    /// Install chain snapshot without RPC (tests / until [`Self::sync`] is
    /// wired).
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
    ) -> Result<PreparedProverTx, PoolError> {
        let storage = self.storage()?;
        let params = match build_transact_params(storage, &req)
            .map_err(|e| PoolError::Other(e.to_string()))?
        {
            BuildTransactParams::Ready(params) => params,
            BuildTransactParams::MembershipSync(status) => {
                return Err(PoolError::MembershipSync(status));
            }
        };

        self.ensure_prover()?;

        self.prover()?
            .prove_transact(params)
            .map_err(|e| PoolError::Other(format!("prove: {e:#}")))
    }

    /// Prove the current plan step, advance the plan, and return unsigned
    /// Soroban tx metadata (empty until RPC simulate is wired).
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

        let proved = self.prepare_transact(req)?;
        let output_commitments = proved.prepared.output_commitments;
        plan.finish_proved_tx(&output_commitments)?;

        Ok(proved.soroban_tx)
    }

    pub fn submit(
        &mut self,
        _signed_tx: SignedTransaction,
    ) -> Result<TransactionResult, PoolError> {
        // TODO: submit signed XDR to Soroban RPC.
        Ok(TransactionResult {
            tx_hash: "stub-tx-hash".into(),
        })
    }

    pub fn storage(&self) -> Result<&Storage, PoolError> {
        self.storage.as_ref().ok_or(PoolError::NotInitialized)
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
        let storage = self.storage()?;
        let (_, note_pub, enc_pub, _) = load_user_key_material(storage, &self.config.user_address)
            .map_err(|e| PoolError::Other(e.to_string()))?;

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
        let storage = self.storage()?;
        let pool_contract_id = &self.config.pool_contract_id;
        let user_address = &self.config.user_address;
        let spendable_notes = storage
            .list_unspent_user_notes(pool_contract_id, user_address)
            .map_err(|e| PoolError::Other(e.to_string()))?
            .into_iter()
            .map(|n| SpendableNote {
                commitment: n.id,
                amount: n.amount,
            })
            .collect();
        Ok(spendable_notes)
    }
}
