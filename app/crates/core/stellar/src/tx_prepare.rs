//! Build and simulate pool contract transactions for signing/submission.

use anyhow::{Result, anyhow};
use stellar_xdr::curr::{self as xdr, Limits, WriteXdr};
use types::ExtData;

use crate::{
    contract_state::{OnchainProofPublicInputs, PreparedSorobanTx, StateFetcher},
    soroban_encode::{
        BASE_FEE, pool_account_to_scval, pool_ext_data_to_scval, pool_proof_to_scval,
    },
    tx_assemble::assemble_soroban_transaction,
};

/// Prover output needed to prepare a pool `transact` invocation.
#[derive(Debug, Clone)]
pub struct PoolTransactInput {
    pub proof_uncompressed: Vec<u8>,
    pub ext_data: ExtData,
    pub public: OnchainProofPublicInputs,
}

impl StateFetcher {
    /// Simulates `transact` and returns unsigned XDR + auth entries for the wallet.
    pub async fn prepare_pool_transact(
        &self,
        input: &PoolTransactInput,
        source_account: &str,
    ) -> Result<PreparedSorobanTx> {
        let pool_id = &self.config.pool;
        let proof_scval = pool_proof_to_scval(
            &input.proof_uncompressed,
            input.public.root,
            input.public.input_nullifiers,
            input.public.output_commitment0,
            input.public.output_commitment1,
            input.public.public_amount,
            input.public.ext_data_hash_be,
            input.public.asp_membership_root,
            input.public.asp_non_membership_root,
        )?;
        let ext_scval = pool_ext_data_to_scval(&input.ext_data)?;
        let sender_scval = xdr::ScVal::Address(
            source_account
                .parse()
                .map_err(|e| anyhow!("invalid source account: {e}"))?,
        );

        let seq = self.account_sequence(source_account).await?;
        let raw = Self::build_invoke_contract_tx_envelope(
            source_account,
            seq,
            BASE_FEE,
            pool_id,
            "transact",
            vec![proof_scval, ext_scval, sender_scval],
            Vec::new(),
        )?;

        let sim = self.client.simulate_transaction(&raw).await?;
        let assembled = assemble_soroban_transaction(&raw, &sim)?;
        let auth_entries = sim.auth_entries_base64()?;

        Ok(PreparedSorobanTx {
            tx_xdr: assembled.to_xdr_base64(Limits::none())?,
            auth_entries,
        })
    }

    /// Simulates `register` and returns unsigned XDR + auth entries for the wallet.
    pub async fn prepare_register(
        &self,
        source_account: &str,
        note_key: [u8; 32],
        encryption_key: [u8; 32],
    ) -> Result<PreparedSorobanTx> {
        let pool_id = &self.config.pool;
        let account_scval = pool_account_to_scval(source_account, encryption_key, note_key)?;

        let seq = self.account_sequence(source_account).await?;
        let raw = Self::build_invoke_contract_tx_envelope(
            source_account,
            seq,
            BASE_FEE,
            pool_id,
            "register",
            vec![account_scval],
            Vec::new(),
        )?;

        let sim = self.client.simulate_transaction(&raw).await?;
        let assembled = assemble_soroban_transaction(&raw, &sim)?;
        let auth_entries = sim.auth_entries_base64()?;

        Ok(PreparedSorobanTx {
            tx_xdr: assembled.to_xdr_base64(Limits::none())?,
            auth_entries,
        })
    }

    async fn account_sequence(&self, source_account: &str) -> Result<xdr::SequenceNumber> {
        let entry = self.client.get_account(source_account).await?;
        Ok(entry.seq_num)
    }
}
