//! Build and simulate pool contract transactions for signing/submission.

use anyhow::{Result, anyhow};
use stellar_xdr::curr::{self as xdr};
use types::ExtData;

use crate::{
    contract_state::{OnchainProofPublicInputs, PreparedSorobanTx, StateFetcher},
    soroban_encode::{
        BASE_FEE, pool_account_to_scval, pool_ext_data_to_scval, pool_proof_to_scval,
    },
};

/// Prover output needed to prepare a pool `transact` invocation.
#[derive(Debug, Clone)]
pub struct PoolTransactInput {
    pub proof_uncompressed: Vec<u8>,
    pub ext_data: ExtData,
    pub public: OnchainProofPublicInputs,
}

impl StateFetcher {
    /// Simulates `transact` and returns unsigned XDR + auth entries for the
    /// wallet.
    pub async fn prepare_pool_transact(
        &self,
        pool_contract_id: &str,
        input: &PoolTransactInput,
        source_account: &str,
    ) -> Result<PreparedSorobanTx> {
        self.enabled_pool_for(pool_contract_id)?;
        let proof_scval = pool_proof_to_scval(
            &input.proof_uncompressed,
            input.public.root,
            &input.public.input_nullifiers,
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
            pool_contract_id,
            "transact",
            vec![proof_scval, ext_scval, sender_scval],
            Vec::new(),
        )?;

        let sim = self.client.simulate_transaction(&raw).await?;
        PreparedSorobanTx::from_simulation(&raw, &sim)
    }

    /// Simulates `register` and returns unsigned XDR + auth entries for the
    /// wallet.
    pub async fn prepare_register(
        &self,
        pool_contract_id: &str,
        source_account: &str,
        note_key: [u8; 32],
        encryption_key: [u8; 32],
    ) -> Result<PreparedSorobanTx> {
        self.enabled_pool_for(pool_contract_id)?;
        let account_scval = pool_account_to_scval(source_account, encryption_key, note_key)?;

        let seq = self.account_sequence(source_account).await?;
        let raw = Self::build_invoke_contract_tx_envelope(
            source_account,
            seq,
            BASE_FEE,
            pool_contract_id,
            "register",
            vec![account_scval],
            Vec::new(),
        )?;

        let sim = self.client.simulate_transaction(&raw).await?;
        PreparedSorobanTx::from_simulation(&raw, &sim)
    }

    async fn account_sequence(&self, source_account: &str) -> Result<xdr::SequenceNumber> {
        let entry = self.client.get_account(source_account).await?;
        next_sequence(entry.seq_num)
    }
}

/// Computes the sequence number for a new transaction from the account's
/// current on-ledger sequence number.
///
/// Stellar requires `tx.seq_num == account.seq_num + 1`; submitting a tx with
/// the account's current sequence is rejected with `txBAD_SEQ`.
fn next_sequence(current: xdr::SequenceNumber) -> Result<xdr::SequenceNumber> {
    let next = current
        .0
        .checked_add(1)
        .ok_or_else(|| anyhow!("account sequence number overflow"))?;
    Ok(xdr::SequenceNumber(next))
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use super::*;
    use crate::{
        rpc::{Error as RpcError, SimulateHostFunctionResult, SimulateTransactionResponse},
        tx_assemble::test_fixtures::{empty_envelope, empty_soroban_data},
    };
    use futures::executor::block_on;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use stellar_strkey::ed25519;
    use stellar_xdr::curr::{Limits, ReadXdr, WriteXdr};
    use types::ContractConfig;

    const TEST_CONFIG_JSON: &str = r#"{
        "network": "test",
        "deployer": "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF",
        "admin": "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF",
        "asp_membership": "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABSC4",
        "asp_non_membership": "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABSC4",
        "verifier": "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABSC4",
        "pools": [{
            "poolContractId": "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABSC4",
            "tokenContractId": "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABSC4",
            "deploymentLedger": 1,
            "enabled": true,
            "asset": {"kind": "native"}
        }]
    }"#;

    fn test_pool_contract_id() -> String {
        let config: ContractConfig = serde_json::from_str(TEST_CONFIG_JSON).expect("test config");
        config
            .pools
            .iter()
            .find(|p| p.enabled)
            .or_else(|| config.pools.first())
            .expect("pool in test config")
            .pool_contract_id
            .clone()
    }

    struct MockRpc {
        seq: xdr::SequenceNumber,
        sim: SimulateTransactionResponse,
        simulate_calls: AtomicUsize,
    }

    impl MockRpc {
        fn new(seq: i64, sim: SimulateTransactionResponse) -> Self {
            Self {
                seq: xdr::SequenceNumber(seq),
                sim,
                simulate_calls: AtomicUsize::new(0),
            }
        }

        async fn simulate_transaction(
            &self,
            _tx: &xdr::TransactionEnvelope,
        ) -> Result<SimulateTransactionResponse, RpcError> {
            self.simulate_calls.fetch_add(1, Ordering::SeqCst);
            Ok(self.sim.clone())
        }
    }

    fn fixture_sim(resource_fee: &str) -> SimulateTransactionResponse {
        let mut sim = SimulateTransactionResponse {
            latest_ledger: 1,
            result: None,
            results: vec![],
            transaction_data: Some(
                empty_soroban_data()
                    .to_xdr_base64(Limits::none())
                    .expect("xdr"),
            ),
            min_resource_fee: Some(resource_fee.to_string()),
            error: None,
        };
        sim.results.push(SimulateHostFunctionResult {
            auth: vec![],
            retval: None,
            ..Default::default()
        });
        sim
    }

    async fn prepare_register_with_mock(
        mock: &MockRpc,
        source_account: &str,
        note_key: [u8; 32],
        encryption_key: [u8; 32],
    ) -> Result<PreparedSorobanTx> {
        let pool_id = test_pool_contract_id();
        let account_scval = pool_account_to_scval(source_account, encryption_key, note_key)?;
        let raw = StateFetcher::build_invoke_contract_tx_envelope(
            source_account,
            next_sequence(mock.seq.clone())?,
            BASE_FEE,
            &pool_id,
            "register",
            vec![account_scval],
            Vec::new(),
        )?;
        let sim = mock.simulate_transaction(&raw).await?;
        PreparedSorobanTx::from_simulation(&raw, &sim)
    }

    #[test]
    fn prepared_tx_applies_simulation_fee_and_auth() {
        let raw = empty_envelope();
        let sim = fixture_sim("500");
        let prepared = PreparedSorobanTx::from_simulation(&raw, &sim).expect("prepare");
        assert!(prepared.auth_entries.is_empty());
        assert_eq!(prepared.latest_ledger, 1);
        assert!(!prepared.tx_xdr.is_empty());

        let assembled = xdr::TransactionEnvelope::from_xdr_base64(&prepared.tx_xdr, Limits::none())
            .expect("xdr");
        let xdr::TransactionEnvelope::Tx(v1) = assembled else {
            panic!("expected v1 envelope");
        };
        assert_eq!(v1.tx.fee, 600);
    }

    #[test]
    fn prepare_register_uses_mocked_simulation() {
        let pk = ed25519::PublicKey([7u8; 32]);
        let source = pk.to_string();
        let mock = MockRpc::new(9, fixture_sim("250"));
        let prepared = block_on(prepare_register_with_mock(
            &mock, &source, [0xAB; 32], [0xEE; 32],
        ))
        .expect("prepare register");

        assert_eq!(mock.simulate_calls.load(Ordering::SeqCst), 1);
        assert!(prepared.auth_entries.is_empty());

        let env = xdr::TransactionEnvelope::from_xdr_base64(&prepared.tx_xdr, Limits::none())
            .expect("xdr");
        let xdr::TransactionEnvelope::Tx(v1) = env else {
            panic!("expected v1 envelope");
        };
        // Account is at seq 9; the new tx must use seq + 1 = 10 (txBAD_SEQ otherwise).
        assert_eq!(v1.tx.seq_num, xdr::SequenceNumber(10));
        assert_eq!(v1.tx.fee, 350);

        let op = &v1.tx.operations[0];
        let xdr::OperationBody::InvokeHostFunction(invoke) = &op.body else {
            panic!("expected invoke");
        };
        let xdr::HostFunction::InvokeContract(args) = &invoke.host_function else {
            panic!("expected contract invoke");
        };
        assert_eq!(args.function_name.to_string(), "register");
        assert_eq!(args.args.len(), 1);
    }

    #[test]
    fn prepare_pool_transact_builds_transact_invoke() {
        let pk = ed25519::PublicKey([8u8; 32]);
        let source = pk.to_string();
        let pool_id = test_pool_contract_id();
        let mock = MockRpc::new(3, fixture_sim("100"));

        let proof_uncompressed = vec![0u8; 256];
        let ext = ExtData {
            recipient: source.to_string(),
            ext_amount: types::ExtAmount::from(0),
            encrypted_output0: vec![],
            encrypted_output1: vec![],
        };
        let public = OnchainProofPublicInputs {
            root: types::Field(types::U256::from(1)),
            input_nullifiers: [
                types::Field(types::U256::from(2)),
                types::Field(types::U256::from(3)),
            ],
            output_commitment0: types::Field(types::U256::from(4)),
            output_commitment1: types::Field(types::U256::from(5)),
            public_amount: types::Field(types::U256::from(6)),
            ext_data_hash_be: [0u8; 32],
            asp_membership_root: types::Field(types::U256::from(7)),
            asp_non_membership_root: types::Field(types::U256::from(8)),
        };

        let proof_scval = pool_proof_to_scval(
            &proof_uncompressed,
            public.root,
            &public.input_nullifiers,
            public.output_commitment0,
            public.output_commitment1,
            public.public_amount,
            public.ext_data_hash_be,
            public.asp_membership_root,
            public.asp_non_membership_root,
        )
        .expect("proof scval");
        let ext_scval = pool_ext_data_to_scval(&ext).expect("ext scval");
        let sender_scval = xdr::ScVal::Address(source.parse().expect("address"));

        let raw = StateFetcher::build_invoke_contract_tx_envelope(
            &source,
            next_sequence(mock.seq.clone()).expect("next seq"),
            BASE_FEE,
            &pool_id,
            "transact",
            vec![proof_scval, ext_scval, sender_scval],
            Vec::new(),
        )
        .expect("raw tx");

        let sim = block_on(mock.simulate_transaction(&raw)).expect("simulate");
        let prepared = PreparedSorobanTx::from_simulation(&raw, &sim).expect("prepare");

        let env = xdr::TransactionEnvelope::from_xdr_base64(&prepared.tx_xdr, Limits::none())
            .expect("xdr");
        let xdr::TransactionEnvelope::Tx(v1) = env else {
            panic!("expected v1 envelope");
        };
        assert_eq!(v1.tx.fee, 200);
        // Account is at seq 3; the new tx must use seq + 1 = 4.
        assert_eq!(v1.tx.seq_num, xdr::SequenceNumber(4));

        let xdr::OperationBody::InvokeHostFunction(invoke) = &v1.tx.operations[0].body else {
            panic!("expected invoke");
        };
        let xdr::HostFunction::InvokeContract(args) = &invoke.host_function else {
            panic!("expected contract invoke");
        };
        assert_eq!(args.function_name.to_string(), "transact");
        assert_eq!(args.args.len(), 3);
    }

    #[test]
    fn next_sequence_increments_by_one() {
        assert_eq!(
            next_sequence(xdr::SequenceNumber(0)).expect("next"),
            xdr::SequenceNumber(1)
        );
        assert_eq!(
            next_sequence(xdr::SequenceNumber(42)).expect("next"),
            xdr::SequenceNumber(43)
        );
    }

    #[test]
    fn next_sequence_rejects_overflow() {
        assert!(next_sequence(xdr::SequenceNumber(i64::MAX)).is_err());
    }
}
