//! Apply Soroban RPC simulation output to an unsigned transaction envelope.

use anyhow::{Result, anyhow};
use stellar_xdr::{
    self as xdr, Limits, ReadXdr, SorobanAuthorizationEntry, SorobanTransactionData, WriteXdr,
};

use super::{
    contract_state::PreparedSorobanTx,
    rpc::{RestorePreamble, SimulateTransactionResponse},
    soroban_encode::BASE_FEE,
};

impl SimulateTransactionResponse {
    /// Returns the first host-function simulation result.
    pub fn first_result(&self) -> Result<&crate::chain::rpc::SimulateHostFunctionResult> {
        if let Some(r) = &self.result {
            return Ok(r);
        }
        self.results
            .first()
            .ok_or_else(|| anyhow!("simulateTransaction returned no op results"))
    }

    /// Parses `minResourceFee` as u64.
    pub fn min_resource_fee_u64(&self) -> Result<u64> {
        let Some(raw) = &self.min_resource_fee else {
            return Ok(0);
        };
        raw.parse::<u64>()
            .map_err(|_| anyhow!("invalid minResourceFee: {raw}"))
    }

    /// Parses Soroban transaction data from simulation.
    pub fn soroban_transaction_data(&self) -> Result<SorobanTransactionData> {
        let b64 = self
            .transaction_data
            .as_deref()
            .ok_or_else(|| anyhow!("simulateTransaction missing transactionData"))?;
        SorobanTransactionData::from_xdr_base64(b64, Limits::none())
            .map_err(|e| anyhow!("invalid transactionData xdr: {e}"))
    }

    /// Auth entries from simulation as base64 XDR strings.
    pub fn auth_entries_base64(&self) -> Result<Vec<String>> {
        Ok(self.first_result()?.auth.clone())
    }

    /// Auth entries decoded from simulation.
    pub fn auth_entries(&self) -> Result<Vec<SorobanAuthorizationEntry>> {
        self.auth_entries_base64()?
            .iter()
            .map(|b64| {
                SorobanAuthorizationEntry::from_xdr_base64(b64, Limits::none())
                    .map_err(|e| anyhow!("invalid auth entry xdr: {e}"))
            })
            .collect()
    }

    /// Fails if the simulation response contains a top-level error string.
    pub fn ensure_success(&self) -> Result<()> {
        if let Some(err) = &self.error {
            return Err(anyhow!("transaction simulation failed: {err}"));
        }
        Ok(())
    }
}

/// Merges simulation resource data and authorization into `raw`.
///
/// Mirrors `assembleTransaction` from the JS Stellar SDK.
fn assemble_soroban_transaction(
    raw: &xdr::TransactionEnvelope,
    sim: &SimulateTransactionResponse,
) -> Result<xdr::TransactionEnvelope> {
    sim.ensure_success()?;

    let min_resource_fee = sim.min_resource_fee_u64()?;
    let soroban_data = sim.soroban_transaction_data()?;
    let auth_entries = sim.auth_entries()?;

    let xdr::TransactionEnvelope::Tx(v1) = raw else {
        return Err(anyhow!("expected TransactionEnvelope::Tx"));
    };

    let mut tx = v1.tx.clone();
    if tx.operations.len() != 1 {
        return Err(anyhow!(
            "expected exactly one operation, got {}",
            tx.operations.len()
        ));
    }

    let resource_fee: u32 = min_resource_fee
        .try_into()
        .map_err(|_| anyhow!("minResourceFee does not fit into u32"))?;

    let mut classic_fee = u64::from(tx.fee);
    if let xdr::TransactionExt::V1(existing) = &tx.ext {
        let resource_fee = u64::try_from(existing.resource_fee).unwrap_or(0);
        classic_fee = classic_fee.saturating_sub(resource_fee);
    }
    tx.fee = classic_fee
        .saturating_add(u64::from(resource_fee))
        .try_into()
        .map_err(|_| anyhow!("total fee does not fit into u32"))?;
    tx.ext = xdr::TransactionExt::V1(soroban_data);

    let op = tx.operations[0].clone();
    let xdr::OperationBody::InvokeHostFunction(mut invoke) = op.body else {
        return Err(anyhow!("expected invokeHostFunction operation"));
    };

    if !invoke.auth.is_empty() {
        return Err(anyhow!(
            "invoke operation already has auth entries; expected empty auth before assembly"
        ));
    }
    invoke.auth = xdr::VecM::try_from(auth_entries)?;

    tx.operations = xdr::VecM::try_from(vec![xdr::Operation {
        source_account: op.source_account,
        body: xdr::OperationBody::InvokeHostFunction(invoke),
    }])?;

    Ok(xdr::TransactionEnvelope::Tx(xdr::TransactionV1Envelope {
        tx,
        signatures: v1.signatures.clone(),
    }))
}

/// Builds the `RestoreFootprint` transaction a simulation's restore preamble
/// asks for.
///
/// The restore reuses the invocation's source account and sequence number, so
/// it takes the sequence the invocation would have used and the retried
/// invocation takes the one after it.
///
/// # Errors
///
/// Returns an error if `raw` is not a V1 transaction envelope, if the
/// preamble's `transactionData` is not valid XDR, if its `minResourceFee` is
/// not a number, or if the total fee does not fit into `u32`.
fn restore_footprint_envelope(
    raw: &xdr::TransactionEnvelope,
    preamble: &RestorePreamble,
) -> Result<xdr::TransactionEnvelope> {
    let xdr::TransactionEnvelope::Tx(v1) = raw else {
        return Err(anyhow!("expected TransactionEnvelope::Tx"));
    };

    let soroban_data =
        SorobanTransactionData::from_xdr_base64(&preamble.transaction_data, Limits::none())
            .map_err(|e| anyhow!("invalid restorePreamble transactionData xdr: {e}"))?;
    let resource_fee = preamble.min_resource_fee.parse::<u64>().map_err(|_| {
        anyhow!(
            "invalid restorePreamble minResourceFee: {}",
            preamble.min_resource_fee
        )
    })?;
    let fee: u32 = u64::from(BASE_FEE)
        .saturating_add(resource_fee)
        .try_into()
        .map_err(|_| anyhow!("restore fee does not fit into u32"))?;

    let tx = xdr::Transaction {
        source_account: v1.tx.source_account.clone(),
        fee,
        seq_num: v1.tx.seq_num.clone(),
        cond: xdr::Preconditions::None,
        memo: xdr::Memo::None,
        operations: xdr::VecM::try_from(vec![xdr::Operation {
            source_account: None,
            body: xdr::OperationBody::RestoreFootprint(xdr::RestoreFootprintOp {
                ext: xdr::ExtensionPoint::V0,
            }),
        }])?,
        ext: xdr::TransactionExt::V1(soroban_data),
    };

    Ok(xdr::TransactionEnvelope::Tx(xdr::TransactionV1Envelope {
        tx,
        signatures: xdr::VecM::default(),
    }))
}

impl PreparedSorobanTx {
    /// Builds a wallet-ready prepared tx from an unsigned envelope and
    /// simulation.
    pub(crate) fn from_simulation(
        raw: &xdr::TransactionEnvelope,
        sim: &SimulateTransactionResponse,
    ) -> Result<Self> {
        let assembled = assemble_soroban_transaction(raw, sim)?;
        let latest_ledger = u32::try_from(sim.latest_ledger)
            .map_err(|_| anyhow!("latestLedger does not fit into u32"))?;
        let restore_tx_xdr = sim
            .restore_preamble
            .as_ref()
            .map(|preamble| -> Result<String> {
                let envelope = restore_footprint_envelope(raw, preamble)?;
                Ok(envelope.to_xdr_base64(Limits::none())?)
            })
            .transpose()?;
        Ok(Self {
            tx_xdr: assembled.to_xdr_base64(Limits::none())?,
            auth_entries: sim.auth_entries_base64()?,
            latest_ledger,
            restore_tx_xdr,
        })
    }
}

#[cfg(test)]
pub(crate) mod test_fixtures {
    use super::*;
    use stellar_xdr::{
        HostFunction, InvokeContractArgs, InvokeHostFunctionOp, LedgerFootprint, Memo,
        MuxedAccount, Operation, OperationBody, Preconditions, ScAddress, ScSymbol, SequenceNumber,
        SorobanAddressCredentials, SorobanAuthorizationEntry, SorobanAuthorizedFunction,
        SorobanAuthorizedInvocation, SorobanCredentials, SorobanResources,
        SorobanTransactionDataExt, Transaction, TransactionExt, TransactionV1Envelope, Uint256,
        VecM, WriteXdr,
    };

    pub fn empty_envelope() -> xdr::TransactionEnvelope {
        let function_name = ScSymbol::try_from("transact").expect("symbol");
        let contract_address = ScAddress::Contract(xdr::ContractId(xdr::Hash([0u8; 32])));
        let invoke_args = InvokeContractArgs {
            contract_address,
            function_name,
            args: VecM::default(),
        };
        let invoke = InvokeHostFunctionOp {
            host_function: HostFunction::InvokeContract(invoke_args),
            auth: VecM::default(),
        };
        let op = Operation {
            source_account: None,
            body: OperationBody::InvokeHostFunction(invoke),
        };
        let tx = Transaction {
            source_account: MuxedAccount::Ed25519(Uint256([0u8; 32])),
            fee: 100,
            seq_num: SequenceNumber(0),
            cond: Preconditions::None,
            memo: Memo::None,
            operations: VecM::try_from(vec![op]).expect("operations"),
            ext: TransactionExt::V0,
        };
        xdr::TransactionEnvelope::Tx(TransactionV1Envelope {
            tx,
            signatures: VecM::default(),
        })
    }

    pub fn sample_auth_entry_b64() -> String {
        let entry = SorobanAuthorizationEntry {
            credentials: SorobanCredentials::Address(SorobanAddressCredentials {
                address: ScAddress::Contract(xdr::ContractId(xdr::Hash([1u8; 32]))),
                nonce: 0,
                signature_expiration_ledger: 0,
                signature: xdr::ScVal::Void,
            }),
            root_invocation: SorobanAuthorizedInvocation {
                function: SorobanAuthorizedFunction::ContractFn(InvokeContractArgs {
                    contract_address: ScAddress::Contract(xdr::ContractId(xdr::Hash([2u8; 32]))),
                    function_name: ScSymbol::try_from("transfer").expect("symbol"),
                    args: VecM::default(),
                }),
                sub_invocations: VecM::default(),
            },
        };
        entry.to_xdr_base64(Limits::none()).expect("auth entry xdr")
    }

    pub fn empty_soroban_data() -> SorobanTransactionData {
        SorobanTransactionData {
            ext: SorobanTransactionDataExt::V0,
            resources: SorobanResources {
                footprint: LedgerFootprint {
                    read_only: VecM::default(),
                    read_write: VecM::default(),
                },
                instructions: 0,
                disk_read_bytes: 0,
                write_bytes: 0,
            },
            resource_fee: 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use stellar_xdr::{Limits, TransactionExt, WriteXdr};
    use test_fixtures::{empty_envelope, empty_soroban_data};

    #[test]
    fn assemble_applies_resource_fee_and_data() {
        let raw = empty_envelope();
        let mut sim = SimulateTransactionResponse {
            latest_ledger: 0,
            result: None,
            results: vec![],
            transaction_data: Some(
                empty_soroban_data()
                    .to_xdr_base64(Limits::none())
                    .expect("xdr base64"),
            ),
            min_resource_fee: Some("500".to_string()),
            restore_preamble: None,
            error: None,
        };
        sim.results
            .push(crate::chain::rpc::SimulateHostFunctionResult {
                auth: vec![],
                retval: None,
                ..Default::default()
            });

        let assembled = assemble_soroban_transaction(&raw, &sim).expect("assemble");
        let xdr::TransactionEnvelope::Tx(v1) = &assembled else {
            panic!("expected v1 envelope")
        };
        assert_eq!(v1.tx.fee, 600);
        assert!(matches!(v1.tx.ext, TransactionExt::V1(_)));
    }

    #[test]
    fn assemble_embeds_simulated_auth_entries() {
        let raw = empty_envelope();
        let auth_b64 = test_fixtures::sample_auth_entry_b64();
        let mut sim = SimulateTransactionResponse {
            latest_ledger: 42,
            result: None,
            results: vec![],
            transaction_data: Some(
                empty_soroban_data()
                    .to_xdr_base64(Limits::none())
                    .expect("xdr base64"),
            ),
            min_resource_fee: Some("0".to_string()),
            restore_preamble: None,
            error: None,
        };
        sim.results
            .push(crate::chain::rpc::SimulateHostFunctionResult {
                auth: vec![auth_b64.clone()],
                retval: None,
                ..Default::default()
            });

        let assembled = assemble_soroban_transaction(&raw, &sim).expect("assemble");
        let xdr::TransactionEnvelope::Tx(v1) = &assembled else {
            panic!("expected v1 envelope");
        };
        let xdr::OperationBody::InvokeHostFunction(invoke) = &v1.tx.operations[0].body else {
            panic!("expected invoke");
        };
        assert_eq!(invoke.auth.len(), 1);
        assert_eq!(
            invoke.auth[0]
                .to_xdr_base64(Limits::none())
                .expect("auth xdr"),
            auth_b64
        );
    }

    #[test]
    fn assemble_rejects_simulation_error() {
        let raw = empty_envelope();
        let sim = SimulateTransactionResponse {
            latest_ledger: 0,
            result: None,
            results: vec![],
            transaction_data: None,
            min_resource_fee: None,
            restore_preamble: None,
            error: Some("boom".to_string()),
        };
        assert!(assemble_soroban_transaction(&raw, &sim).is_err());
    }

    fn preamble(resource_fee: &str) -> RestorePreamble {
        RestorePreamble {
            min_resource_fee: resource_fee.to_string(),
            transaction_data: empty_soroban_data()
                .to_xdr_base64(Limits::none())
                .expect("xdr"),
        }
    }

    fn sim_with_preamble(preamble: Option<RestorePreamble>) -> SimulateTransactionResponse {
        let mut sim = SimulateTransactionResponse {
            latest_ledger: 1,
            result: None,
            results: vec![],
            transaction_data: Some(
                empty_soroban_data()
                    .to_xdr_base64(Limits::none())
                    .expect("xdr"),
            ),
            min_resource_fee: Some("500".to_string()),
            restore_preamble: preamble,
            error: None,
        };
        sim.results
            .push(crate::chain::rpc::SimulateHostFunctionResult {
                auth: vec![],
                retval: None,
                ..Default::default()
            });
        sim
    }

    #[test]
    fn a_restore_preamble_yields_a_restore_footprint_transaction() {
        let raw = empty_envelope();

        let envelope = restore_footprint_envelope(&raw, &preamble("700")).expect("restore tx");

        let xdr::TransactionEnvelope::Tx(v1) = envelope else {
            panic!("expected v1 envelope");
        };
        assert_eq!(v1.tx.operations.len(), 1);
        assert!(matches!(
            v1.tx.operations[0].body,
            xdr::OperationBody::RestoreFootprint(_)
        ));
        let TransactionExt::V1(data) = &v1.tx.ext else {
            panic!("expected soroban transaction data on the restore");
        };
        assert_eq!(*data, empty_soroban_data());
        assert_eq!(v1.tx.fee, BASE_FEE + 700);
    }

    /// The restore takes the sequence the invocation would have used, so the
    /// invocation retried after it takes the one following.
    #[test]
    fn a_restore_reuses_the_source_and_sequence_of_the_invocation() {
        let raw = empty_envelope();
        let xdr::TransactionEnvelope::Tx(original) = &raw else {
            panic!("expected v1 envelope");
        };

        let envelope = restore_footprint_envelope(&raw, &preamble("0")).expect("restore tx");

        let xdr::TransactionEnvelope::Tx(v1) = &envelope else {
            panic!("expected v1 envelope");
        };
        assert_eq!(v1.tx.source_account, original.tx.source_account);
        assert_eq!(v1.tx.seq_num, original.tx.seq_num);
    }

    #[test]
    fn a_restore_preamble_with_invalid_transaction_data_is_rejected() {
        let raw = empty_envelope();
        let preamble = RestorePreamble {
            min_resource_fee: "1".to_string(),
            transaction_data: "not base64 xdr".to_string(),
        };

        let err = restore_footprint_envelope(&raw, &preamble)
            .expect_err("a preamble with unreadable transaction data must not assemble");

        assert!(err.to_string().contains("transactionData"), "{err}");
    }

    #[test]
    fn a_restore_preamble_with_a_non_numeric_fee_is_rejected() {
        let raw = empty_envelope();
        let preamble = RestorePreamble {
            min_resource_fee: "lots".to_string(),
            transaction_data: empty_soroban_data()
                .to_xdr_base64(Limits::none())
                .expect("xdr"),
        };

        let err = restore_footprint_envelope(&raw, &preamble)
            .expect_err("a preamble with a non-numeric fee must not assemble");

        assert!(err.to_string().contains("minResourceFee"), "{err}");
    }

    #[test]
    fn a_simulation_with_a_preamble_carries_the_restore_xdr() {
        let raw = empty_envelope();

        let prepared =
            PreparedSorobanTx::from_simulation(&raw, &sim_with_preamble(Some(preamble("300"))))
                .expect("prepare");

        let restore = prepared.restore_tx_xdr.expect("restore xdr");
        let envelope =
            xdr::TransactionEnvelope::from_xdr_base64(&restore, Limits::none()).expect("xdr");
        let xdr::TransactionEnvelope::Tx(v1) = envelope else {
            panic!("expected v1 envelope");
        };
        assert!(matches!(
            v1.tx.operations[0].body,
            xdr::OperationBody::RestoreFootprint(_)
        ));
    }

    #[test]
    fn a_simulation_without_a_preamble_leaves_the_restore_xdr_unset() {
        let raw = empty_envelope();

        let prepared =
            PreparedSorobanTx::from_simulation(&raw, &sim_with_preamble(None)).expect("prepare");

        assert!(prepared.restore_tx_xdr.is_none());
    }
}
