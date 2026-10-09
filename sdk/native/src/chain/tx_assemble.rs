//! Build an unsigned invoke-contract transaction envelope, and apply Soroban
//! RPC simulation output to one.

use std::str::FromStr;

use anyhow::{Result, anyhow};
use stellar_xdr::{
    self as xdr, Limits, ReadXdr, SorobanAuthorizationEntry, SorobanTransactionData, WriteXdr,
};

use super::{contract_state::PreparedSorobanTx, rpc::SimulateTransactionResponse};

/// Refundable fee added for each contract code entry in a footprint: 1.5
/// times the rent for one hour (`soroban_utils::MIN_EXTENSION_LEDGERS`, 720
/// ledgers) of the largest code entry, measured on testnet on 2026-10-09 at
/// 980,109 stroops for the blocklist tree.
const CODE_RENT_MARGIN: i64 = 1_500_000;

/// Refundable fee added for each other persistent contract data entry: covers
/// an hour of rent for the largest data entry, measured on testnet on
/// 2026-10-09 at about 12,500 stroops for the allowlist `State`, plus about
/// 2,542 for the extension's TTL write.
const DATA_RENT_MARGIN: i64 = 25_000;

/// Returns the rent a transaction may owe beyond its simulation. Contracts
/// extend an entry an hour at a time, so an entry that crosses that step
/// between simulation and apply owes an hour of rent the simulation did not
/// include.
fn rent_margin(footprint: &xdr::LedgerFootprint) -> i64 {
    footprint
        .read_only
        .iter()
        .chain(footprint.read_write.iter())
        .map(|key| match key {
            xdr::LedgerKey::ContractCode(_) => CODE_RENT_MARGIN,
            xdr::LedgerKey::ContractData(data)
                if data.durability == xdr::ContractDataDurability::Persistent =>
            {
                DATA_RENT_MARGIN
            }
            _ => 0,
        })
        .fold(0, i64::saturating_add)
}

/// Builds an unsigned, unsubmitted transaction envelope invoking `function`
/// on `contract_id`, for read-only simulation.
pub(crate) fn build_invoke_contract_tx_envelope(
    source_account: &str,
    seq_num: xdr::SequenceNumber,
    fee: u32,
    contract_id: &str,
    function: &str,
    args: Vec<xdr::ScVal>,
    auth_entries: Vec<xdr::SorobanAuthorizationEntry>,
) -> Result<xdr::TransactionEnvelope> {
    let source = muxed_account_from_g(source_account)?;
    let contract_address = contract_scaddress_from_str(contract_id)?;
    let function_name =
        xdr::ScSymbol::try_from(function).map_err(|_| anyhow!("invalid function name"))?;
    let args = xdr::VecM::try_from(args)?;

    let invoke_args = xdr::InvokeContractArgs {
        contract_address,
        function_name,
        args,
    };
    let host_function = xdr::HostFunction::InvokeContract(invoke_args);
    let invoke_op = xdr::InvokeHostFunctionOp {
        host_function,
        auth: xdr::VecM::try_from(auth_entries)?,
    };
    let op = xdr::Operation {
        source_account: None,
        body: xdr::OperationBody::InvokeHostFunction(invoke_op),
    };

    let operations = xdr::VecM::try_from(vec![op])?;
    let tx = xdr::Transaction {
        source_account: source,
        fee,
        seq_num,
        cond: xdr::Preconditions::None,
        memo: xdr::Memo::None,
        operations,
        ext: xdr::TransactionExt::V0,
    };

    Ok(xdr::TransactionEnvelope::Tx(xdr::TransactionV1Envelope {
        tx,
        signatures: xdr::VecM::default(),
    }))
}

fn muxed_account_from_g(account: &str) -> Result<xdr::MuxedAccount> {
    let pk = stellar_strkey::ed25519::PublicKey::from_str(account)?;
    Ok(xdr::MuxedAccount::Ed25519(xdr::Uint256(pk.0)))
}

fn contract_scaddress_from_str(contract_id: &str) -> Result<xdr::ScAddress> {
    let contract = stellar_strkey::Contract::from_str(contract_id)?;
    Ok(xdr::ScAddress::Contract(xdr::ContractId(xdr::Hash(
        contract.0,
    ))))
}

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
///
/// Adds [`rent_margin`] to the refundable fee; the network refunds what is
/// unused.
fn assemble_soroban_transaction(
    raw: &xdr::TransactionEnvelope,
    sim: &SimulateTransactionResponse,
) -> Result<xdr::TransactionEnvelope> {
    sim.ensure_success()?;

    let min_resource_fee = sim.min_resource_fee_u64()?;
    let mut soroban_data = sim.soroban_transaction_data()?;
    let auth_entries = sim.auth_entries()?;

    let margin = rent_margin(&soroban_data.resources.footprint);
    soroban_data.resource_fee = soroban_data
        .resource_fee
        .checked_add(margin)
        .ok_or_else(|| anyhow!("resourceFee plus the rent margin overflows"))?;

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

    let resource_fee = i64::try_from(min_resource_fee)
        .ok()
        .and_then(|fee| fee.checked_add(margin))
        .and_then(|fee| u32::try_from(fee).ok())
        .ok_or_else(|| anyhow!("minResourceFee plus the rent margin does not fit into u32"))?;

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
        Ok(Self {
            tx_xdr: assembled.to_xdr_base64(Limits::none())?,
            auth_entries: sim.auth_entries_base64()?,
            latest_ledger,
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

    /// Returns a simulation whose footprint holds two code entries, a
    /// persistent and a temporary data entry, and an account.
    fn extendable_entries_sim(min_resource_fee: &str) -> SimulateTransactionResponse {
        let contract = xdr::ScAddress::Contract(xdr::ContractId(xdr::Hash([3u8; 32])));
        let data_key = |durability| {
            xdr::LedgerKey::ContractData(xdr::LedgerKeyContractData {
                contract: contract.clone(),
                key: xdr::ScVal::LedgerKeyContractInstance,
                durability,
            })
        };
        let mut data = empty_soroban_data();
        data.resource_fee = 500;
        let code_key = |byte| {
            xdr::LedgerKey::ContractCode(xdr::LedgerKeyContractCode {
                hash: xdr::Hash([byte; 32]),
            })
        };
        data.resources.footprint = xdr::LedgerFootprint {
            read_only: vec![
                code_key(4),
                code_key(6),
                data_key(xdr::ContractDataDurability::Temporary),
            ]
            .try_into()
            .expect("read-only footprint"),
            read_write: vec![
                data_key(xdr::ContractDataDurability::Persistent),
                xdr::LedgerKey::Account(xdr::LedgerKeyAccount {
                    account_id: xdr::AccountId(xdr::PublicKey::PublicKeyTypeEd25519(xdr::Uint256(
                        [5u8; 32],
                    ))),
                }),
            ]
            .try_into()
            .expect("read-write footprint"),
        };
        SimulateTransactionResponse {
            latest_ledger: 0,
            result: None,
            results: vec![crate::chain::rpc::SimulateHostFunctionResult::default()],
            transaction_data: Some(data.to_xdr_base64(Limits::none()).expect("xdr base64")),
            min_resource_fee: Some(min_resource_fee.to_string()),
            error: None,
        }
    }

    #[test]
    fn assemble_pads_the_fee_for_each_extendable_entry() {
        let sim = extendable_entries_sim("500");

        let assembled = assemble_soroban_transaction(&empty_envelope(), &sim).expect("assemble");
        let xdr::TransactionEnvelope::Tx(v1) = &assembled else {
            panic!("expected v1 envelope")
        };
        let margin = CODE_RENT_MARGIN
            .saturating_mul(2)
            .saturating_add(DATA_RENT_MARGIN);
        assert_eq!(i64::from(v1.tx.fee), margin.saturating_add(600));
        let TransactionExt::V1(applied) = &v1.tx.ext else {
            panic!("expected soroban transaction data")
        };
        assert_eq!(applied.resource_fee, margin.saturating_add(500));
    }

    #[test]
    fn assemble_rejects_a_fee_the_margin_pushes_past_u32() {
        let sim = extendable_entries_sim(&u32::MAX.to_string());

        let err = assemble_soroban_transaction(&empty_envelope(), &sim)
            .expect_err("a fee past u32 must fail");
        assert_eq!(
            err.to_string(),
            "minResourceFee plus the rent margin does not fit into u32"
        );
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
            error: Some("boom".to_string()),
        };
        assert!(assemble_soroban_transaction(&raw, &sim).is_err());
    }
}
