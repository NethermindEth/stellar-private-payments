use crate::{
    conversions::{
        field_to_scval_u256, scval_to_address_string, scval_to_bool, scval_to_u32, scval_to_u64,
        scval_to_u256,
    },
    rpc::{Client, ContractDataBulkRequest},
    soroban_encode::BASE_FEE,
};
use anyhow::{Result, anyhow};
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, str::FromStr};
use stellar_strkey::ed25519;
use stellar_xdr::{curr as xdr, curr::ReadXdr};

use types::{
    AspMembership, AspNonMembership, AspNonMembershipProof, ContractConfig, ContractsStateData,
    ExtAmount, Field, NotePublicKey, PoolInfo, U256,
};

macro_rules! get_state {
    ($map:expr, $key:expr, $source:expr) => {
        $map.get($key).ok_or_else(|| {
            anyhow::anyhow!("missing {} state key in the contract {:?}", $key, $source)
        })
    };
}

pub struct StateFetcher {
    pub(crate) client: Client,
    pub(crate) config: &'static ContractConfig,
}

#[derive(Clone, Debug)]
struct ParsedFindResult {
    found: bool,
    siblings: Vec<Field>,
    not_found_key: Field,
    not_found_value: Field,
    is_old0: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OnchainProofPublicInputs {
    pub root: Field,
    pub input_nullifiers: [Field; 2],
    pub output_commitment0: Field,
    pub output_commitment1: Field,
    pub public_amount: Field,
    pub ext_data_hash_be: [u8; 32],
    pub asp_membership_root: Field,
    pub asp_non_membership_root: Field,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct PreparedSorobanTx {
    pub tx_xdr: String,
    /// Base64-encoded XDR `SorobanAuthorizationEntry` list from simulation.
    pub auth_entries: Vec<String>,
    /// Ledger number from `simulateTransaction` (`latestLedger`), for auth
    /// expiration.
    pub latest_ledger: u32,
}

impl StateFetcher {
    fn u256_to_i128_checked(v: U256, what: &'static str) -> Result<i128> {
        let be = v.to_big_endian();

        // Must fit into 128 bits to be representable as i128.
        if be[..16].iter().any(|&b| b != 0) {
            return Err(anyhow!("{what} does not fit into i128"));
        }

        let mut low_bytes = [0u8; 16];
        low_bytes.copy_from_slice(&be[16..]);
        let low = u128::from_be_bytes(low_bytes);

        if low > i128::MAX as u128 {
            return Err(anyhow!("{what} does not fit into i128"));
        }

        let value = i128::try_from(low).map_err(|_| anyhow!("{what} does not fit into i128"))?;
        Ok(value)
    }

    pub fn new(rpc_url: &str, config: &'static ContractConfig) -> Result<Self> {
        Ok(Self {
            client: Client::new(rpc_url)?,
            config,
        })
    }

    pub fn contract_config(&self) -> &ContractConfig {
        self.config
    }

    pub fn rpc(&self) -> &Client {
        &self.client
    }

    pub fn enabled_pool_for(&self, pool_contract_id: &str) -> Result<&types::PoolConfigEntry> {
        self.config
            .pools
            .iter()
            .find(|p| p.enabled && p.pool_contract_id == pool_contract_id)
            .ok_or_else(|| {
                anyhow!("enabled pool not found in deployments config: {pool_contract_id}")
            })
    }

    pub async fn all_contracts_data(&self) -> Result<ContractsStateData> {
        let enabled_pools: Vec<&types::PoolConfigEntry> =
            self.config.pools.iter().filter(|p| p.enabled).collect();
        self.contracts_data(&enabled_pools).await
    }

    pub async fn contracts_data_for_pool(
        &self,
        pool_contract_id: &str,
    ) -> Result<ContractsStateData> {
        let enabled_pool = self.enabled_pool_for(pool_contract_id)?;
        self.contracts_data(&[enabled_pool]).await
    }

    pub async fn asp_state(&self) -> Result<ContractsStateData> {
        self.contracts_data(&[]).await
    }

    async fn contracts_data(
        &self,
        enabled_pools: &[&types::PoolConfigEntry],
    ) -> Result<ContractsStateData> {
        const MAX_SNAPSHOT_ATTEMPTS: u32 = 3;

        let mut requests = Vec::with_capacity(enabled_pools.len().wrapping_add(2));
        for pool in enabled_pools.iter() {
            requests.push(ContractDataBulkRequest {
                contract_id: &pool.pool_contract_id,
                enum_keys: vec![
                    "Admin",
                    "Token",
                    "Verifier",
                    "ASPMembership",
                    "ASPNonMembership",
                    "Levels",
                    "CurrentRootIndex",
                    "NextIndex",
                    "MaximumDepositAmount",
                ],
                valued_keys: vec![],
            });
        }

        requests.push(ContractDataBulkRequest {
            contract_id: self.config.asp_membership.as_str(),
            enum_keys: vec!["Root", "Levels", "NextIndex", "Admin", "AdminInsertOnly"],
            valued_keys: vec![],
        });

        requests.push(ContractDataBulkRequest {
            contract_id: self.config.asp_non_membership.as_str(),
            enum_keys: vec!["Root", "Admin"],
            valued_keys: vec![],
        });

        // We fetch up to MAX_SNAPSHOT_ATTEMPTS and comparing roots indices to ensure
        // that the roots fetched later correspond to the pools states
        // fetched first
        let mut last_drift = String::new();

        for attempt in 1..=MAX_SNAPSHOT_ATTEMPTS {
            let (bulk_state, base_latest_ledger) =
                self.client.get_contract_data_bulk(&requests).await?;

            let mut expected_root_indices: HashMap<String, u32> =
                HashMap::with_capacity(enabled_pools.len());
            let mut root_requests = Vec::with_capacity(enabled_pools.len());
            for pool in enabled_pools.iter() {
                let pool_state = bulk_state
                    .get(&pool.pool_contract_id)
                    .ok_or_else(|| anyhow!("missing pool state for {}", pool.pool_contract_id))?;
                let current_root_index_val =
                    pool_state.get("CurrentRootIndex").ok_or_else(|| {
                        anyhow!(
                            "missing pool current root index state for {}",
                            pool.pool_contract_id
                        )
                    })?;
                let current_root_index = scval_to_u32(current_root_index_val)?;
                expected_root_indices.insert(pool.pool_contract_id.clone(), current_root_index);
                root_requests.push(ContractDataBulkRequest {
                    contract_id: &pool.pool_contract_id,
                    enum_keys: vec!["CurrentRootIndex"],
                    valued_keys: vec![("Root", current_root_index)],
                });
            }

            let (root_state, _) = self.client.get_contract_data_bulk(&root_requests).await?;

            let mut drift = vec![];
            for pool in enabled_pools.iter() {
                let expected = expected_root_indices
                    .get(&pool.pool_contract_id)
                    .ok_or_else(|| {
                        anyhow!(
                            "missing expected current root index state for {}",
                            pool.pool_contract_id
                        )
                    })?;

                let check_state = root_state.get(&pool.pool_contract_id).ok_or_else(|| {
                    anyhow!(
                        "missing pool index check state for {}",
                        pool.pool_contract_id
                    )
                })?;
                let observed = scval_to_u32(get_state!(
                    check_state,
                    "CurrentRootIndex",
                    pool.pool_contract_id
                )?)?;

                if observed != *expected {
                    drift.push(format!(
                        "{} expected_index={} observed_index={}",
                        pool.pool_contract_id, expected, observed
                    ));
                }
            }

            if !drift.is_empty() {
                last_drift = drift.join(", ");
                log::debug!(
                    "snapshot drift detected while fetching pool roots (attempt {attempt}/{MAX_SNAPSHOT_ATTEMPTS}): {last_drift}"
                );
                if attempt < MAX_SNAPSHOT_ATTEMPTS {
                    continue;
                }
                return Err(anyhow!(
                    "inconsistent snapshot after {MAX_SNAPSHOT_ATTEMPTS} attempts: {last_drift}"
                ));
            }

            let mut out = Vec::with_capacity(enabled_pools.len());
            for pool in enabled_pools.iter() {
                let pool_state = bulk_state
                    .get(&pool.pool_contract_id)
                    .ok_or_else(|| anyhow!("missing pool state for {}", pool.pool_contract_id))?;

                let merkle_current_root_index = pool_state
                    .get("CurrentRootIndex")
                    .map(scval_to_u32)
                    .transpose()?;
                let merkle_root = root_state
                    .get(&pool.pool_contract_id)
                    .and_then(|state| state.get("Root"))
                    .map(scval_to_u256)
                    .transpose()?
                    .map(Field::try_from_u256)
                    .transpose()?;

                let merkle_levels =
                    scval_to_u32(get_state!(pool_state, "Levels", pool.pool_contract_id)?)?;
                let merkle_capacity = 2u64.pow(merkle_levels);
                let merkle_next_index =
                    scval_to_u64(get_state!(pool_state, "NextIndex", pool.pool_contract_id)?)?;
                let maximum_deposit_amount_u256 = scval_to_u256(get_state!(
                    pool_state,
                    "MaximumDepositAmount",
                    pool.pool_contract_id
                )?)?;
                let maximum_deposit_amount = ExtAmount::from(Self::u256_to_i128_checked(
                    maximum_deposit_amount_u256,
                    "maximum_deposit_amount",
                )?);

                let pool_info = PoolInfo {
                    ledger: base_latest_ledger,
                    contract_id: pool.pool_contract_id.clone(),
                    contract_type: "Privacy Pool".to_string(),
                    admin: scval_to_address_string(get_state!(
                        pool_state,
                        "Admin",
                        pool.pool_contract_id
                    )?)?,
                    token: scval_to_address_string(get_state!(
                        pool_state,
                        "Token",
                        pool.pool_contract_id
                    )?)?,
                    verifier: scval_to_address_string(get_state!(
                        pool_state,
                        "Verifier",
                        pool.pool_contract_id
                    )?)?,
                    aspmembership: scval_to_address_string(get_state!(
                        pool_state,
                        "ASPMembership",
                        pool.pool_contract_id
                    )?)?,
                    aspnonmembership: scval_to_address_string(get_state!(
                        pool_state,
                        "ASPNonMembership",
                        pool.pool_contract_id
                    )?)?,
                    merkle_levels,
                    merkle_current_root_index,
                    merkle_next_index: merkle_next_index.to_string(),
                    maximum_deposit_amount,
                    merkle_root,
                    merkle_capacity,
                    total_commitments: merkle_next_index.to_string(),
                };

                out.push(pool_info);
            }

            let asp_membership_id = &self.config.asp_membership;
            let asp_membership_state = bulk_state
                .get(asp_membership_id)
                .ok_or_else(|| anyhow!("missing asp membership state for {asp_membership_id}"))?;
            let asp_mem_next_index = scval_to_u64(get_state!(
                asp_membership_state,
                "NextIndex",
                asp_membership_id
            )?)?;
            let asp_mem_levels = scval_to_u32(get_state!(
                asp_membership_state,
                "Levels",
                asp_membership_id
            )?)?;
            let asp_mem_capacity = 2u64.pow(asp_mem_levels);
            let root_u256 =
                scval_to_u256(get_state!(asp_membership_state, "Root", asp_membership_id)?)?;
            let asp_membership = AspMembership {
                ledger: base_latest_ledger,
                contract_id: asp_membership_id.to_string(),
                contract_type: "ASP Membership".to_string(),
                root: Field::try_from_u256(root_u256)?,
                levels: asp_mem_levels,
                next_index: asp_mem_next_index.to_string(),
                admin: scval_to_address_string(get_state!(
                    asp_membership_state,
                    "Admin",
                    asp_membership_id
                )?)?,
                admin_insert_only: scval_to_bool(get_state!(
                    asp_membership_state,
                    "AdminInsertOnly",
                    asp_membership_id
                )?)?,
                capacity: asp_mem_capacity,
                used_slots: asp_mem_next_index.to_string(),
            };

            let asp_non_membership_id = &self.config.asp_non_membership;
            let asp_non_membership_state =
                bulk_state.get(asp_non_membership_id).ok_or_else(|| {
                    anyhow!("missing asp non-membership state for {asp_non_membership_id}")
                })?;
            let asp_nonmem_root_u256 = scval_to_u256(get_state!(
                asp_non_membership_state,
                "Root",
                asp_non_membership_id
            )?)?;
            let asp_nonmem_root = Field::try_from_u256(asp_nonmem_root_u256)?;
            let asp_non_membership = AspNonMembership {
                ledger: base_latest_ledger,
                contract_id: asp_non_membership_id.to_string(),
                contract_type: "ASP Non-Membership (Sparse Merkle Tree)".to_string(),
                root: asp_nonmem_root,
                is_empty: asp_nonmem_root.is_zero(),
                admin: scval_to_address_string(get_state!(
                    asp_non_membership_state,
                    "Admin",
                    asp_non_membership_id
                )?)?,
            };

            return Ok(ContractsStateData {
                pools: out,
                asp_membership,
                asp_non_membership,
            });
        }

        Err(anyhow!(
            "inconsistent snapshot after {MAX_SNAPSHOT_ATTEMPTS} attempts: {last_drift}"
        ))
    }

    /// Builds ASP SMT non-membership proof data by querying the on-chain SMT
    /// via `simulateTransaction`.
    ///
    /// - if `non_membership_root == 0`, returns a dummy "empty tree" proof
    ///   padded to `smt_depth`
    /// - otherwise calls `asp_non_membership.find_key(key)` and pads/trims
    ///   siblings to `smt_depth`
    pub async fn get_nonmembership_proof(
        &self,
        note_pubkey: &NotePublicKey,
        non_membership_root: Field,
        smt_depth: usize,
        source_account: &str,
    ) -> Result<AspNonMembershipProof> {
        if smt_depth == 0 {
            return Err(anyhow!("smt_depth must be > 0"));
        }

        // NotePublicKey bytes are little-endian field bytes (see
        // prover::serialization).
        let key = Field::try_from_le_bytes(*note_pubkey.as_ref())?;

        // Empty tree case (root = 0): non-membership is trivially provable.
        if non_membership_root.is_zero() {
            return Ok(AspNonMembershipProof {
                key,
                old_key: Field::ZERO,
                old_value: Field::ZERO,
                is_old0: true,
                siblings: vec![Field::ZERO; smt_depth],
                root: Field::ZERO,
            });
        }

        let tx = Self::build_find_key_simulation_tx(
            &self.config.asp_non_membership,
            source_account,
            key,
        )?;
        let retval = self.simulate_single_retval(&tx).await?;
        let parsed = Self::parse_find_result(&retval)?;

        if parsed.found {
            return Err(anyhow!(
                "Key exists in non-membership tree (user is sanctioned)"
            ));
        }

        // Pad/trim siblings to circuit SMT depth.
        let mut siblings = parsed.siblings;
        if siblings.len() < smt_depth {
            let padding = smt_depth.saturating_sub(siblings.len());
            siblings.extend(core::iter::repeat_n(Field::ZERO, padding));
        } else if siblings.len() > smt_depth {
            siblings.truncate(smt_depth);
        }

        Ok(AspNonMembershipProof {
            key,
            old_key: parsed.not_found_key,
            old_value: parsed.not_found_value,
            is_old0: parsed.is_old0,
            siblings,
            root: non_membership_root,
        })
    }

    /// Checks whether a pool Merkle root is still known by the deployed pool.
    ///
    /// # Arguments
    /// * `pool_contract_id` - Contract id of the enabled pool to query.
    /// * `root` - Pool Merkle root to check.
    ///
    /// # Returns
    /// Returns `true` when the root is in the pool root-history window.
    ///
    /// # Errors
    /// Returns an error if the pool is not an enabled deployment, the
    /// simulation fails, or the contract returns a non-boolean value.
    pub async fn is_pool_known_root(&self, pool_contract_id: &str, root: Field) -> Result<bool> {
        let pool = self.enabled_pool_for(pool_contract_id)?;
        let tx = Self::build_is_known_root_simulation_tx(
            &pool.pool_contract_id,
            &self.config.deployer,
            root,
        )?;
        let retval = self.simulate_single_retval(&tx).await?;
        Ok(scval_to_bool(&retval)?)
    }

    async fn simulate_single_retval(&self, tx: &xdr::TransactionEnvelope) -> Result<xdr::ScVal> {
        let sim = self.client.simulate_transaction(tx).await?;

        let op_result = sim
            .result
            .or_else(|| sim.results.into_iter().next())
            .ok_or_else(|| anyhow!("simulateTransaction returned no op results"))?;

        // Newer RPC servers return read-only results in `xdr` instead of the
        // legacy `retval` field. Try `retval` first for backwards compatibility.
        let retval_b64 = op_result
            .retval
            .or(op_result.xdr)
            .ok_or_else(|| anyhow!("simulateTransaction missing retval and xdr"))?;

        Ok(xdr::ScVal::from_xdr_base64(
            &retval_b64,
            xdr::Limits::none(),
        )?)
    }

    fn build_find_key_simulation_tx(
        contract_id: &str,
        source_account: &str,
        key: Field,
    ) -> Result<xdr::TransactionEnvelope> {
        Self::build_invoke_contract_tx_envelope(
            source_account,
            xdr::SequenceNumber(0),
            BASE_FEE,
            contract_id,
            "find_key",
            vec![field_to_scval_u256(key)],
            Vec::new(),
        )
    }

    fn build_is_known_root_simulation_tx(
        contract_id: &str,
        source_account: &str,
        root: Field,
    ) -> Result<xdr::TransactionEnvelope> {
        Self::build_invoke_contract_tx_envelope(
            source_account,
            xdr::SequenceNumber(0),
            BASE_FEE,
            contract_id,
            "is_known_root",
            vec![field_to_scval_u256(root)],
            Vec::new(),
        )
    }

    pub(crate) fn build_invoke_contract_tx_envelope(
        source_account: &str,
        seq_num: xdr::SequenceNumber,
        fee: u32,
        contract_id: &str,
        function: &str,
        args: Vec<xdr::ScVal>,
        auth_entries: Vec<xdr::SorobanAuthorizationEntry>,
    ) -> Result<xdr::TransactionEnvelope> {
        let source = Self::muxed_account_from_g(source_account)?;
        let contract_address = Self::contract_scaddress_from_str(contract_id)?;
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

    fn parse_find_result(val: &xdr::ScVal) -> Result<ParsedFindResult> {
        let xdr::ScVal::Map(Some(map)) = val else {
            return Err(anyhow!("FindResult: expected ScVal::Map, got {val:?}"));
        };

        let mut fields = std::collections::HashMap::<String, xdr::ScVal>::new();
        for xdr::ScMapEntry { key, val } in map.iter() {
            let name = match key {
                xdr::ScVal::Symbol(sym) => sym.to_utf8_string()?,
                _ => {
                    return Err(anyhow!(
                        "FindResult: field name should be a symbol: {key:?}"
                    ));
                }
            };
            fields.insert(name, val.clone());
        }

        let found = scval_to_bool(
            fields
                .get("found")
                .ok_or_else(|| anyhow!("FindResult missing field: found"))?,
        )?;

        let mut siblings = Vec::new();
        if let Some(v) = fields.get("siblings") {
            match v {
                xdr::ScVal::Vec(Some(sc_vec)) => {
                    for inner in sc_vec.0.iter() {
                        let u = scval_to_u256(inner)?;
                        siblings.push(Field::try_from_u256(u)?);
                    }
                }
                xdr::ScVal::Vec(None) => {}
                other => return Err(anyhow!("FindResult.siblings: unexpected ScVal: {other:?}")),
            }
        }

        let not_found_key = fields
            .get("not_found_key")
            .or_else(|| fields.get("notFoundKey"))
            .map(scval_to_u256)
            .transpose()?
            .map(Field::try_from_u256)
            .transpose()?
            .unwrap_or(Field::ZERO);

        let not_found_value = fields
            .get("not_found_value")
            .or_else(|| fields.get("notFoundValue"))
            .map(scval_to_u256)
            .transpose()?
            .map(Field::try_from_u256)
            .transpose()?
            .unwrap_or(Field::ZERO);

        let is_old0 = fields
            .get("is_old0")
            .or_else(|| fields.get("isOld0"))
            .map(scval_to_bool)
            .transpose()?
            .unwrap_or(false);

        Ok(ParsedFindResult {
            found,
            siblings,
            not_found_key,
            not_found_value,
            is_old0,
        })
    }

    fn muxed_account_from_g(account: &str) -> Result<xdr::MuxedAccount> {
        let pk = ed25519::PublicKey::from_string(account)?;
        Ok(xdr::MuxedAccount::Ed25519(xdr::Uint256(pk.0)))
    }

    fn contract_scaddress_from_str(contract_id: &str) -> Result<xdr::ScAddress> {
        let contract = stellar_strkey::Contract::from_str(contract_id)?;
        Ok(xdr::ScAddress::Contract(xdr::ContractId(xdr::Hash(
            contract.0,
        ))))
    }
}
