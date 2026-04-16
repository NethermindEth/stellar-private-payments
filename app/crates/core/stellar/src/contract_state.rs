use crate::{
    DEPLOYMENT,
    conversions::{
        scval_to_address_string, scval_to_bool, scval_to_u32, scval_to_u64, scval_to_u256,
    },
    rpc::Client,
};
use anyhow::{Result, anyhow};
use futures::try_join;
use serde::{Deserialize, Serialize};
use std::str::FromStr;
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
    client: Client,
    config: ContractConfig,
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

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PreparedSorobanTx {
    pub tx_xdr: String,
    /// Base64-encoded XDR `SorobanAuthorizationEntry` list from simulation.
    pub auth_entries: Vec<String>,
}

impl StateFetcher {
    fn u256_to_i128_checked(v: U256, what: &'static str) -> Result<i128> {
        let mut be = [0u8; 32];
        v.to_big_endian(&mut be);

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

        Ok(low as i128)
    }

    pub fn new(rpc_url: &str) -> Result<Self> {
        let config: ContractConfig = serde_json::from_str(DEPLOYMENT)?;
        Ok(Self {
            client: Client::new(rpc_url)?,
            config,
        })
    }

    pub fn contract_config(&self) -> &ContractConfig {
        &self.config
    }

    pub async fn pool_contract_state(&self) -> Result<PoolInfo> {
        let (pool_state, latest_ledger) = self
            .client
            .get_contract_data(
                &self.config.pool,
                &[
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
                &[],
            )
            .await?;
        let (merkle_current_root_index, merkle_root) =
            if let Some(current_roout_index) = pool_state.get("CurrentRootIndex") {
                let merkle_current_root_index = scval_to_u32(current_roout_index)?;
                let (state, _root_ledger) = self
                    .client
                    .get_contract_data(
                        &self.config.pool,
                        &[],
                        &[("Root", merkle_current_root_index)],
                    )
                    .await?;
                (
                    Some(merkle_current_root_index),
                    Some(scval_to_u256(get_state!(state, "Root", self.config.pool)?)?),
                )
            } else {
                (None, None)
            };

        let merkle_levels = scval_to_u32(get_state!(pool_state, "Levels", self.config.pool)?)?;
        let merkle_capacity = 2u64.pow(merkle_levels);
        let merkle_next_index =
            scval_to_u64(get_state!(pool_state, "NextIndex", self.config.pool)?)?;
        let maximum_deposit_amount_u256 = scval_to_u256(get_state!(
            pool_state,
            "MaximumDepositAmount",
            self.config.pool
        )?)?;
        let maximum_deposit_amount = ExtAmount::from(Self::u256_to_i128_checked(
            maximum_deposit_amount_u256,
            "maximum_deposit_amount",
        )?);
        let merkle_root = merkle_root.map(Field::try_from_u256).transpose()?;

        let pool = PoolInfo {
            success: true,
            ledger: latest_ledger,
            contract_id: self.config.pool.clone(),
            contract_type: "Privacy Pool".to_string(),
            admin: scval_to_address_string(get_state!(pool_state, "Admin", self.config.pool)?)?,
            token: scval_to_address_string(get_state!(pool_state, "Token", self.config.pool)?)?,
            verifier: scval_to_address_string(get_state!(
                pool_state,
                "Verifier",
                self.config.pool
            )?)?,
            aspmembership: scval_to_address_string(get_state!(
                pool_state,
                "ASPMembership",
                self.config.pool
            )?)?,
            aspnonmembership: scval_to_address_string(get_state!(
                pool_state,
                "ASPNonMembership",
                self.config.pool
            )?)?,
            merkle_levels,
            merkle_current_root_index,
            merkle_next_index: merkle_next_index.to_string(),
            maximum_deposit_amount,
            merkle_root,
            merkle_capacity,
            total_commitments: merkle_next_index.to_string(),
        };
        Ok(pool)
    }

    pub async fn asp_membership_contract_state(&self) -> Result<AspMembership> {
        let (asp_membership_state, latest_ledger) = self
            .client
            .get_contract_data(
                &self.config.asp_membership,
                &["Root", "Levels", "NextIndex", "Admin", "AdminInsertOnly"],
                &[],
            )
            .await?;
        let asp_mem_next_index = scval_to_u64(get_state!(
            asp_membership_state,
            "NextIndex",
            self.config.asp_membership
        )?)?;
        let asp_mem_levels = scval_to_u32(get_state!(
            asp_membership_state,
            "Levels",
            self.config.asp_membership
        )?)?;
        let asp_mem_capacity = 2u64.pow(asp_mem_levels);
        let root_u256 = scval_to_u256(get_state!(
            asp_membership_state,
            "Root",
            self.config.asp_membership
        )?)?;
        let root = Field::try_from_u256(root_u256)?;

        let asp_membership = AspMembership {
            success: true,
            ledger: latest_ledger,
            contract_id: self.config.asp_membership.clone(),
            contract_type: "ASP Membership".to_string(),
            root,
            levels: asp_mem_levels,
            next_index: asp_mem_next_index.to_string(),
            admin: scval_to_address_string(get_state!(
                asp_membership_state,
                "Admin",
                self.config.asp_membership
            )?)?,
            admin_insert_only: scval_to_bool(get_state!(
                asp_membership_state,
                "AdminInsertOnly",
                self.config.asp_membership
            )?)?,
            capacity: asp_mem_capacity,
            used_slots: asp_mem_next_index.to_string(),
        };
        Ok(asp_membership)
    }

    pub async fn asp_nonmembership_contract_state(&self) -> Result<AspNonMembership> {
        let (asp_non_membership_state, latest_ledger) = self
            .client
            .get_contract_data(&self.config.asp_non_membership, &["Root", "Admin"], &[])
            .await?;
        let asp_nonmem_root_u256 = scval_to_u256(get_state!(
            asp_non_membership_state,
            "Root",
            self.config.asp_non_membership
        )?)?;
        let asp_nonmem_root = Field::try_from_u256(asp_nonmem_root_u256)?;
        let asp_non_membership = AspNonMembership {
            success: true,
            ledger: latest_ledger,
            contract_id: self.config.asp_non_membership.clone(),
            contract_type: "ASP Non-Membership (Sparse Merkle Tree)".to_string(),
            root: asp_nonmem_root,
            is_empty: asp_nonmem_root.as_u256() == U256::from(0u64),
            admin: scval_to_address_string(get_state!(
                asp_non_membership_state,
                "Admin",
                self.config.asp_non_membership
            )?)?,
        };
        Ok(asp_non_membership)
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
        let sim = self.client.simulate_transaction(&tx).await?;

        let op_result = sim
            .result
            .or_else(|| sim.results.into_iter().next())
            .ok_or_else(|| anyhow!("simulateTransaction returned no op results"))?;

        let retval_b64 = op_result
            .retval
            .ok_or_else(|| anyhow!("simulateTransaction missing retval"))?;

        let retval = xdr::ScVal::from_xdr_base64(&retval_b64, xdr::Limits::none())?;
        let parsed = Self::parse_find_result(&retval)?;

        if parsed.found {
            return Err(anyhow!(
                "Key exists in non-membership tree (user is sanctioned)"
            ));
        }

        // Pad/trim siblings to circuit SMT depth.
        let mut siblings = parsed.siblings;
        if siblings.len() < smt_depth {
            siblings.extend(core::iter::repeat(Field::ZERO).take(smt_depth - siblings.len()));
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

    fn build_find_key_simulation_tx(
        contract_id: &str,
        source_account: &str,
        key: Field,
    ) -> Result<xdr::TransactionEnvelope> {
        Self::build_invoke_contract_tx_envelope(
            source_account,
            xdr::SequenceNumber(0),
            100,
            contract_id,
            "find_key",
            vec![Self::field_to_scval_u256(key)],
            Vec::new(),
        )
    }

    fn build_invoke_contract_tx_envelope(
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

    fn field_to_scval_u256(v: Field) -> xdr::ScVal {
        let mut be = [0u8; 32];
        v.as_u256().to_big_endian(&mut be);

        let hi_hi = u64::from_be_bytes(be[0..8].try_into().unwrap());
        let hi_lo = u64::from_be_bytes(be[8..16].try_into().unwrap());
        let lo_hi = u64::from_be_bytes(be[16..24].try_into().unwrap());
        let lo_lo = u64::from_be_bytes(be[24..32].try_into().unwrap());

        xdr::ScVal::U256(xdr::UInt256Parts {
            hi_hi,
            hi_lo,
            lo_hi,
            lo_lo,
        })
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

    pub async fn all_contracts_data(&self) -> Result<ContractsStateData> {
        let (pool, asp_membership, asp_non_membership) = try_join!(
            self.pool_contract_state(),
            self.asp_membership_contract_state(),
            self.asp_nonmembership_contract_state(),
        )?;

        let data = ContractsStateData {
            success: true,
            network: "testnet".to_string(),
            pool,
            asp_membership,
            asp_non_membership,
        };

        Ok(data)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_ext_data_scval_has_expected_shape() {
        let ext = ExtData {
            recipient: "GDF4BXPQY5N4BEO24UIHM4NVB62MW7HDWH7SVHKLVZAMLP5IIHCFQORC".to_string(),
            ext_amount: ExtAmount::from(123i128),
            encrypted_output0: vec![1, 2, 3],
            encrypted_output1: vec![4, 5],
        };

        let sc = StateFetcher::encode_ext_data_scval(&ext).expect("encode");
        let xdr::ScVal::Map(Some(map)) = sc else {
            panic!("expected map");
        };

        let mut keys: Vec<String> = map
            .0
            .iter()
            .map(|e| match &e.key {
                xdr::ScVal::Symbol(sym) => sym.to_utf8_string().unwrap(),
                _ => panic!("key not symbol"),
            })
            .collect();
        keys.sort();
        assert_eq!(
            keys,
            vec![
                "encrypted_output0",
                "encrypted_output1",
                "ext_amount",
                "recipient"
            ]
        );
    }

    #[test]
    fn encode_pool_proof_scval_has_expected_shape() {
        let public = OnchainProofPublicInputs {
            root: Field::ONE,
            input_nullifiers: [Field::ONE, Field::ONE],
            output_commitment0: Field::ONE,
            output_commitment1: Field::ONE,
            public_amount: Field::ONE,
            ext_data_hash_be: [7u8; 32],
            asp_membership_root: Field::ONE,
            asp_non_membership_root: Field::ONE,
        };
        let proof = vec![0u8; 256];

        let sc = StateFetcher::encode_pool_proof_scval(&public, &proof).expect("encode");
        let xdr::ScVal::Map(Some(map)) = sc else {
            panic!("expected map");
        };

        // Ensure the nested `proof` struct exists and has a/b/c.
        let mut proof_val = None;
        for e in map.0.iter() {
            if let xdr::ScVal::Symbol(sym) = &e.key {
                if sym.to_utf8_string().unwrap() == "proof" {
                    proof_val = Some(e.val.clone());
                }
            }
        }
        let proof_val = proof_val.expect("proof field");
        let xdr::ScVal::Map(Some(inner)) = proof_val else {
            panic!("expected inner proof map");
        };
        let mut inner_keys: Vec<String> = inner
            .0
            .iter()
            .map(|e| match &e.key {
                xdr::ScVal::Symbol(sym) => sym.to_utf8_string().unwrap(),
                _ => panic!("inner key not symbol"),
            })
            .collect();
        inner_keys.sort();
        assert_eq!(inner_keys, vec!["a", "b", "c"]);
    }
}
