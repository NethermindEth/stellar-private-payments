use super::{ContractConfig, EncryptionPublicKey, NoteOwnerAddress, NotePublicKey, SignerAddress};
use serde::{Deserialize, Serialize};

/// Circuit bytes for lazy prover init (load via platform I/O before
/// constructing a [`crate::Client`] prover).
#[derive(Debug, Clone)]
pub struct ProverArtifacts {
    pub proving_key: Vec<u8>,
    pub circuit_graph: Vec<u8>,
    pub circuit_r1cs: Vec<u8>,
}

impl ProverArtifacts {
    pub fn empty() -> Self {
        Self {
            proving_key: Vec::new(),
            circuit_graph: Vec::new(),
            circuit_r1cs: Vec::new(),
        }
    }
}

/// Per-pool session config (deployment, pool contract, the two identities).
///
/// `user_address` owns the notes; `signer_address` signs the transaction,
/// sources its envelope and pays the fee. Distinct types so that passing one
/// where the other belongs cannot compile — see
/// [`crate::types::SignerAddress`]. Every caller currently sets them to the
/// same account.
#[derive(Debug, Clone)]
pub struct PrivatePoolConfig {
    pub contract_config: ContractConfig,
    pub pool_contract_id: String,
    pub user_address: NoteOwnerAddress,
    pub signer_address: SignerAddress,
}

impl PrivatePoolConfig {
    pub fn validate(&self) -> Result<(), crate::error::Error> {
        if self.pool_contract_id.is_empty() {
            return Err(crate::error::Error::InvalidConfig(
                "pool_contract_id must not be empty".into(),
            ));
        }
        if self.user_address.is_empty() {
            return Err(crate::error::Error::InvalidConfig(
                "user_address must not be empty".into(),
            ));
        }
        if self.signer_address.is_empty() {
            return Err(crate::error::Error::InvalidConfig(
                "signer_address must not be empty".into(),
            ));
        }
        self.contract_config
            .pool(&self.pool_contract_id)
            .map_err(|e| crate::error::Error::InvalidConfig(e.to_string()))?;
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TransactionResult {
    pub tx_hash: String,
}

#[derive(Debug, Clone)]
pub enum TransferRecipient {
    Address(String),
    Keys {
        note_public_key: NotePublicKey,
        encryption_public_key: EncryptionPublicKey,
    },
}

impl TransferRecipient {
    pub fn keys(
        note_public_key: NotePublicKey,
        encryption_public_key: EncryptionPublicKey,
    ) -> Self {
        Self::Keys {
            note_public_key,
            encryption_public_key,
        }
    }
}

impl From<String> for TransferRecipient {
    fn from(address: String) -> Self {
        Self::Address(address)
    }
}

impl From<&str> for TransferRecipient {
    fn from(address: &str) -> Self {
        Self::Address(address.to_string())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Estimate {
    pub tx_count: u32,
}

#[derive(Debug, Clone)]
pub struct SignedTransaction {
    pub signed_xdr: String,
}

#[cfg(test)]
mod split_tests {
    use super::*;
    use crate::types::ContractConfig;

    const OWNER: &str = "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF";
    const SIGNER: &str = "GBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBK";

    fn config(user: &str, signer: &str) -> PrivatePoolConfig {
        PrivatePoolConfig {
            // Contents are irrelevant here: validate() checks both addresses
            // before it looks the pool up, so these tests never reach it.
            contract_config: ContractConfig {
                network: String::new(),
                deployer: String::new(),
                admin: String::new(),
                asp_membership: String::new(),
                asp_non_membership: String::new(),
                verifiers: Default::default(),
                public_key_registry: String::new(),
                pools: Vec::new(),
            },
            pool_contract_id: "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".into(),
            user_address: NoteOwnerAddress::new(user),
            signer_address: SignerAddress::new(signer),
        }
    }

    /// Crossing the fields must fail rather than silently sign as the wrong
    /// account.
    #[test]
    fn distinct_identities_are_kept_distinct() {
        let cfg = config(OWNER, SIGNER);
        assert_eq!(cfg.user_address.as_str(), OWNER);
        assert_eq!(cfg.signer_address.as_str(), SIGNER);
        assert_ne!(cfg.user_address.as_str(), cfg.signer_address.as_str());
    }

    /// Both set to the note owner is legitimate.
    #[test]
    fn same_account_for_both_is_legitimate() {
        let cfg = config(OWNER, OWNER);
        assert_eq!(cfg.user_address.as_str(), cfg.signer_address.as_str());
    }

    /// An empty signing address must fail validation rather than reach the
    /// chain layer.
    #[test]
    fn validate_requires_both_addresses() {
        let missing_signer = config(OWNER, "");
        let err = missing_signer
            .validate()
            .expect_err("empty signer_address must be rejected");
        assert!(
            err.to_string().contains("signer_address"),
            "error should name the field that was empty, got: {err}"
        );

        let missing_owner = config("", SIGNER);
        let err = missing_owner
            .validate()
            .expect_err("empty user_address must be rejected");
        assert!(
            err.to_string().contains("user_address"),
            "error should name the field that was empty, got: {err}"
        );
    }
}
