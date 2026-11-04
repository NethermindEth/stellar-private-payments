//! Signing status and submission of admin call envelopes, for any role.

use anyhow::{Context, anyhow};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use stellar_xdr::{self as xdr, Limits, ReadXdr};

use crate::{
    Error,
    chain::{RpcClient, TxConfirmStatus, confirm_tx, network_id, submit_tx},
};

use super::call::{OperatorCall, describe};

/// One key that may sign for an admin account.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignerWeight {
    /// `G…` strkey of the signing key.
    pub key: String,
    pub weight: u32,
    /// Whether the envelope already carries this key's signature.
    pub signed: bool,
}

/// How far an envelope is from the weight its source requires.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SigningStatus {
    /// The account's medium threshold, at least 1: contract calls need it.
    pub threshold: u32,
    pub signers: Vec<SignerWeight>,
    /// Total weight of the keys that signed.
    pub signed_weight: u32,
}

impl SigningStatus {
    pub fn is_ready(&self) -> bool {
        self.signed_weight >= self.threshold
    }
}

/// Where a submitted admin call stands.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CallStatus {
    Success,
    /// The call landed and failed; `result_xdr` is the base64
    /// `TransactionResult`, when the RPC returned one.
    Failed {
        result_xdr: Option<String>,
    },
    Pending,
}

/// Session for reading, submitting and confirming admin call envelopes.
pub struct Envelopes {
    rpc: RpcClient,
    network_passphrase: String,
}

impl Envelopes {
    pub fn open(rpc_url: &str, network_passphrase: &str) -> Result<Self, Error> {
        Ok(Self {
            rpc: RpcClient::new(rpc_url)?,
            network_passphrase: network_passphrase.to_string(),
        })
    }

    /// Reads an admin call envelope; see [`super::describe`].
    pub fn describe(&self, envelope_xdr: &str) -> Result<OperatorCall, Error> {
        describe(&decode(envelope_xdr)?)
    }

    /// Reads the source's signers and which of them signed `envelope_xdr`.
    pub async fn signing_status(&self, envelope_xdr: &str) -> Result<SigningStatus, Error> {
        let envelope = decode(envelope_xdr)?;
        let call = describe(&envelope)?;
        let account = self.rpc.get_account(&call.source).await?;
        signing_status(&account, &envelope, &self.network_passphrase)
    }

    /// Sends a signed envelope and returns its transaction hash.
    pub async fn submit(&self, signed_envelope_xdr: &str) -> Result<String, Error> {
        let envelope = decode(signed_envelope_xdr)?;
        describe(&envelope)?;
        Ok(submit_tx(&self.rpc, &envelope).await?)
    }

    /// Polls a submitted call once.
    pub async fn confirm(&self, hash: &str) -> Result<CallStatus, Error> {
        Ok(match confirm_tx(&self.rpc, hash).await? {
            TxConfirmStatus::Success => CallStatus::Success,
            TxConfirmStatus::Failed { result_xdr } => CallStatus::Failed { result_xdr },
            TxConfirmStatus::Pending => CallStatus::Pending,
        })
    }
}

fn decode(envelope_xdr: &str) -> Result<xdr::TransactionEnvelope, Error> {
    Ok(
        xdr::TransactionEnvelope::from_xdr_base64(envelope_xdr.trim(), Limits::none())
            .context("decode transaction envelope")?,
    )
}

fn signing_status(
    account: &xdr::AccountEntry,
    envelope: &xdr::TransactionEnvelope,
    network_passphrase: &str,
) -> Result<SigningStatus, Error> {
    let xdr::TransactionEnvelope::Tx(v1) = envelope else {
        return Err(anyhow!("expected a v1 envelope").into());
    };
    let hash = envelope
        .hash(network_id(network_passphrase))
        .context("hash transaction envelope")?;
    let [master, _, medium, _] = account.thresholds.0;

    let xdr::PublicKey::PublicKeyTypeEd25519(xdr::Uint256(master_key)) = &account.account_id.0;
    let keys =
        std::iter::once((*master_key, u32::from(master))).chain(account.signers.iter().filter_map(
            |signer| match &signer.key {
                xdr::SignerKey::Ed25519(xdr::Uint256(key)) => Some((*key, signer.weight)),
                _ => None,
            },
        ));
    let signers: Vec<SignerWeight> = keys
        .map(|(key, weight)| SignerWeight {
            key: stellar_strkey::ed25519::PublicKey(key)
                .to_string()
                .as_str()
                .to_string(),
            weight,
            signed: v1
                .signatures
                .iter()
                .any(|signature| signed_by(&key, &hash, signature)),
        })
        .collect();
    let signed_weight = signers
        .iter()
        .filter(|signer| signer.signed)
        .map(|signer| signer.weight)
        .fold(0u32, u32::saturating_add);

    Ok(SigningStatus {
        threshold: u32::from(medium).max(1),
        signers,
        signed_weight,
    })
}

fn signed_by(key: &[u8; 32], hash: &[u8; 32], signature: &xdr::DecoratedSignature) -> bool {
    if signature.hint.0 != key[28..32] {
        return false;
    }
    let (Ok(verifying_key), Ok(bytes)) = (
        VerifyingKey::from_bytes(key),
        <[u8; 64]>::try_from(signature.signature.as_slice()),
    ) else {
        return false;
    };
    verifying_key
        .verify(hash, &Signature::from_bytes(&bytes))
        .is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain::LocalSigner;

    const PASSPHRASE: &str = "Test SDF Network ; September 2015";

    fn envelope(source: [u8; 32]) -> xdr::TransactionEnvelope {
        xdr::TransactionEnvelope::Tx(xdr::TransactionV1Envelope {
            tx: xdr::Transaction {
                source_account: xdr::MuxedAccount::Ed25519(xdr::Uint256(source)),
                fee: 100,
                seq_num: xdr::SequenceNumber(1),
                cond: xdr::Preconditions::None,
                memo: xdr::Memo::None,
                operations: xdr::VecM::default(),
                ext: xdr::TransactionExt::V0,
            },
            signatures: xdr::VecM::default(),
        })
    }

    fn public_key(signer: &LocalSigner) -> [u8; 32] {
        stellar_strkey::ed25519::PublicKey::from_string(signer.public_key())
            .expect("strkey")
            .0
    }

    fn account(
        master: [u8; 32],
        thresholds: [u8; 4],
        signers: &[([u8; 32], u32)],
    ) -> xdr::AccountEntry {
        xdr::AccountEntry {
            account_id: xdr::AccountId(xdr::PublicKey::PublicKeyTypeEd25519(xdr::Uint256(master))),
            balance: 0,
            seq_num: xdr::SequenceNumber(0),
            num_sub_entries: 0,
            inflation_dest: None,
            flags: 0,
            home_domain: xdr::String32::default(),
            thresholds: xdr::Thresholds(thresholds),
            signers: signers
                .iter()
                .map(|(key, weight)| xdr::Signer {
                    key: xdr::SignerKey::Ed25519(xdr::Uint256(*key)),
                    weight: *weight,
                })
                .collect::<Vec<_>>()
                .try_into()
                .expect("signers"),
            ext: xdr::AccountEntryExt::V0,
        }
    }

    #[test]
    fn signing_status_counts_the_weight_of_valid_signatures() {
        let master = LocalSigner::from_seed([1; 32]);
        let second = LocalSigner::from_seed([2; 32]);
        let third = LocalSigner::from_seed([3; 32]);
        let account = account(
            public_key(&master),
            [1, 0, 2, 0],
            &[(public_key(&second), 1), (public_key(&third), 1)],
        );
        let unsigned = envelope(public_key(&master));

        let status = signing_status(&account, &unsigned, PASSPHRASE).expect("status");
        assert_eq!(status.threshold, 2);
        assert_eq!(status.signed_weight, 0);
        assert!(!status.is_ready());

        let once = second
            .sign_transaction(unsigned.clone(), PASSPHRASE)
            .expect("sign");
        let status = signing_status(&account, &once, PASSPHRASE).expect("status");
        assert_eq!(status.signed_weight, 1);
        assert!(
            status
                .signers
                .iter()
                .any(|s| s.key == second.public_key() && s.signed)
        );

        let twice = master.sign_transaction(once, PASSPHRASE).expect("sign");
        let status = signing_status(&account, &twice, PASSPHRASE).expect("status");
        assert_eq!(status.signed_weight, 2);
        assert!(status.is_ready());
    }

    #[test]
    fn a_signature_for_another_network_does_not_count() {
        let master = LocalSigner::from_seed([1; 32]);
        let account = account(public_key(&master), [1, 0, 0, 0], &[]);
        let signed = master
            .sign_transaction(envelope(public_key(&master)), "another network")
            .expect("sign");
        let status = signing_status(&account, &signed, PASSPHRASE).expect("status");
        assert_eq!(status.threshold, 1);
        assert_eq!(status.signed_weight, 0);
    }
}
