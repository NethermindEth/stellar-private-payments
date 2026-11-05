//! Signing status and submission of admin call envelopes, for any role.

use anyhow::{Context, anyhow};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use stellar_xdr::{self as xdr, Limits, ReadXdr};

use crate::{
    Error,
    chain::{RpcClient, TxConfirmStatus, confirm_tx, network_id, submit_tx},
};

use super::call::{OperatorCall, describe, unix_now};

/// How long [`Envelopes::state`] looks for a call whose sequence number is
/// used before it reports another transaction: about two ledger closes.
const LANDED_POLL_ATTEMPTS: u32 = 10;
const LANDED_POLL_INTERVAL_MS: u32 = 1_000;

/// One key that may sign for an admin account.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignerWeight {
    /// Strkey of the signer: `G…` for a key, `T…` for a pre-authorized
    /// transaction, `X…` for a hash, `P…` for a signed payload.
    pub key: String,
    pub weight: u32,
    /// Whether the envelope already carries this key's signature; `None` for
    /// a signer that is not a plain key, which no envelope signature shows.
    pub signed: Option<bool>,
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
    /// `TransactionResult`, when the RPC returned one, and `host_error` the
    /// contract or host error that stopped it, such as `Error(Contract, #6)`.
    Failed {
        result_xdr: Option<String>,
        host_error: Option<String>,
    },
    Pending,
}

/// Whether an admin call can still land, read before signing or sending it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CallState {
    /// Its sequence number is unused and its time bound has not passed.
    Live,
    /// It landed and succeeded, whoever sent it.
    Landed { hash: String },
    /// It landed and failed; the rest as in [`CallStatus::Failed`].
    Failed {
        hash: String,
        result_xdr: Option<String>,
        host_error: Option<String>,
    },
    /// The source sent another transaction with its sequence number first.
    SequenceUsed,
    /// Its time bound passed before it landed.
    Expired,
}

/// Names the code of a base64 `TransactionResult`, as [`CallStatus::Failed`]
/// carries it: `TxBadSeq`, or `TxFailed: InvokeHostFunctionTrapped`.
pub fn result_code(result_xdr: &str) -> Option<String> {
    crate::chain::result_code(result_xdr)
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

    /// Whether `envelope_xdr` can still land, or how it already did.
    ///
    /// The RPC can serve the account a ledger ahead of the transaction, so
    /// once the sequence number is used this polls the call's hash for up to
    /// [`LANDED_POLL_ATTEMPTS`] seconds before it reports
    /// [`CallState::SequenceUsed`].
    pub async fn state(&self, envelope_xdr: &str) -> Result<CallState, Error> {
        let envelope = decode(envelope_xdr)?;
        let call = describe(&envelope)?;
        let account = self.rpc.get_account(&call.source).await?;
        if let Some(state) = state_before_landing(account.seq_num.0, &call, unix_now()?) {
            return Ok(state);
        }
        let hash = hex::encode(
            envelope
                .hash(network_id(&self.network_passphrase))
                .context("hash transaction envelope")?,
        );
        for attempt in 1..=LANDED_POLL_ATTEMPTS {
            if attempt > 1 {
                crate::sleep::sleep(LANDED_POLL_INTERVAL_MS).await;
            }
            match confirm_tx(&self.rpc, &hash).await? {
                TxConfirmStatus::Success => return Ok(CallState::Landed { hash }),
                TxConfirmStatus::Failed {
                    result_xdr,
                    host_error,
                } => {
                    return Ok(CallState::Failed {
                        hash,
                        result_xdr,
                        host_error,
                    });
                }
                TxConfirmStatus::Pending => {}
            }
        }
        Ok(CallState::SequenceUsed)
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
            TxConfirmStatus::Failed {
                result_xdr,
                host_error,
            } => CallStatus::Failed {
                result_xdr,
                host_error,
            },
            TxConfirmStatus::Pending => CallStatus::Pending,
        })
    }
}

/// The state of `call` while its source is at `account_sequence`, or `None`
/// once a transaction used the call's sequence number.
fn state_before_landing(account_sequence: i64, call: &OperatorCall, now: u64) -> Option<CallState> {
    if account_sequence >= call.sequence {
        return None;
    }
    Some(if call.valid_until <= now {
        CallState::Expired
    } else {
        CallState::Live
    })
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

    let xdr::PublicKey::PublicKeyTypeEd25519(master_key) = &account.account_id.0;
    let master = xdr::Signer {
        key: xdr::SignerKey::Ed25519(master_key.clone()),
        weight: u32::from(master),
    };
    let signers: Vec<SignerWeight> = std::iter::once(&master)
        .chain(account.signers.iter())
        .map(|signer| SignerWeight {
            key: signer.key.to_string(),
            weight: signer.weight,
            signed: match &signer.key {
                xdr::SignerKey::Ed25519(xdr::Uint256(key)) => Some(
                    v1.signatures
                        .iter()
                        .any(|signature| signed_by(key, &hash, signature)),
                ),
                _ => None,
            },
        })
        .collect();
    let signed_weight = signers
        .iter()
        .filter(|signer| signer.signed == Some(true))
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
                .any(|s| s.key == second.public_key() && s.signed == Some(true))
        );

        let twice = master.sign_transaction(once, PASSPHRASE).expect("sign");
        let status = signing_status(&account, &twice, PASSPHRASE).expect("status");
        assert_eq!(status.signed_weight, 2);
        assert!(status.is_ready());
    }

    #[test]
    fn a_call_is_live_until_its_sequence_is_used_or_its_bound_passes() {
        let call = OperatorCall {
            source: String::new(),
            sequence: 11,
            fee: 100,
            valid_until: 1_000,
            contract_id: String::new(),
            method: String::new(),
            args: Vec::new(),
        };
        assert_eq!(state_before_landing(10, &call, 999), Some(CallState::Live));
        assert_eq!(
            state_before_landing(10, &call, 1_000),
            Some(CallState::Expired)
        );
        assert_eq!(state_before_landing(11, &call, 999), None);
    }

    /// The RPC can serve an account whose sequence a call used before it
    /// serves the call.
    #[cfg(not(target_arch = "wasm32"))]
    #[tokio::test]
    async fn state_waits_for_a_call_its_account_already_shows() {
        use serde_json::json;
        use stellar_xdr::WriteXdr;
        use wiremock::{Mock, MockServer, ResponseTemplate, matchers::body_partial_json};

        let envelope = super::super::call::tests::envelope();
        let xdr::TransactionEnvelope::Tx(v1) = &envelope else {
            unreachable!()
        };
        let xdr::MuxedAccount::Ed25519(xdr::Uint256(source)) = v1.tx.source_account else {
            unreachable!()
        };
        let mut used = account(source, [1, 0, 1, 0], &[]);
        used.seq_num = v1.tx.seq_num.clone();
        let entry = xdr::LedgerEntryData::Account(used);
        let key = xdr::LedgerKey::Account(xdr::LedgerKeyAccount {
            account_id: xdr::AccountId(xdr::PublicKey::PublicKeyTypeEd25519(xdr::Uint256(source))),
        });

        let server = MockServer::start().await;
        let rpc_answer = |result: serde_json::Value| {
            ResponseTemplate::new(200)
                .set_body_json(json!({ "jsonrpc": "2.0", "id": 1, "result": result }))
        };
        Mock::given(body_partial_json(json!({ "method": "getLedgerEntries" })))
            .respond_with(rpc_answer(json!({
                "latestLedger": 100,
                "entries": [{
                    "key": key.to_xdr_base64(Limits::none()).expect("key"),
                    "xdr": entry.to_xdr_base64(Limits::none()).expect("entry"),
                    "lastModifiedLedgerSeq": 99,
                }],
            })))
            .mount(&server)
            .await;
        Mock::given(body_partial_json(json!({ "method": "getTransaction" })))
            .respond_with(rpc_answer(json!({ "status": "NOT_FOUND" })))
            .up_to_n_times(1)
            .with_priority(1)
            .mount(&server)
            .await;
        Mock::given(body_partial_json(json!({ "method": "getTransaction" })))
            .respond_with(rpc_answer(json!({ "status": "SUCCESS" })))
            .with_priority(2)
            .mount(&server)
            .await;

        let envelope_xdr = envelope.to_xdr_base64(Limits::none()).expect("envelope");
        let state = Envelopes::open(&server.uri(), PASSPHRASE)
            .expect("envelopes")
            .state(&envelope_xdr)
            .await
            .expect("state");
        assert!(matches!(state, CallState::Landed { .. }), "{state:?}");
    }

    #[test]
    fn a_signer_that_is_not_a_key_is_listed_as_unknown() {
        let master = LocalSigner::from_seed([1; 32]);
        let mut account = account(public_key(&master), [1, 0, 1, 0], &[]);
        account.signers = vec![xdr::Signer {
            key: xdr::SignerKey::HashX(xdr::Uint256([5; 32])),
            weight: 1,
        }]
        .try_into()
        .expect("signers");
        let status =
            signing_status(&account, &envelope(public_key(&master)), PASSPHRASE).expect("status");
        let hash_x = &status.signers[1];
        assert!(hash_x.key.starts_with('X'), "{}", hash_x.key);
        assert_eq!((hash_x.weight, hash_x.signed), (1, None));
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
