//! Admin-side Global View Key audit over indexed pool events.

use anyhow::{Context, Result};
use std::collections::{HashSet, VecDeque};

use crate::{
    gvk::GvkEvent,
    storage::Storage,
    types::Field,
    zk::gvk::{GvkAuditedNote, try_decrypt_against_commitment_set},
};

/// Stellar RPC event ids start with a 19-character TOID (SEP-0035 operation id)
pub(crate) const TOID_LEN: usize = 19;

const ROW_BATCH: u32 = 256;

/// One output slot from a private `transact` call.
///
/// `commitment` is always present; `note` is `None` for dummy outputs or when
/// decryption/verification fails.
#[derive(Clone, PartialEq, Eq)]
pub struct GvkOutputSlot {
    pub commitment: Field,
    pub note: Option<GvkAuditedNote>,
}

/// One input slot from a private `transact` call.
///
/// `nullifier` is always present; `note` is `None` for dummy inputs, view-only
/// pools (no ciphertext), or when decryption/verification fails.
#[derive(Clone, PartialEq, Eq)]
pub struct GvkSpentInput {
    pub nullifier: Field,
    pub note: Option<GvkAuditedNote>,
}

/// Decrypted notes aligned with on-chain input/output slots for one private
/// `transact` call.
#[derive(Clone, PartialEq, Eq)]
pub struct GvkTxAudit {
    pub ledger: u32,
    pub outputs: Vec<GvkOutputSlot>,
    pub inputs: Vec<GvkSpentInput>,
}

#[derive(Clone, PartialEq, Eq)]
struct TxGroup {
    ledger: u32,
    toid: String,
    outputs: Vec<(Field, crate::types::GlobalViewKeyCiphertext)>,
    nullifiers: Vec<(Field, Option<crate::types::GlobalViewKeyCiphertext>)>,
}

/// Cursor over private transacts for one pool
pub struct GvkAudit<S: Storage> {
    storage: S,
    pool_contract_id: String,
    d_priv: Field,
    after: Option<(u32, String)>,
    commitment_candidates: Option<HashSet<Field>>,
    pending: Option<TxGroup>,
    complete: VecDeque<TxGroup>,
    exhausted: bool,
}

impl<S: Storage> GvkAudit<S> {
    pub fn new(storage: S, pool_contract_id: impl Into<String>, d_priv: Field) -> Self {
        Self {
            storage,
            pool_contract_id: pool_contract_id.into(),
            d_priv,
            after: None,
            commitment_candidates: None,
            pending: None,
            complete: VecDeque::new(),
            exhausted: false,
        }
    }

    pub fn pool_contract_id(&self) -> &str {
        &self.pool_contract_id
    }

    /// Fetch and audit the next transaction, or `None` when exhausted.
    pub async fn next_tx(&mut self) -> Result<Option<GvkTxAudit>> {
        loop {
            if let Some(group) = self.complete.pop_front() {
                return Ok(Some(self.audit_group(group).await?));
            }

            if self.exhausted {
                return match self.pending.take() {
                    Some(group) => Ok(Some(self.audit_group(group).await?)),
                    None => Ok(None),
                };
            }

            self.load_batch().await?;
        }
    }

    async fn load_batch(&mut self) -> Result<()> {
        let events = self
            .storage
            .list_pool_gvk_events(&self.pool_contract_id, self.after.clone(), ROW_BATCH)
            .await
            .map_err(|e| anyhow::anyhow!("{e}"))?;
        if events.len() < ROW_BATCH as usize {
            self.exhausted = true;
        }
        if events.is_empty() {
            self.exhausted = true;
            return Ok(());
        }

        if let Some(last) = events.last() {
            self.after = Some((last.ledger(), last.event_id().to_string()));
        }

        for event in events {
            let key = tx_group_key(&event)?;
            match &mut self.pending {
                None => self.pending = Some(TxGroup::from_event(event, key)),
                Some(pending) if pending.ledger == key.0 && pending.toid == key.1 => {
                    pending.push_event(event)
                }
                Some(pending) => {
                    let complete = std::mem::replace(pending, TxGroup::from_event(event, key));
                    self.complete.push_back(complete);
                }
            }
        }

        Ok(())
    }

    async fn audit_group(&mut self, group: TxGroup) -> Result<GvkTxAudit> {
        let d_priv = self.d_priv;

        let mut outputs = Vec::with_capacity(group.outputs.len());
        for (commitment, ciphertext) in group.outputs {
            let note = ciphertext.decrypt_audited_for_commitment(&d_priv, &commitment);
            outputs.push(GvkOutputSlot { commitment, note });
        }

        let candidates = self.commitment_candidates().await?;
        let mut inputs = Vec::with_capacity(group.nullifiers.len());
        for (nullifier, ciphertext) in group.nullifiers {
            let note = ciphertext
                .as_ref()
                .and_then(|ct| try_decrypt_against_commitment_set(&d_priv, ct, candidates));
            inputs.push(GvkSpentInput { nullifier, note });
        }

        Ok(GvkTxAudit {
            ledger: group.ledger,
            outputs,
            inputs,
        })
    }

    async fn commitment_candidates(&mut self) -> Result<&HashSet<Field>> {
        if self.commitment_candidates.is_none() {
            let set = self
                .storage
                .list_pool_commitment_hashes(&self.pool_contract_id)
                .await
                .map_err(|e| anyhow::anyhow!("{e}"))?
                .into_iter()
                .collect();
            self.commitment_candidates = Some(set);
        }
        Ok(self
            .commitment_candidates
            .as_ref()
            .expect("just initialized"))
    }
}

impl TxGroup {
    fn from_event(event: GvkEvent, key: (u32, String)) -> Self {
        let mut group = Self {
            ledger: key.0,
            toid: key.1,
            outputs: Vec::new(),
            nullifiers: Vec::new(),
        };
        group.push_event(event);
        group
    }

    fn push_event(&mut self, event: GvkEvent) {
        match event {
            GvkEvent::Commitment {
                commitment,
                gvk_ciphertext,
                ..
            } => self.outputs.push((commitment, gvk_ciphertext)),
            GvkEvent::Nullifier {
                nullifier,
                gvk_ciphertext,
                ..
            } => self.nullifiers.push((nullifier, gvk_ciphertext)),
        }
    }
}

pub(crate) fn toid(event_id: &str) -> Result<&str> {
    event_id
        .get(..TOID_LEN)
        .with_context(|| format!("event id `{event_id}` is shorter than {TOID_LEN} characters"))
}

fn tx_group_key(row: &GvkEvent) -> Result<(u32, String)> {
    Ok((row.ledger(), toid(row.event_id())?.to_string()))
}

/// Decrypt and verify the output note carried by a `NewCommitmentEvent`.
pub fn audit_commitment_event(
    admin_private_key: &Field,
    event: &crate::types::NewCommitmentEvent,
) -> Option<GvkAuditedNote> {
    let ciphertext = event.gvk_ciphertext.as_ref()?;
    ciphertext.decrypt_audited_for_commitment(admin_private_key, &event.commitment)
}

/// Decrypt and verify a traceable-mode input note from a `NewNullifierEvent`.
pub fn audit_nullifier_event(
    admin_private_key: &Field,
    event: &crate::types::NewNullifierEvent,
    candidate_commitments: impl IntoIterator<Item = Field>,
) -> Option<GvkAuditedNote> {
    let ciphertext = event.gvk_ciphertext.as_ref()?;
    crate::zk::gvk::try_decrypt_against_commitments(
        admin_private_key,
        ciphertext,
        candidate_commitments,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        state::Storage as SqliteStorage,
        storage::LocalStorage,
        types::{
            BabyJubJubPoint, ContractEvent, ContractsEventData, NewCommitmentEvent,
            NewNullifierEvent, NoteAmount,
        },
        zk::{
            crypto,
            gvk::{GvkNote, generate_gvk_nonce},
        },
    };
    use std::path::PathBuf;

    fn field(value: u64) -> Field {
        Field(crate::types::U256::from(value))
    }

    fn commitment_for(note: &GvkNote) -> anyhow::Result<Field> {
        let commitment_le = crypto::compute_commitment(
            &note.amount.to_le_bytes(),
            &note.pk.to_le_bytes(),
            &note.blinding.to_le_bytes(),
        )?;
        Field::try_from_le_bytes(
            commitment_le
                .as_slice()
                .try_into()
                .map_err(|_| anyhow::anyhow!("commitment hash is not 32 bytes"))?,
        )
    }

    fn tx_event_id(toid: &str, index: u32) -> String {
        format!("{toid}-{index:010}")
    }

    fn dummy_event(id: &str) -> ContractEvent {
        ContractEvent {
            id: id.to_string(),
            ledger: 1,
            contract_id: "CPOOL".to_string(),
            topics: vec!["dummy".to_string()],
            value: "dummy".to_string(),
        }
    }

    fn temp_db_path(label: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "spp-gvk-audit-{label}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ))
    }

    fn open_audit_db(label: &str) -> anyhow::Result<(PathBuf, LocalStorage)> {
        let path = temp_db_path(label);
        let db = SqliteStorage::connect_file(&path)?;
        drop(db);
        let storage = LocalStorage::open(path.to_str().expect("temp path utf-8"))?;
        Ok((path, storage))
    }

    fn seed_db(
        path: &PathBuf,
        f: impl FnOnce(&mut SqliteStorage) -> anyhow::Result<()>,
    ) -> anyhow::Result<()> {
        let mut db = SqliteStorage::connect_file(path)?;
        f(&mut db)
    }

    #[test]
    fn audit_commitment_event_roundtrip() -> anyhow::Result<()> {
        let d_priv = field(0xA11CE);
        let admin = BabyJubJubPoint::from_priv_scalar(&d_priv).expect("valid admin key");
        let nonce = generate_gvk_nonce()?;
        let note = GvkNote::new(
            field(0xBEEF),
            5_000_000u128.into(),
            field(0x1234),
            field(99),
        );
        let ct = note.encrypt(&admin, &nonce, 2)?;
        let commitment = commitment_for(&note)?;

        let event = NewCommitmentEvent {
            id: "test-event".into(),
            commitment,
            index: 7,
            encrypted_output: vec![],
            gvk_ciphertext: Some(ct),
        };

        let audited = audit_commitment_event(&d_priv, &event).expect("audit output note");
        assert_eq!(audited.note.pk, note.pk);
        assert_eq!(audited.note.amount()?, 5_000_000u128.into());
        assert_eq!(audited.note.blinding, note.blinding);
        assert_eq!(audited.commitment, commitment);
        Ok(())
    }

    #[test]
    fn audit_commitment_event_rejects_tampered_ciphertext() -> anyhow::Result<()> {
        let d_priv = field(0xA11CE);
        let admin = BabyJubJubPoint::from_priv_scalar(&d_priv).expect("valid admin key");
        let note = GvkNote::new(field(1), 1u128.into(), field(2), field(3));
        let mut ct = note.encrypt(&admin, &field(4), 0)?;
        ct.c1 = field(0xFFFF);

        let event = NewCommitmentEvent {
            id: "test-event".into(),
            commitment: field(0xDEAD),
            index: 0,
            encrypted_output: vec![],
            gvk_ciphertext: Some(ct),
        };

        assert!(audit_commitment_event(&d_priv, &event).is_none());
        Ok(())
    }

    #[test]
    fn audit_nullifier_event_finds_matching_commitment() -> anyhow::Result<()> {
        let d_priv = field(0x510);
        let admin = BabyJubJubPoint::from_priv_scalar(&d_priv).expect("valid admin key");
        let note = GvkNote::new(field(0xABC), 42u128.into(), field(0xDEF), field(5));
        let ct = note.encrypt(&admin, &field(9), 0)?;
        let commitment = commitment_for(&note)?;

        let event = NewNullifierEvent {
            id: "nullifier-event".into(),
            nullifier: field(0x999),
            gvk_ciphertext: Some(ct),
        };

        let audited = audit_nullifier_event(&d_priv, &event, [field(0x1111), commitment])
            .expect("match spent note");
        assert_eq!(audited.commitment, commitment);
        assert_eq!(audited.note.amount()?, 42u128.into());
        Ok(())
    }

    #[test]
    fn toid_parses_from_event_id() -> Result<()> {
        assert_eq!(
            toid("0000000000000000002-0000000001")?,
            "0000000000000000002"
        );
        assert!(toid("short").is_err());
        Ok(())
    }

    #[cfg(all(test, not(target_arch = "wasm32")))]
    #[tokio::test]
    async fn cursor_audits_output_note() -> anyhow::Result<()> {
        let (path, storage) = open_audit_db("output")?;
        let d_priv = field(0xA11CE);
        let admin = BabyJubJubPoint::from_priv_scalar(&d_priv).expect("valid admin key");
        let note = GvkNote::new(
            field(0xBEEF),
            NoteAmount::from(5_000_000u128),
            field(0x1234),
            field(99),
        );
        let ct = note.encrypt(&admin, &generate_gvk_nonce()?, 0)?;
        let commitment = commitment_for(&note)?;
        let event_id = tx_event_id("0000000000000000001", 0);

        seed_db(&path, |storage| {
            storage.save_events_batch(&ContractsEventData {
                events: vec![dummy_event(&event_id)],
                cursor: "cur".into(),
                latest_ledger: 1,
            })?;
            storage.save_commitment_events_batch(&vec![NewCommitmentEvent {
                id: event_id,
                commitment,
                index: 0,
                encrypted_output: vec![],
                gvk_ciphertext: Some(ct),
            }])
        })?;

        let mut audit = GvkAudit::new(storage, "CPOOL", d_priv);
        let tx = audit.next_tx().await?.expect("one tx");
        assert_eq!(tx.outputs.len(), 1);
        let output = tx.outputs[0].note.as_ref().expect("recovered output note");
        assert_eq!(output.note.amount()?, NoteAmount::from(5_000_000u128));
        assert_eq!(tx.outputs[0].commitment, commitment);
        assert!(tx.inputs.is_empty());
        assert!(audit.next_tx().await?.is_none());

        let _ = std::fs::remove_file(path);
        Ok(())
    }

    #[cfg(all(test, not(target_arch = "wasm32")))]
    #[tokio::test]
    async fn cursor_audits_traceable_input() -> anyhow::Result<()> {
        let (path, storage) = open_audit_db("traceable")?;
        let d_priv = field(0x510);
        let admin = BabyJubJubPoint::from_priv_scalar(&d_priv).expect("valid admin key");

        let spent = GvkNote::new(
            field(0xABC),
            NoteAmount::from(42u128),
            field(0xDEF),
            field(5),
        );
        let spent_commitment = commitment_for(&spent)?;
        let spent_ct = spent.encrypt(&admin, &field(9), 0)?;

        let output = GvkNote::new(field(1), NoteAmount::from(10u128), field(2), field(3));
        let output_commitment = commitment_for(&output)?;
        let output_ct = output.encrypt(&admin, &field(8), 0)?;

        let prior_id = tx_event_id("0000000000000000000", 0);
        let toid = "0000000000000000002";
        let commit_id = tx_event_id(toid, 0);
        let null_id = tx_event_id(toid, 1);

        seed_db(&path, |storage| {
            storage.save_events_batch(&ContractsEventData {
                events: vec![
                    dummy_event(&prior_id),
                    dummy_event(&commit_id),
                    dummy_event(&null_id),
                ],
                cursor: "cur".into(),
                latest_ledger: 1,
            })?;
            storage.save_commitment_events_batch(&vec![
                NewCommitmentEvent {
                    id: prior_id,
                    commitment: spent_commitment,
                    index: 0,
                    encrypted_output: vec![],
                    gvk_ciphertext: None,
                },
                NewCommitmentEvent {
                    id: commit_id.clone(),
                    commitment: output_commitment,
                    index: 1,
                    encrypted_output: vec![],
                    gvk_ciphertext: Some(output_ct),
                },
            ])?;
            storage.save_nullifier_events_batch(&vec![NewNullifierEvent {
                id: null_id,
                nullifier: field(0x999),
                gvk_ciphertext: Some(spent_ct),
            }])
        })?;

        let mut audit = GvkAudit::new(storage, "CPOOL", d_priv);
        let tx = audit.next_tx().await?.expect("transact tx");
        assert_eq!(tx.outputs.len(), 1);
        assert_eq!(tx.inputs.len(), 1);
        assert_eq!(tx.inputs[0].nullifier, field(0x999));
        assert_eq!(
            tx.inputs[0]
                .note
                .as_ref()
                .expect("recovered input note")
                .commitment,
            spent_commitment
        );

        let _ = std::fs::remove_file(path);
        Ok(())
    }
}
