use super::*;
use crate::{
    state::database_key::{DatabaseKey, OpenPurpose},
    types::{ContractEvent, ContractsEventData, Field, NewCommitmentEvent, SyncMetadata, U256},
};

struct Fixture(std::path::PathBuf);
impl Fixture {
    fn new() -> Result<Self> {
        let mut suffix = [0; 16];
        getrandom::getrandom(&mut suffix)?;
        let dir = std::env::temp_dir().join(format!("spp-private-vault-{}", hex::encode(suffix)));
        std::fs::create_dir(&dir)?;
        Ok(Self(dir))
    }

    fn vault(&self) -> std::path::PathBuf {
        self.0.join("private.db")
    }

    fn public(&self) -> std::path::PathBuf {
        self.0.join("public.db")
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn event(id: &str, contract: &str) -> ContractsEventData {
    ContractsEventData {
        events: vec![ContractEvent {
            id: id.into(),
            ledger: 10,
            contract_id: contract.into(),
            topics: vec!["public-topic".into()],
            value: "public-value".into(),
        }],
        cursor: id.into(),
        latest_ledger: 10,
    }
}
fn commitment(id: &str, index: u32) -> NewCommitmentEvent {
    NewCommitmentEvent {
        id: id.into(),
        commitment: Field(U256::from(42)),
        index,
        encrypted_output: vec![],
        gvk_ciphertext: None,
    }
}
fn tables(storage: &Storage, schema: &str) -> Result<Vec<String>> {
    Ok(storage.conn.prepare(&format!("SELECT name FROM {schema}.sqlite_schema WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name"))?
       .query_map([], |r| r.get(0))?.collect::<rusqlite::Result<_>>()?)
}

#[test]
fn fresh_private_vault_has_its_own_format_and_reopens_without_native_tables() -> Result<()> {
    let f = Fixture::new()?;
    let key = DatabaseKey::generate()?;
    let mut public = Storage::connect_public(f.public())?;
    public.save_events_batch(&event("public-event", "pool"))?;
    public.open_private_vault(f.vault(), &key, OpenPurpose::CreateNew)?;
    public.set_setting_json("private-marker", &"retained")?;
    assert_eq!(
        tables(&public, "vault")?,
        [
            "account_commitment_scan",
            "accounts",
            "app_user_operations",
            "disclaimer_acceptances",
            "keypairs",
            "private_settings",
            "user_notes"
        ]
    );
    assert_eq!(
        public
            .conn
            .pragma_query_value(Some("vault"), "application_id", |r| r.get::<_, i32>(0))?,
        super::super::private_vault::APPLICATION_ID
    );
    assert_eq!(
        public
            .conn
            .pragma_query_value(Some("vault"), "user_version", |r| r.get::<_, i64>(0))?,
        1
    );
    drop(public);
    // A native opener must refuse the different layout before applying its
    // migration list, even when the vault's version is lower than native's.
    let bytes = std::fs::read(f.vault())?;
    assert!(Storage::connect_encrypted(f.vault(), &key, OpenPurpose::OpenExisting).is_err());
    assert_eq!(std::fs::read(f.vault())?, bytes);
    let mut public = Storage::connect_public(f.public())?;
    public.open_private_vault(f.vault(), &key, OpenPurpose::OpenExisting)?;
    assert_eq!(
        public
            .get_setting_json::<String>("private-marker")?
            .as_deref(),
        Some("retained")
    );
    assert!(!tables(&public, "vault")?.contains(&"contracts".to_string()));
    assert!(
        public
            .open_private_vault(f.vault(), &key, OpenPurpose::CreateNew)
            .is_err()
    );
    Ok(())
}

#[test]
fn future_vault_and_legacy_versions_are_refused_without_replacing_records() -> Result<()> {
    let f = Fixture::new()?;
    let key = DatabaseKey::generate()?;
    let mut public = Storage::connect_public(f.public())?;
    public.open_private_vault(f.vault(), &key, OpenPurpose::CreateNew)?;
    public.set_setting_json("private-marker", &"retained")?;
    public
        .conn
        .pragma_update(Some("vault"), "user_version", 2)?;
    drop(public);
    let bytes = std::fs::read(f.vault())?;
    let mut public = Storage::connect_public(f.public())?;
    assert!(
        public
            .open_private_vault(f.vault(), &key, OpenPurpose::OpenExisting)
            .is_err()
    );
    assert_eq!(std::fs::read(f.vault())?, bytes);
    assert!(public.is_public_only());
    public.set_setting_json("explorer", &"https://explorer.example")?;
    let legacy = f.0.join("future-native.db");
    let storage = Storage::connect_encrypted(&legacy, &key, OpenPurpose::CreateNew)?;
    storage.conn.pragma_update(None, "user_version", 4)?;
    drop(storage);
    let bytes = std::fs::read(&legacy)?;
    assert!(
        public
            .open_private_vault(&legacy, &key, OpenPurpose::OpenExisting)
            .is_err()
    );
    assert_eq!(std::fs::read(&legacy)?, bytes);
    Ok(())
}

#[test]
fn vault_contains_only_private_state_and_public_bytes_exclude_secrets() -> Result<()> {
    let f = Fixture::new()?;
    let key = DatabaseKey::generate()?;
    let mut vault = Storage::connect_encrypted(f.vault(), &key, OpenPurpose::CreateNew)?;
    vault.set_setting_json("private-marker", &"never-public")?;
    vault.set_setting_json("explorer", &"https://explorer.example")?;
    vault.insert_operation(
        "private-owner",
        "pool",
        "sent",
        "123",
        "out",
        Some("private-recipient"),
        None,
    )?;
    vault.save_events_batch(&event("first", "pool"))?;
    vault.save_sync_progress(
        &[SyncMetadata {
            contract_id: "pool".into(),
            cursor: "legacy-cursor".into(),
            last_indexed_ledger: 10,
            last_fully_indexed_ledger: 10,
        }],
        true,
    )?;
    let mut public = Storage::connect_public(f.public())?;
    assert!(public.get_setting_json::<String>("private-marker").is_err());
    assert!(public.set_setting_json("gvk_authority", &"secret").is_err());
    drop(vault);
    public.open_private_vault(f.vault(), &key, OpenPurpose::OpenExisting)?;
    assert_eq!(public.get_sync_metadata()?[0].cursor, "legacy-cursor");
    assert_eq!(public.get_sync_metadata()?[0].last_fully_indexed_ledger, 10);
    assert_eq!(
        tables(&public, "vault")?,
        [
            "account_commitment_scan",
            "accounts",
            "app_user_operations",
            "disclaimer_acceptances",
            "keypairs",
            "private_settings",
            "user_notes"
        ]
    );
    assert_eq!(
        public
            .get_setting_json::<String>("private-marker")?
            .as_deref(),
        Some("never-public")
    );
    assert_eq!(
        public.get_setting_json::<String>("explorer")?.as_deref(),
        Some("https://explorer.example")
    );
    public.set_setting_json("another-private-marker", &"private-after-attach")?;
    public.set_setting_json("bootnode_config", &"public-after-attach")?;
    assert_eq!(
        public.list_operations("private-owner", "pool", 10)?.len(),
        1
    );
    assert!(
        !tables(&public, "main")?
            .iter()
            .any(|name| name == "accounts" || name == "user_notes")
    );
    assert_eq!(
        public
            .conn
            .query_row("SELECT count(*) FROM raw_contract_events", [], |r| r
                .get::<_, i64>(0))?,
        1
    );
    assert!(
        public
            .conn
            .execute(
                "INSERT INTO main.app_settings VALUES ('private','secret')",
                []
            )
            .is_err()
    );
    drop(public);
    let bytes = std::fs::read(f.public())?;
    for secret in [
        "never-public",
        "private-after-attach",
        "private-owner",
        "private-recipient",
    ] {
        assert!(
            !bytes
                .windows(secret.len())
                .any(|window| window == secret.as_bytes())
        );
    }
    assert!(bytes.starts_with(b"SQLite format 3"));
    assert!(!std::fs::read(f.vault())?.starts_with(b"SQLite format 3"));
    Ok(())
}

#[test]
fn legacy_note_references_migrate_to_commitment_hashes_and_preserve_spent_state() -> Result<()> {
    let f = Fixture::new()?;
    let key = DatabaseKey::generate()?;
    let conn = super::super::database_key::open(&f.vault(), &key, OpenPurpose::CreateNew)?;
    conn.execute_batch(include_str!("schema.sql"))?;
    conn.execute_batch(include_str!("schema_v2_gvk_ciphertext.sql"))?;
    conn.pragma_update(None, "user_version", 2)?;
    conn.execute_batch("INSERT INTO accounts VALUES (1,'owner'); INSERT INTO contracts VALUES (73,'pool');
        INSERT INTO raw_contract_events VALUES ('commit',10,73,'public-topic','public-value'),('spend',11,73,'public-topic','public-value');
        INSERT INTO pool_commitments VALUES (99,zeroblob(32),0,zeroblob(32),'commit',NULL);
        INSERT INTO pool_nullifiers VALUES (123,zeroblob(32),'spend',NULL);
        INSERT INTO user_notes VALUES (zeroblob(32),1,99,123,zeroblob(32),zeroblob(32),'42');
        INSERT INTO indexing_metadata VALUES (73,'legacy-cursor',10,10);")?;
    drop(conn);
    let mut public = Storage::connect_public(f.public())?;
    public.save_events_batch(&event("different-id", "different-pool"))?;
    public.save_sync_progress(
        &[SyncMetadata {
            contract_id: "pool".into(),
            cursor: "public-cursor".into(),
            last_indexed_ledger: 20,
            last_fully_indexed_ledger: 20,
        }],
        true,
    )?;
    public.clear_indexing_cursors()?;
    public.clamp_last_fully_indexed_ledger(5)?;
    public.open_private_vault(f.vault(), &key, OpenPurpose::OpenExisting)?;
    let metadata = public.get_sync_metadata()?;
    assert_eq!(metadata[0].cursor, "");
    assert_eq!(metadata[0].last_indexed_ledger, 20);
    assert_eq!(metadata[0].last_fully_indexed_ledger, 5);
    public.save_commitment_events_batch(&vec![NewCommitmentEvent {
        commitment: Field(U256::zero()),
        ..commitment("commit", 0)
    }])?;
    let notes = public.list_user_notes("owner", 10)?;
    assert_eq!(notes.len(), 1);
    assert_eq!(notes[0].pool_contract_id, "pool");
    assert!(notes[0].spent);
    assert!(
        public
            .get_unspent_user_note_by_commitment("pool", "owner", &Field(U256::zero()))?
            .is_none()
    );
    assert!(
        public
            .get_user_note_by_commitment("pool", "owner", &Field(U256::zero()))?
            .is_some()
    );
    Ok(())
}

#[test]
fn conflicting_public_import_keeps_legacy_vault_and_can_be_retried() -> Result<()> {
    let f = Fixture::new()?;
    let key = DatabaseKey::generate()?;
    let mut vault = Storage::connect_encrypted(f.vault(), &key, OpenPurpose::CreateNew)?;
    vault.save_events_batch(&event("existing", "pool"))?;
    let mut public = Storage::connect_public(f.public())?;
    public.save_events_batch(&event("existing", "pool"))?;
    public
        .conn
        .execute("UPDATE raw_contract_events SET value='tampered'", [])?;
    drop(vault);
    assert!(
        public
            .open_private_vault(f.vault(), &key, OpenPurpose::OpenExisting)
            .is_err()
    );
    let conn = super::super::database_key::open(&f.vault(), &key, OpenPurpose::OpenExisting)?;
    assert!(conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE name='raw_contract_events')",
        [],
        |r| r.get::<_, bool>(0)
    )?);
    drop(conn);
    public
        .conn
        .execute("UPDATE raw_contract_events SET value='public-value'", [])?;
    public.open_private_vault(f.vault(), &key, OpenPurpose::OpenExisting)?;
    assert!(!tables(&public, "vault")?.contains(&"raw_contract_events".to_string()));
    Ok(())
}

#[test]
fn cache_rebuild_changes_public_ids_without_erasing_private_notes_or_history() -> Result<()> {
    let f = Fixture::new()?;
    let key = DatabaseKey::generate()?;
    let mut vault = Storage::connect_encrypted(f.vault(), &key, OpenPurpose::CreateNew)?;
    vault.save_events_batch(&event("original", "pool"))?;
    vault.save_commitment_events_batch(&vec![commitment("original", 0)])?;
    vault
        .conn
        .execute("INSERT INTO accounts(address) VALUES ('owner')", [])?;
    vault.conn.execute("INSERT INTO user_notes(id,account_id,expected_nullifier,blinding,amount) SELECT commitment,1,zeroblob(32),zeroblob(32),'42' FROM pool_commitments", [])?;
    vault.set_setting_json("private-marker", &"never-public")?;
    let mut public = Storage::connect_public(f.public())?;
    drop(vault);
    public.open_private_vault(f.vault(), &key, OpenPurpose::OpenExisting)?;
    public.save_commitment_events_batch(&vec![commitment("original", 0)])?;
    assert_eq!(public.list_user_notes("owner", 10)?.len(), 1);
    drop(public);
    std::fs::remove_file(f.public())?;
    let mut public = Storage::connect_public(f.public())?;
    public.save_events_batch(&event("another", "another-pool"))?;
    public.open_private_vault(f.vault(), &key, OpenPurpose::OpenExisting)?;
    assert_eq!(
        public
            .get_setting_json::<String>("private-marker")?
            .as_deref(),
        Some("never-public")
    );
    assert!(public.list_user_notes("owner", 10)?.is_empty());
    public.save_events_batch(&event("original", "pool"))?;
    public.save_commitment_events_batch(&vec![commitment("original", 0)])?;
    let notes = public.list_user_notes("owner", 10)?;
    assert_eq!(notes.len(), 1);
    assert_eq!(notes[0].pool_contract_id, "pool");
    assert_eq!(notes[0].amount.to_string(), "42");
    Ok(())
}

#[test]
fn attached_private_scans_follow_leaf_order_and_reconcile_only_matching_pools() -> Result<()> {
    use crate::{
        state::storage::DerivedUserNoteRow,
        types::{KeyDerivationSignature, NewNullifierEvent, NoteAmount},
        zk::encryption,
    };
    let f = Fixture::new()?;
    let key = DatabaseKey::generate()?;
    let mut public = Storage::connect_public(f.public())?;
    public.open_private_vault(f.vault(), &key, OpenPurpose::CreateNew)?;
    let signature = KeyDerivationSignature(vec![1; 64]);
    let (note, encryption) = encryption::derive_encryption_and_note_keypairs(signature.clone())?;
    public.save_encryption_and_note_keypairs(
        "owner",
        &note,
        &encryption,
        &encryption::derive_membership_blinding(&signature, "testnet")?,
    )?;
    public.save_events_batch(&event("late-leaf", "pool"))?;
    public.save_commitment_events_batch(&vec![commitment("late-leaf", 1)])?;
    public.save_events_batch(&event("early-leaf", "pool"))?;
    public.save_commitment_events_batch(&vec![NewCommitmentEvent {
        commitment: Field(U256::from(43)),
        ..commitment("early-leaf", 0)
    }])?;
    let mut derive = |_: &crate::state::storage::AccountKeys,
                      row: &crate::state::storage::PoolCommitmentRow| {
        Ok(Some(DerivedUserNoteRow {
            amount: NoteAmount::from(42),
            blinding: Field(U256::from(1)),
            expected_nullifier: Field(U256::from(50 + row.leaf_index)),
        }))
    };
    assert!(public.scan_commitments_for_user_notes(1, &mut derive)?);
    let notes = public.list_user_notes("owner", 10)?;
    assert_eq!(notes.len(), 1);
    assert_eq!(notes[0].leaf_index, 0);
    assert!(public.scan_commitments_for_user_notes(1, &mut derive)?);
    assert!(!public.scan_commitments_for_user_notes(1, &mut derive)?);
    assert_eq!(public.list_user_notes("owner", 10)?.len(), 2);
    // Matching nullifier material from another pool cannot spend this note.
    public.save_events_batch(&event("wrong-pool-spend", "other-pool"))?;
    public.save_nullifier_events_batch(&vec![NewNullifierEvent {
        id: "wrong-pool-spend".into(),
        nullifier: Field(U256::from(50)),
        gvk_ciphertext: None,
    }])?;
    assert!(!public.reconcile_nullifiers(1)?);
    public.save_events_batch(&event("correct-pool-spend", "pool"))?;
    public.save_nullifier_events_batch(&vec![NewNullifierEvent {
        id: "correct-pool-spend".into(),
        nullifier: Field(U256::from(51)),
        gvk_ciphertext: None,
    }])?;
    assert!(public.reconcile_nullifiers(1)?);
    assert!(!public.reconcile_nullifiers(1)?);
    assert_eq!(public.list_unspent_user_notes("pool", "owner")?.len(), 1);
    assert_eq!(
        public
            .get_private_keys("owner")?
            .expect("attached vault retains account keys")
            .note_keypair
            .public
            .0,
        note.public.0
    );
    assert!(!tables(&public, "vault")?.contains(&"pool_commitments".to_string()));
    Ok(())
}

#[test]
fn wrong_attachment_key_preserves_vault_and_public_storage_remains_usable() -> Result<()> {
    let f = Fixture::new()?;
    let key = DatabaseKey::generate()?;
    let mut public = Storage::connect_public(f.public())?;
    public.open_private_vault(f.vault(), &key, OpenPurpose::CreateNew)?;
    drop(public);
    let mut public = Storage::connect_public(f.public())?;
    let before = std::fs::read(f.vault())?;
    assert!(Storage::connect_public(f.vault()).is_err());
    assert!(
        public
            .open_private_vault(
                f.vault(),
                &DatabaseKey::generate()?,
                OpenPurpose::OpenExisting
            )
            .is_err()
    );
    assert_eq!(std::fs::read(f.vault())?, before);
    assert!(public.is_public_only());
    public.set_setting_json("explorer", &"https://explorer.example")?;
    public.open_private_vault(f.vault(), &key, OpenPurpose::OpenExisting)?;
    assert!(!public.is_public_only());
    Ok(())
}

#[test]
fn orphaned_legacy_note_aborts_upgrade_without_discarding_private_rows() -> Result<()> {
    let f = Fixture::new()?;
    let key = DatabaseKey::generate()?;
    let conn = super::super::database_key::open(&f.vault(), &key, OpenPurpose::CreateNew)?;
    conn.execute_batch(include_str!("schema.sql"))?;
    conn.execute_batch(include_str!("schema_v2_gvk_ciphertext.sql"))?;
    conn.pragma_update(None, "user_version", 2)?;
    conn.pragma_update(None, "foreign_keys", "OFF")?;
    conn.execute_batch("INSERT INTO accounts VALUES (1,'owner'); INSERT INTO user_notes VALUES (zeroblob(32),1,99,NULL,zeroblob(32),zeroblob(32),'42')")?;
    drop(conn);
    let mut public = Storage::connect_public(f.public())?;
    assert!(
        public
            .open_private_vault(f.vault(), &key, OpenPurpose::OpenExisting)
            .is_err()
    );
    let conn = super::super::database_key::open(&f.vault(), &key, OpenPurpose::OpenExisting)?;
    assert_eq!(
        conn.query_row("SELECT amount FROM user_notes", [], |r| r
            .get::<_, String>(0))?,
        "42"
    );
    assert_eq!(
        conn.pragma_query_value(None, "user_version", |r| r.get::<_, i64>(0))?,
        2
    );
    Ok(())
}

#[test]
fn legacy_v3_integrity_failure_remains_rejected_on_retry() -> Result<()> {
    let f = Fixture::new()?;
    let key = DatabaseKey::generate()?;
    let vault = Storage::connect_encrypted(f.vault(), &key, OpenPurpose::CreateNew)?;
    vault.conn.pragma_update(None, "foreign_keys", "OFF")?;
    vault.conn.execute("INSERT INTO user_notes(id,account_id,expected_nullifier,blinding,amount) VALUES (zeroblob(32),99,zeroblob(32),zeroblob(32),'42')", [])?;
    drop(vault);
    let original = std::fs::read(f.vault())?;
    let mut public = Storage::connect_public(f.public())?;
    for _ in 0..2 {
        assert!(
            public
                .open_private_vault(f.vault(), &key, OpenPurpose::OpenExisting)
                .is_err()
        );
        assert!(public.is_public_only());
        assert_eq!(std::fs::read(f.vault())?, original);
    }
    Ok(())
}
