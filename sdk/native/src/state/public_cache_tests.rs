use super::*;
use crate::types::{ContractEvent, ContractsEventData, SyncMetadata};

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

#[test]
fn cache_excludes_private_tables_and_settings() -> Result<()> {
    let mut vault = Storage::connect_in_memory()?;
    vault.set_setting_json("private-marker", &"secret-value")?;
    vault.set_setting_json(
        "explorer",
        &serde_json::json!({"baseUrl":"https://example.org"}),
    )?;
    vault.insert_operation(
        "private-account",
        "pool",
        "sent",
        "123",
        "out",
        Some("private-recipient"),
        None,
    )?;
    vault.save_events_batch(&event("first", "pool"))?;
    let mut cache = Storage::connect_public(":memory:")?;
    vault.synchronize_public_cache(&mut cache)?;
    assert_eq!(
        cache
            .conn
            .query_row("SELECT count(*) FROM raw_contract_events", [], |r| r
                .get::<_, i64>(0))?,
        1
    );
    for name in [
        "accounts",
        "keypairs",
        "user_notes",
        "app_user_operations",
        "account_commitment_scan",
        "nullifier_scan_state",
        "disclaimer_acceptances",
    ] {
        assert!(!cache.conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE name=?1)",
            [name],
            |r| r.get::<_, bool>(0)
        )?);
    }
    assert!(cache.get_setting_json::<String>("private-marker").is_err());
    assert!(cache.set_setting_json("gvk_authority", &"secret").is_err());
    assert!(
        cache
            .conn
            .execute("INSERT INTO app_settings VALUES ('secret','value')", [])
            .is_err()
    );
    assert!(
        cache
            .get_setting_json::<serde_json::Value>("explorer")?
            .is_some()
    );
    assert_eq!(
        vault.list_operations("private-account", "pool", 10)?.len(),
        1
    );
    Ok(())
}

#[test]
fn locked_sync_merges_by_contract_address_and_preserves_private_references() -> Result<()> {
    let mut vault = Storage::connect_in_memory()?;
    vault.save_events_batch(&event("old", "old-pool"))?;
    vault
        .conn
        .execute("INSERT INTO accounts(address) VALUES ('private-owner')", [])?;
    vault.conn.execute("INSERT INTO pool_commitments(commitment,leaf_index,encrypted_output,event_id) VALUES (zeroblob(32),0,zeroblob(32),'old')", [])?;
    vault.conn.execute("INSERT INTO user_notes(id,account_id,commitment_id,expected_nullifier,blinding,amount) VALUES (zeroblob(32),1,1,zeroblob(32),zeroblob(32),'42')", [])?;
    let mut cache = Storage::connect_public(":memory:")?;
    // Different local IDs on the two sides must not change event ownership.
    cache.save_events_batch(&event("new", "new-pool"))?;
    vault.synchronize_public_cache(&mut cache)?;
    let address: String = vault.conn.query_row("SELECT c.address FROM raw_contract_events r JOIN contracts c ON c.contract_id=r.contract_id WHERE r.id='new'", [], |r| r.get(0))?;
    assert_eq!(address, "new-pool");
    cache.save_sync_progress(
        &[SyncMetadata {
            contract_id: "old-pool".into(),
            cursor: "cursor".into(),
            last_indexed_ledger: 20,
            last_fully_indexed_ledger: 20,
        }],
        true,
    )?;
    vault.synchronize_public_cache(&mut cache)?;
    cache.clear_indexing_cursors()?;
    cache.clamp_last_fully_indexed_ledger(5)?;
    vault.synchronize_public_cache(&mut cache)?;
    let metadata = vault.get_sync_metadata()?;
    assert_eq!(metadata[0].cursor, "");
    assert_eq!(metadata[0].last_fully_indexed_ledger, 5);
    let (amount, contract): (String, String) = vault.conn.query_row("SELECT n.amount,c.address FROM user_notes n JOIN pool_commitments p ON p.id=n.commitment_id JOIN raw_contract_events r ON r.id=p.event_id JOIN contracts c ON c.contract_id=r.contract_id", [], |r| Ok((r.get(0)?,r.get(1)?)))?;
    assert_eq!((amount.as_str(), contract.as_str()), ("42", "old-pool"));
    assert!(
        vault
            .conn
            .prepare("PRAGMA foreign_key_check")?
            .query([])?
            .next()?
            .is_none()
    );
    assert_eq!(
        vault
            .conn
            .query_row("SELECT count(*) FROM raw_contract_events", [], |r| r
                .get::<_, i64>(0))?,
        2
    );
    Ok(())
}

#[test]
fn conflicting_cache_rolls_back_import_and_can_be_retried() -> Result<()> {
    let mut vault = Storage::connect_in_memory()?;
    vault.save_events_batch(&event("existing", "pool"))?;
    let mut cache = Storage::connect_public(":memory:")?;
    vault.synchronize_public_cache(&mut cache)?;
    cache.save_events_batch(&event("a-new-event", "pool"))?;
    cache.conn.execute(
        "UPDATE raw_contract_events SET value='tampered' WHERE id='existing'",
        [],
    )?;
    assert!(vault.synchronize_public_cache(&mut cache).is_err());
    assert_eq!(
        vault
            .conn
            .query_row("SELECT count(*) FROM raw_contract_events", [], |r| r
                .get::<_, i64>(0))?,
        1
    );
    cache.conn.execute(
        "UPDATE raw_contract_events SET value='public-value' WHERE id='existing'",
        [],
    )?;
    vault.synchronize_public_cache(&mut cache)?;
    assert_eq!(
        vault
            .conn
            .query_row("SELECT count(*) FROM raw_contract_events", [], |r| r
                .get::<_, i64>(0))?,
        2
    );
    Ok(())
}

#[test]
fn public_cache_rebuild_preserves_encrypted_vault_and_refuses_its_path() -> Result<()> {
    use crate::state::database_key::{DatabaseKey, OpenPurpose};
    struct Directory(std::path::PathBuf);
    impl Drop for Directory {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    let mut suffix = [0; 16];
    getrandom::getrandom(&mut suffix)?;
    let dir =
        Directory(std::env::temp_dir().join(format!("spp-public-cache-{}", hex::encode(suffix))));
    std::fs::create_dir(&dir.0)?;
    let path = dir.0.join("private.db");
    let key = DatabaseKey::generate()?;
    let mut vault = Storage::connect_encrypted(&path, &key, OpenPurpose::CreateNew)?;
    vault.save_events_batch(&event("original", "pool"))?;
    vault.set_setting_json("private-marker", &"never-public")?;
    drop(vault);
    let before = std::fs::read(&path)?;
    assert!(Storage::connect_public(&path).is_err());
    assert_eq!(std::fs::read(&path)?, before);
    let mut vault = Storage::connect_encrypted(&path, &key, OpenPurpose::OpenExisting)?;
    let mut cache = Storage::connect_public(dir.0.join("public.db"))?;
    vault.synchronize_public_cache(&mut cache)?;
    drop(cache);
    std::fs::remove_file(dir.0.join("public.db"))?;
    let mut cache = Storage::connect_public(dir.0.join("public.db"))?;
    vault.synchronize_public_cache(&mut cache)?;
    assert_eq!(
        cache
            .conn
            .query_row("SELECT count(*) FROM raw_contract_events", [], |r| r
                .get::<_, i64>(0))?,
        1
    );
    assert_eq!(
        vault
            .get_setting_json::<String>("private-marker")?
            .as_deref(),
        Some("never-public")
    );
    drop(cache);
    let bytes = std::fs::read(dir.0.join("public.db"))?;
    assert!(
        !bytes
            .windows(b"never-public".len())
            .any(|w| w == b"never-public")
    );
    Ok(())
}
