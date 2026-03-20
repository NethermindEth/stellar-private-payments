//! Integration tests for the storage crate (native backend).

use storage::{
    Storage,
    types::{
        AspMembershipLeaf, PoolEncryptedOutput, PoolLeaf, PoolNullifier, PublicKeyEntry,
        RetentionConfig, SyncCursor, SyncMetadata, UserNote,
    },
};

const ADDR_ALICE: &str = "GBBD47IF6LWK7P7MDEVSCWR7DPUWV3NY3DTQEVFL4NAT4AQH3ZLLFLA5";
const ADDR_BOB: &str = "GCEZWKCA5VLDNRLN3RPRJMRZOX3Z6G5CHCGZWL8AYPKVF9P5T6B4N6E";

const COMMITMENT_1: &str = "0x1a2b3c4d5e6f708192a3b4c5d6e7f80911223344556677889900aabbccddeeff";
const COMMITMENT_2: &str = "0x2b3c4d5e6f708192a3b4c5d6e7f80911223344556677889900aabbccddeeff1a";
const COMMITMENT_3: &str = "0x3c4d5e6f708192a3b4c5d6e7f80911223344556677889900aabbccddeeff1a2b";
const NULLIFIER_1: &str = "0xdeadbeefcafebabedeadbeefcafebabedeadbeefcafebabedeadbeefcafebabe";
const ENC_KEY: &str = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const NOTE_KEY: &str = "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const PRIVATE_KEY: &str = "0xcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
const BLINDING: &str = "0xdddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";

const LEAF_1: &str = "0x1111111111111111111111111111111111111111111111111111111111111111";
const LEAF_2: &str = "0x2222222222222222222222222222222222222222222222222222222222222222";
const ROOT_1: &str = "0xaaaa111111111111111111111111111111111111111111111111111111111111";
const ROOT_2: &str = "0xbbbb222222222222222222222222222222222222222222222222222222222222";

const LEDGER_A: u32 = 50_000_100;
const LEDGER_B: u32 = 50_000_200;
const LEDGER_C: u32 = 50_000_300;

fn open() -> Storage {
    Storage::open_in_memory().expect("Failed to open in-memory storage")
}

fn sample_note(id: &str, owner: &str, spent: bool) -> UserNote {
    UserNote {
        id: id.into(),
        owner: owner.into(),
        private_key: PRIVATE_KEY.into(),
        blinding: BLINDING.into(),
        amount: "1000000000".into(),
        leaf_index: Some(0),
        created_at: "2025-01-01T00:00:00Z".into(),
        created_at_ledger: LEDGER_A,
        spent,
        spent_at_ledger: None,
        is_received: false,
    }
}

fn sample_key(address: &str, ledger: u32) -> PublicKeyEntry {
    PublicKeyEntry {
        address: address.into(),
        encryption_key: ENC_KEY.into(),
        note_key: NOTE_KEY.into(),
        public_key: ENC_KEY.into(),
        ledger,
        registered_at: "2025-01-01T00:00:00Z".into(),
    }
}

fn sample_sync_meta(network: &str) -> SyncMetadata {
    SyncMetadata {
        network: network.into(),
        pool_sync: SyncCursor {
            last_ledger: 0,
            last_cursor: None,
            sync_broken: false,
        },
        asp_membership_sync: SyncCursor {
            last_ledger: 0,
            last_cursor: None,
            sync_broken: false,
        },
        last_successful_sync: None,
    }
}

// ---------------------------------------------------------------------------
// pool_leaves
// ---------------------------------------------------------------------------

#[test]
fn pool_leaves_put_and_iterate() {
    let db = open();
    db.put_pool_leaf(&PoolLeaf {
        index: 0,
        commitment: COMMITMENT_1.into(),
        ledger: LEDGER_A,
    })
    .expect("Failed to put pool leaf 0");
    db.put_pool_leaf(&PoolLeaf {
        index: 1,
        commitment: COMMITMENT_2.into(),
        ledger: LEDGER_B,
    })
    .expect("Failed to put pool leaf 1");

    let mut seen = Vec::new();
    db.iterate_pool_leaves(|leaf| {
        seen.push(leaf.index);
        true
    })
    .expect("Failed to iterate pool leaves");
    assert_eq!(seen, vec![0, 1]);
}

#[test]
fn pool_leaves_count_and_clear() {
    let db = open();
    db.put_pool_leaf(&PoolLeaf {
        index: 0,
        commitment: COMMITMENT_1.into(),
        ledger: LEDGER_A,
    })
    .expect("Failed to put pool leaf");
    assert_eq!(db.count_pool_leaves().expect("Failed to count"), 1);
    db.clear_pool_leaves().expect("Failed to clear");
    assert_eq!(
        db.count_pool_leaves().expect("Failed to count after clear"),
        0
    );
}

#[test]
fn pool_leaves_replace_on_same_index() {
    let db = open();
    db.put_pool_leaf(&PoolLeaf {
        index: 0,
        commitment: COMMITMENT_1.into(),
        ledger: LEDGER_A,
    })
    .expect("Failed to put first leaf");
    db.put_pool_leaf(&PoolLeaf {
        index: 0,
        commitment: COMMITMENT_2.into(),
        ledger: LEDGER_B,
    })
    .expect("Failed to put replacement leaf");
    assert_eq!(db.count_pool_leaves().expect("Failed to count"), 1);
}

#[test]
fn pool_leaves_iterate_early_stop() {
    let db = open();
    let commitments = [COMMITMENT_1, COMMITMENT_2, COMMITMENT_3];
    for (i, c) in commitments.iter().enumerate() {
        let idx = u32::try_from(i).expect("Failed to convert index");
        db.put_pool_leaf(&PoolLeaf {
            index: idx,
            commitment: (*c).into(),
            ledger: LEDGER_A.saturating_add(idx),
        })
        .expect("Failed to put pool leaf");
    }
    let mut count = 0_u32;
    db.iterate_pool_leaves(|_| {
        count = count.saturating_add(1);
        count < 2
    })
    .expect("Failed to iterate");
    assert_eq!(count, 2);
}

// ---------------------------------------------------------------------------
// pool_nullifiers
// ---------------------------------------------------------------------------

#[test]
fn pool_nullifiers_put_get_count() {
    let db = open();
    db.put_nullifier(&PoolNullifier {
        nullifier: NULLIFIER_1.into(),
        ledger: LEDGER_A,
    })
    .expect("Failed to put nullifier");
    assert!(
        db.get_nullifier(NULLIFIER_1)
            .expect("Failed to get nullifier")
            .is_some()
    );
    assert!(
        db.get_nullifier(COMMITMENT_1)
            .expect("Failed to get missing nullifier")
            .is_none()
    );
    assert_eq!(db.count_nullifiers().expect("Failed to count"), 1);
}

#[test]
fn pool_nullifiers_clear() {
    let db = open();
    db.put_nullifier(&PoolNullifier {
        nullifier: NULLIFIER_1.into(),
        ledger: LEDGER_A,
    })
    .expect("Failed to put nullifier");
    db.clear_nullifiers().expect("Failed to clear");
    assert_eq!(db.count_nullifiers().expect("Failed to count"), 0);
}

// ---------------------------------------------------------------------------
// pool_encrypted_outputs
// ---------------------------------------------------------------------------

#[test]
fn encrypted_outputs_put_and_get_all() {
    let db = open();
    db.put_encrypted_output(&PoolEncryptedOutput {
        commitment: COMMITMENT_1.into(),
        leaf_index: 0,
        encrypted_output: ENC_KEY.into(),
        ledger: LEDGER_A,
    })
    .expect("Failed to put output 1");
    db.put_encrypted_output(&PoolEncryptedOutput {
        commitment: COMMITMENT_2.into(),
        leaf_index: 1,
        encrypted_output: NOTE_KEY.into(),
        ledger: LEDGER_C,
    })
    .expect("Failed to put output 2");

    assert_eq!(
        db.get_all_encrypted_outputs()
            .expect("Failed to get all")
            .len(),
        2
    );

    let filtered = db
        .get_encrypted_outputs_from(LEDGER_B)
        .expect("Failed to get filtered");
    assert_eq!(filtered.len(), 1);
    assert_eq!(filtered[0].commitment, COMMITMENT_2);
}

#[test]
fn encrypted_outputs_clear() {
    let db = open();
    db.put_encrypted_output(&PoolEncryptedOutput {
        commitment: COMMITMENT_1.into(),
        leaf_index: 0,
        encrypted_output: ENC_KEY.into(),
        ledger: LEDGER_A,
    })
    .expect("Failed to put output");
    db.clear_encrypted_outputs().expect("Failed to clear");
    assert!(
        db.get_all_encrypted_outputs()
            .expect("Failed to get all")
            .is_empty()
    );
}

// ---------------------------------------------------------------------------
// asp_membership_leaves
// ---------------------------------------------------------------------------

#[test]
fn asp_leaves_put_iterate_and_find() {
    let db = open();
    db.put_asp_membership_leaf(&AspMembershipLeaf {
        index: 0,
        leaf: LEAF_1.into(),
        root: ROOT_1.into(),
        ledger: LEDGER_A,
    })
    .expect("Failed to put asp leaf 0");
    db.put_asp_membership_leaf(&AspMembershipLeaf {
        index: 1,
        leaf: LEAF_2.into(),
        root: ROOT_2.into(),
        ledger: LEDGER_B,
    })
    .expect("Failed to put asp leaf 1");

    assert_eq!(
        db.count_asp_membership_leaves().expect("Failed to count"),
        2
    );
    assert_eq!(
        db.get_asp_membership_leaf_by_hash(LEAF_2)
            .expect("Failed to find by hash")
            .expect("Expected leaf to exist")
            .index,
        1
    );
    assert!(
        db.get_asp_membership_leaf_by_hash(COMMITMENT_3)
            .expect("Failed to query missing hash")
            .is_none()
    );
}

#[test]
fn asp_leaves_iterate_ascending_order() {
    let db = open();
    // Insert in reverse order — iterate must still return ascending.
    let leaves = [(2, LEAF_2, ROOT_2, LEDGER_B), (0, LEAF_1, ROOT_1, LEDGER_A)];
    for (i, leaf, root, ledger) in leaves {
        db.put_asp_membership_leaf(&AspMembershipLeaf {
            index: i,
            leaf: leaf.into(),
            root: root.into(),
            ledger,
        })
        .expect("Failed to put asp leaf");
    }
    let mut indices = Vec::new();
    db.iterate_asp_membership_leaves(|l| {
        indices.push(l.index);
        true
    })
    .expect("Failed to iterate");
    assert_eq!(indices, vec![0, 2]);
}

// ---------------------------------------------------------------------------
// user_notes
// ---------------------------------------------------------------------------

#[test]
fn user_notes_put_get_delete() {
    let db = open();
    db.put_note(&sample_note(COMMITMENT_1, ADDR_ALICE, false))
        .expect("Failed to put note");
    let fetched = db
        .get_note(COMMITMENT_1)
        .expect("Failed to get note")
        .expect("Expected note to exist");
    assert_eq!(fetched.owner, ADDR_ALICE);
    assert!(!fetched.spent);

    db.delete_note(COMMITMENT_1).expect("Failed to delete note");
    assert!(
        db.get_note(COMMITMENT_1)
            .expect("Failed to get deleted note")
            .is_none()
    );
}

#[test]
fn user_notes_pending_leaf_index_null() {
    let db = open();
    let note = UserNote {
        id: COMMITMENT_1.into(),
        owner: ADDR_ALICE.into(),
        private_key: PRIVATE_KEY.into(),
        blinding: BLINDING.into(),
        amount: "5000000000".into(),
        leaf_index: None,
        created_at: "2025-03-01T00:00:00Z".into(),
        created_at_ledger: LEDGER_A,
        spent: false,
        spent_at_ledger: None,
        is_received: false,
    };
    db.put_note(&note).expect("Failed to put pending note");
    let fetched = db
        .get_note(COMMITMENT_1)
        .expect("Failed to get note")
        .expect("Expected note to exist");
    assert!(fetched.leaf_index.is_none());

    // Simulate mining: update leaf_index after commitment appears in pool.
    let mut mined = fetched;
    mined.leaf_index = Some(42);
    db.put_note(&mined).expect("Failed to update mined note");
    assert_eq!(
        db.get_note(COMMITMENT_1)
            .expect("Failed to get mined note")
            .expect("Expected mined note to exist")
            .leaf_index,
        Some(42)
    );
}

#[test]
fn user_notes_get_by_owner() {
    let db = open();
    db.put_note(&sample_note(COMMITMENT_1, ADDR_ALICE, false))
        .expect("Failed to put note 1");
    db.put_note(&sample_note(COMMITMENT_2, ADDR_ALICE, false))
        .expect("Failed to put note 2");
    db.put_note(&sample_note(COMMITMENT_3, ADDR_BOB, false))
        .expect("Failed to put note 3");

    assert_eq!(
        db.get_notes_by_owner(ADDR_ALICE)
            .expect("Failed to get Alice's notes")
            .len(),
        2
    );
    assert_eq!(
        db.get_notes_by_owner(ADDR_BOB)
            .expect("Failed to get Bob's notes")
            .len(),
        1
    );
}

#[test]
fn user_notes_mark_spent_via_put() {
    let db = open();
    db.put_note(&sample_note(COMMITMENT_1, ADDR_ALICE, false))
        .expect("Failed to put note");

    let mut updated = db
        .get_note(COMMITMENT_1)
        .expect("Failed to get note")
        .expect("Expected note to exist");
    updated.spent = true;
    updated.spent_at_ledger = Some(LEDGER_C);
    db.put_note(&updated).expect("Failed to update note");

    let fetched = db
        .get_note(COMMITMENT_1)
        .expect("Failed to get updated note")
        .expect("Expected updated note to exist");
    assert!(fetched.spent);
    assert_eq!(fetched.spent_at_ledger, Some(LEDGER_C));
}

#[test]
fn user_notes_get_all_and_clear() {
    let db = open();
    db.put_note(&sample_note(COMMITMENT_1, ADDR_ALICE, false))
        .expect("Failed to put note 1");
    db.put_note(&sample_note(COMMITMENT_2, ADDR_BOB, true))
        .expect("Failed to put note 2");
    assert_eq!(db.get_all_notes().expect("Failed to get all").len(), 2);
    db.clear_notes().expect("Failed to clear");
    assert!(
        db.get_all_notes()
            .expect("Failed to get all after clear")
            .is_empty()
    );
}

#[test]
fn user_notes_is_received_roundtrip() {
    let db = open();
    let note = UserNote {
        is_received: true,
        ..sample_note(COMMITMENT_1, ADDR_ALICE, false)
    };
    db.put_note(&note).expect("Failed to put received note");
    assert!(
        db.get_note(COMMITMENT_1)
            .expect("Failed to get note")
            .expect("Expected note to exist")
            .is_received
    );
}

// ---------------------------------------------------------------------------
// registered_public_keys
// ---------------------------------------------------------------------------

#[test]
fn public_keys_put_get_count() {
    let db = open();
    db.put_public_key(&sample_key(ADDR_ALICE, LEDGER_A))
        .expect("Failed to put key");
    assert!(
        db.get_public_key(ADDR_ALICE)
            .expect("Failed to get Alice key")
            .is_some()
    );
    assert!(
        db.get_public_key(ADDR_BOB)
            .expect("Failed to get Bob key")
            .is_none()
    );
    assert_eq!(db.count_public_keys().expect("Failed to count"), 1);
}

#[test]
fn public_keys_get_all_ordered_by_ledger_desc() {
    let db = open();
    db.put_public_key(&sample_key(ADDR_ALICE, LEDGER_A))
        .expect("Failed to put Alice key");
    db.put_public_key(&sample_key(ADDR_BOB, LEDGER_C))
        .expect("Failed to put Bob key");

    let all = db.get_all_public_keys().expect("Failed to get all keys");
    assert_eq!(all[0].address, ADDR_BOB); // most recent ledger first
    assert_eq!(all[1].address, ADDR_ALICE);
}

// ---------------------------------------------------------------------------
// sync_metadata
// ---------------------------------------------------------------------------

#[test]
fn sync_metadata_put_get_delete() {
    let db = open();
    db.put_sync_metadata(&sample_sync_meta("testnet"))
        .expect("Failed to put sync metadata");
    assert!(
        !db.get_sync_metadata("testnet")
            .expect("Failed to get sync metadata")
            .expect("Expected metadata to exist")
            .pool_sync
            .sync_broken
    );
    db.delete_sync_metadata("testnet")
        .expect("Failed to delete sync metadata");
    assert!(
        db.get_sync_metadata("testnet")
            .expect("Failed to get deleted metadata")
            .is_none()
    );
}

#[test]
fn sync_metadata_cursor_round_trip() {
    let db = open();
    let mut meta = sample_sync_meta("testnet");
    meta.pool_sync.last_ledger = LEDGER_B;
    meta.pool_sync.last_cursor = Some("CAAAAAAAAABkAAAAAA==".into());
    db.put_sync_metadata(&meta)
        .expect("Failed to put sync metadata");

    let fetched = db
        .get_sync_metadata("testnet")
        .expect("Failed to get sync metadata")
        .expect("Expected metadata to exist");
    assert_eq!(fetched.pool_sync.last_ledger, LEDGER_B);
    assert_eq!(
        fetched.pool_sync.last_cursor.as_deref(),
        Some("CAAAAAAAAABkAAAAAA==")
    );
}

// ---------------------------------------------------------------------------
// retention_config
// ---------------------------------------------------------------------------

#[test]
fn retention_config_put_get() {
    let db = open();
    db.put_retention_config(&RetentionConfig {
        rpc_endpoint: "https://soroban-testnet.stellar.org".into(),
        window: 120_960,
        description: "7 days".into(),
        warning_threshold: 96_768,
        detected_at: "2025-03-19T00:00:00Z".into(),
    })
    .expect("Failed to put retention config");

    let fetched = db
        .get_retention_config("https://soroban-testnet.stellar.org")
        .expect("Failed to get retention config")
        .expect("Expected config to exist");
    assert_eq!(fetched.window, 120_960);
    assert!(
        db.get_retention_config("https://other.example.com")
            .expect("Failed to get missing config")
            .is_none()
    );
}

// ---------------------------------------------------------------------------
// batch inserts
// ---------------------------------------------------------------------------

#[test]
fn pool_leaves_batch_insert() {
    let db = open();
    let leaves = vec![
        PoolLeaf {
            index: 0,
            commitment: COMMITMENT_1.into(),
            ledger: LEDGER_A,
        },
        PoolLeaf {
            index: 1,
            commitment: COMMITMENT_2.into(),
            ledger: LEDGER_B,
        },
        PoolLeaf {
            index: 2,
            commitment: COMMITMENT_3.into(),
            ledger: LEDGER_C,
        },
    ];
    db.put_pool_leaves_batch(&leaves)
        .expect("Failed to batch insert");
    assert_eq!(db.count_pool_leaves().expect("Failed to count"), 3);
}

#[test]
fn asp_leaves_batch_insert() {
    let db = open();
    let leaves = vec![
        AspMembershipLeaf {
            index: 0,
            leaf: LEAF_1.into(),
            root: ROOT_1.into(),
            ledger: LEDGER_A,
        },
        AspMembershipLeaf {
            index: 1,
            leaf: LEAF_2.into(),
            root: ROOT_2.into(),
            ledger: LEDGER_B,
        },
    ];
    db.put_asp_membership_leaves_batch(&leaves)
        .expect("Failed to batch insert");
    assert_eq!(
        db.count_asp_membership_leaves().expect("Failed to count"),
        2
    );
}

// ---------------------------------------------------------------------------
// clear_all
// ---------------------------------------------------------------------------

#[test]
fn clear_all_empties_every_store() {
    let db = open();
    db.put_pool_leaf(&PoolLeaf {
        index: 0,
        commitment: COMMITMENT_1.into(),
        ledger: LEDGER_A,
    })
    .expect("Failed to put pool leaf");
    db.put_nullifier(&PoolNullifier {
        nullifier: NULLIFIER_1.into(),
        ledger: LEDGER_A,
    })
    .expect("Failed to put nullifier");
    db.put_encrypted_output(&PoolEncryptedOutput {
        commitment: COMMITMENT_2.into(),
        leaf_index: 0,
        encrypted_output: ENC_KEY.into(),
        ledger: LEDGER_A,
    })
    .expect("Failed to put encrypted output");
    db.put_asp_membership_leaf(&AspMembershipLeaf {
        index: 0,
        leaf: LEAF_1.into(),
        root: ROOT_1.into(),
        ledger: LEDGER_A,
    })
    .expect("Failed to put asp leaf");
    db.put_note(&sample_note(COMMITMENT_3, ADDR_ALICE, false))
        .expect("Failed to put note");
    db.put_public_key(&sample_key(ADDR_BOB, LEDGER_A))
        .expect("Failed to put public key");
    db.put_sync_metadata(&sample_sync_meta("testnet"))
        .expect("Failed to put sync metadata");

    db.clear_all().expect("Failed to clear all");

    assert_eq!(
        db.count_pool_leaves().expect("Failed to count pool leaves"),
        0
    );
    assert_eq!(
        db.count_nullifiers().expect("Failed to count nullifiers"),
        0
    );
    assert!(
        db.get_all_encrypted_outputs()
            .expect("Failed to get encrypted outputs")
            .is_empty()
    );
    assert_eq!(
        db.count_asp_membership_leaves()
            .expect("Failed to count asp leaves"),
        0
    );
    assert!(db.get_all_notes().expect("Failed to get notes").is_empty());
    assert_eq!(
        db.count_public_keys().expect("Failed to count public keys"),
        0
    );
    assert!(
        db.get_sync_metadata("testnet")
            .expect("Failed to get sync metadata")
            .is_none()
    );
}
