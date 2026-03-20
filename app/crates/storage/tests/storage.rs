//! Integration tests for the storage crate (native backend).

#![allow(clippy::unwrap_used, clippy::cast_possible_truncation)]

use storage::{
    Storage,
    types::{
        AspMembershipLeaf, PoolEncryptedOutput, PoolLeaf, PoolNullifier, PublicKeyEntry,
        RetentionConfig, SyncCursor, SyncMetadata, UserNote,
    },
};

// ---------------------------------------------------------------------------
// Test fixtures — realistic-looking values matching what the app produces.
// Stellar addresses: 56-char G-prefix base32.
// Field elements / hashes: 0x + 64 hex chars (32 bytes).
// ---------------------------------------------------------------------------

const ADDR_ALICE: &str = "GBBD47IF6LWK7P7MDEVSCWR7DPUWV3NY3DTQEVFL4NAT4AQH3ZLLFLA5";
const ADDR_BOB: &str = "GCEZWKCA5VLDNRLN3RPRJMRZOX3Z6G5CHCGZWL8AYPKVF9P5T6B4N6E";

// 32-byte Poseidon2 field elements (random-looking but fixed for
// reproducibility)
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

// Realistic Stellar testnet ledger numbers
const LEDGER_A: u32 = 50_000_100;
const LEDGER_B: u32 = 50_000_200;
const LEDGER_C: u32 = 50_000_300;

fn open() -> Storage {
    Storage::open_in_memory().expect("open_in_memory")
}

fn sample_note(id: &str, owner: &str, spent: bool) -> UserNote {
    UserNote {
        id: id.into(),
        owner: owner.into(),
        private_key: PRIVATE_KEY.into(),
        blinding: BLINDING.into(),
        amount: "1000000000".into(), // stroops
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
    .unwrap();
    db.put_pool_leaf(&PoolLeaf {
        index: 1,
        commitment: COMMITMENT_2.into(),
        ledger: LEDGER_B,
    })
    .unwrap();

    let mut seen = Vec::new();
    db.iterate_pool_leaves(|leaf| {
        seen.push(leaf.index);
        true
    })
    .unwrap();
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
    .unwrap();
    assert_eq!(db.count_pool_leaves().unwrap(), 1);
    db.clear_pool_leaves().unwrap();
    assert_eq!(db.count_pool_leaves().unwrap(), 0);
}

#[test]
fn pool_leaves_replace_on_same_index() {
    let db = open();
    db.put_pool_leaf(&PoolLeaf {
        index: 0,
        commitment: COMMITMENT_1.into(),
        ledger: LEDGER_A,
    })
    .unwrap();
    db.put_pool_leaf(&PoolLeaf {
        index: 0,
        commitment: COMMITMENT_2.into(),
        ledger: LEDGER_B,
    })
    .unwrap();
    assert_eq!(db.count_pool_leaves().unwrap(), 1);
}

#[test]
fn pool_leaves_iterate_early_stop() {
    let db = open();
    let commitments = [COMMITMENT_1, COMMITMENT_2, COMMITMENT_3];
    for (i, c) in commitments.iter().enumerate() {
        db.put_pool_leaf(&PoolLeaf {
            index: i as u32,
            commitment: (*c).into(),
            ledger: LEDGER_A.saturating_add(i as u32),
        })
        .unwrap();
    }
    let mut count = 0_u32;
    db.iterate_pool_leaves(|_| {
        count = count.saturating_add(1);
        count < 2
    })
    .unwrap();
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
    .unwrap();
    assert!(db.get_nullifier(NULLIFIER_1).unwrap().is_some());
    assert!(db.get_nullifier(COMMITMENT_1).unwrap().is_none());
    assert_eq!(db.count_nullifiers().unwrap(), 1);
}

#[test]
fn pool_nullifiers_clear() {
    let db = open();
    db.put_nullifier(&PoolNullifier {
        nullifier: NULLIFIER_1.into(),
        ledger: LEDGER_A,
    })
    .unwrap();
    db.clear_nullifiers().unwrap();
    assert_eq!(db.count_nullifiers().unwrap(), 0);
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
    .unwrap();
    db.put_encrypted_output(&PoolEncryptedOutput {
        commitment: COMMITMENT_2.into(),
        leaf_index: 1,
        encrypted_output: NOTE_KEY.into(),
        ledger: LEDGER_C,
    })
    .unwrap();

    assert_eq!(db.get_all_encrypted_outputs().unwrap().len(), 2);

    let filtered = db.get_encrypted_outputs_from(LEDGER_B).unwrap();
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
    .unwrap();
    db.clear_encrypted_outputs().unwrap();
    assert!(db.get_all_encrypted_outputs().unwrap().is_empty());
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
    .unwrap();
    db.put_asp_membership_leaf(&AspMembershipLeaf {
        index: 1,
        leaf: LEAF_2.into(),
        root: ROOT_2.into(),
        ledger: LEDGER_B,
    })
    .unwrap();

    assert_eq!(db.count_asp_membership_leaves().unwrap(), 2);
    assert_eq!(
        db.get_asp_membership_leaf_by_hash(LEAF_2)
            .unwrap()
            .unwrap()
            .index,
        1
    );
    assert!(
        db.get_asp_membership_leaf_by_hash(COMMITMENT_3)
            .unwrap()
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
        .unwrap();
    }
    let mut indices = Vec::new();
    db.iterate_asp_membership_leaves(|l| {
        indices.push(l.index);
        true
    })
    .unwrap();
    assert_eq!(indices, vec![0, 2]);
}

// ---------------------------------------------------------------------------
// user_notes
// ---------------------------------------------------------------------------

#[test]
fn user_notes_put_get_delete() {
    let db = open();
    db.put_note(&sample_note(COMMITMENT_1, ADDR_ALICE, false))
        .unwrap();
    let fetched = db.get_note(COMMITMENT_1).unwrap().expect("should exist");
    assert_eq!(fetched.owner, ADDR_ALICE);
    assert!(!fetched.spent);

    db.delete_note(COMMITMENT_1).unwrap();
    assert!(db.get_note(COMMITMENT_1).unwrap().is_none());
}

#[test]
fn user_notes_pending_leaf_index_null() {
    // Notes start with leaf_index = None (pending / not yet mined).
    let db = open();
    let note = UserNote {
        id: COMMITMENT_1.into(),
        owner: ADDR_ALICE.into(),
        private_key: PRIVATE_KEY.into(),
        blinding: BLINDING.into(),
        amount: "5000000000".into(),
        leaf_index: None, // not yet mined
        created_at: "2025-03-01T00:00:00Z".into(),
        created_at_ledger: LEDGER_A,
        spent: false,
        spent_at_ledger: None,
        is_received: false,
    };
    db.put_note(&note).unwrap();
    let fetched = db.get_note(COMMITMENT_1).unwrap().unwrap();
    assert!(fetched.leaf_index.is_none());

    // Simulate mining: update leaf_index after commitment appears in pool.
    let mut mined = fetched;
    mined.leaf_index = Some(42);
    db.put_note(&mined).unwrap();
    assert_eq!(
        db.get_note(COMMITMENT_1).unwrap().unwrap().leaf_index,
        Some(42)
    );
}

#[test]
fn user_notes_get_by_owner() {
    let db = open();
    db.put_note(&sample_note(COMMITMENT_1, ADDR_ALICE, false))
        .unwrap();
    db.put_note(&sample_note(COMMITMENT_2, ADDR_ALICE, false))
        .unwrap();
    db.put_note(&sample_note(COMMITMENT_3, ADDR_BOB, false))
        .unwrap();

    assert_eq!(db.get_notes_by_owner(ADDR_ALICE).unwrap().len(), 2);
    assert_eq!(db.get_notes_by_owner(ADDR_BOB).unwrap().len(), 1);
}

#[test]
fn user_notes_mark_spent_via_put() {
    let db = open();
    db.put_note(&sample_note(COMMITMENT_1, ADDR_ALICE, false))
        .unwrap();

    let mut updated = db.get_note(COMMITMENT_1).unwrap().unwrap();
    updated.spent = true;
    updated.spent_at_ledger = Some(LEDGER_C);
    db.put_note(&updated).unwrap();

    let fetched = db.get_note(COMMITMENT_1).unwrap().unwrap();
    assert!(fetched.spent);
    assert_eq!(fetched.spent_at_ledger, Some(LEDGER_C));
}

#[test]
fn user_notes_get_all_and_clear() {
    let db = open();
    db.put_note(&sample_note(COMMITMENT_1, ADDR_ALICE, false))
        .unwrap();
    db.put_note(&sample_note(COMMITMENT_2, ADDR_BOB, true))
        .unwrap();
    assert_eq!(db.get_all_notes().unwrap().len(), 2);
    db.clear_notes().unwrap();
    assert!(db.get_all_notes().unwrap().is_empty());
}

#[test]
fn user_notes_is_received_roundtrip() {
    let db = open();
    let note = UserNote {
        is_received: true,
        ..sample_note(COMMITMENT_1, ADDR_ALICE, false)
    };
    db.put_note(&note).unwrap();
    assert!(db.get_note(COMMITMENT_1).unwrap().unwrap().is_received);
}

// ---------------------------------------------------------------------------
// registered_public_keys
// ---------------------------------------------------------------------------

#[test]
fn public_keys_put_get_count() {
    let db = open();
    db.put_public_key(&sample_key(ADDR_ALICE, LEDGER_A))
        .unwrap();
    assert!(db.get_public_key(ADDR_ALICE).unwrap().is_some());
    assert!(db.get_public_key(ADDR_BOB).unwrap().is_none());
    assert_eq!(db.count_public_keys().unwrap(), 1);
}

#[test]
fn public_keys_get_all_ordered_by_ledger_desc() {
    let db = open();
    db.put_public_key(&sample_key(ADDR_ALICE, LEDGER_A))
        .unwrap();
    db.put_public_key(&sample_key(ADDR_BOB, LEDGER_C)).unwrap();

    let all = db.get_all_public_keys().unwrap();
    assert_eq!(all[0].address, ADDR_BOB); // most recent ledger first
    assert_eq!(all[1].address, ADDR_ALICE);
}

// ---------------------------------------------------------------------------
// sync_metadata
// ---------------------------------------------------------------------------

#[test]
fn sync_metadata_put_get_delete() {
    let db = open();
    db.put_sync_metadata(&sample_sync_meta("testnet")).unwrap();
    assert!(
        !db.get_sync_metadata("testnet")
            .unwrap()
            .unwrap()
            .pool_sync
            .sync_broken
    );
    db.delete_sync_metadata("testnet").unwrap();
    assert!(db.get_sync_metadata("testnet").unwrap().is_none());
}

#[test]
fn sync_metadata_cursor_round_trip() {
    let db = open();
    let mut meta = sample_sync_meta("testnet");
    meta.pool_sync.last_ledger = LEDGER_B;
    meta.pool_sync.last_cursor = Some("CAAAAAAAAABkAAAAAA==".into()); // realistic base64 cursor
    db.put_sync_metadata(&meta).unwrap();

    let fetched = db.get_sync_metadata("testnet").unwrap().unwrap();
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
    .unwrap();

    let fetched = db
        .get_retention_config("https://soroban-testnet.stellar.org")
        .unwrap()
        .unwrap();
    assert_eq!(fetched.window, 120_960);
    assert!(
        db.get_retention_config("https://other.example.com")
            .unwrap()
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
    db.put_pool_leaves_batch(&leaves).unwrap();
    assert_eq!(db.count_pool_leaves().unwrap(), 3);
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
    db.put_asp_membership_leaves_batch(&leaves).unwrap();
    assert_eq!(db.count_asp_membership_leaves().unwrap(), 2);
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
    .unwrap();
    db.put_nullifier(&PoolNullifier {
        nullifier: NULLIFIER_1.into(),
        ledger: LEDGER_A,
    })
    .unwrap();
    db.put_encrypted_output(&PoolEncryptedOutput {
        commitment: COMMITMENT_2.into(),
        leaf_index: 0,
        encrypted_output: ENC_KEY.into(),
        ledger: LEDGER_A,
    })
    .unwrap();
    db.put_asp_membership_leaf(&AspMembershipLeaf {
        index: 0,
        leaf: LEAF_1.into(),
        root: ROOT_1.into(),
        ledger: LEDGER_A,
    })
    .unwrap();
    db.put_note(&sample_note(COMMITMENT_3, ADDR_ALICE, false))
        .unwrap();
    db.put_public_key(&sample_key(ADDR_BOB, LEDGER_A)).unwrap();
    db.put_sync_metadata(&sample_sync_meta("testnet")).unwrap();

    db.clear_all().unwrap();

    assert_eq!(db.count_pool_leaves().unwrap(), 0);
    assert_eq!(db.count_nullifiers().unwrap(), 0);
    assert!(db.get_all_encrypted_outputs().unwrap().is_empty());
    assert_eq!(db.count_asp_membership_leaves().unwrap(), 0);
    assert!(db.get_all_notes().unwrap().is_empty());
    assert_eq!(db.count_public_keys().unwrap(), 0);
    assert!(db.get_sync_metadata("testnet").unwrap().is_none());
}
