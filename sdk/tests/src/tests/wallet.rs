//! Wallet reads through
//! [`stellar_private_payments_sdk::blocking::PrivatePool`].

use crate::{pool::test_pool, seed::seeded_user_public_keys};
use stellar_private_payments_sdk::types::NoteAmount;

#[test]
fn balance_zero() {
    let pool = test_pool(Some(&[])).expect("test pool");

    let balance = pool.balance().expect("balance");
    assert_eq!(balance, NoteAmount::from(0u128));
}

#[test]
fn balance_some() {
    let pool = test_pool(Some(&[2, 3, 5])).expect("test pool");

    let balance = pool.balance().expect("balance");
    assert_eq!(balance, NoteAmount::from(10u128));
}

#[test]
fn spendable_notes() {
    let pool = test_pool(Some(&[2, 3, 5])).expect("test pool");

    let notes = pool.spendable_notes().expect("spendable notes");
    assert_eq!(notes.len(), 3);

    let mut amounts: Vec<_> = notes.iter().map(|n| n.amount).collect();
    amounts.sort();
    assert_eq!(
        amounts,
        [
            NoteAmount::from(2u128),
            NoteAmount::from(3u128),
            NoteAmount::from(5u128),
        ]
    );
}

#[test]
fn user_public_keys() {
    let pool = test_pool(Some(&[2, 3, 5])).expect("test pool");

    let (note, enc) = pool
        .user_public_keys(&pool.config().user_address)
        .expect("user public keys");
    let (expected_note, expected_enc) = seeded_user_public_keys().expect("seeded keys");

    assert_eq!(note.0, expected_note.0);
    assert_eq!(enc.0, expected_enc.0);
}

#[test]
fn notes_some() {
    let pool = test_pool(Some(&[2, 3, 5])).expect("test pool");

    let notes = pool.notes().expect("notes");
    assert_eq!(notes.len(), 3);

    let spendable = pool.spendable_notes().expect("spendable notes");
    assert_eq!(notes.len(), spendable.len());

    let mut note_amounts: Vec<_> = notes.iter().map(|n| n.amount).collect();
    note_amounts.sort();
    assert_eq!(
        note_amounts,
        [
            NoteAmount::from(2u128),
            NoteAmount::from(3u128),
            NoteAmount::from(5u128),
        ]
    );
}
