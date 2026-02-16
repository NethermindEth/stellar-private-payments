//! Output formatting (tables, JSON).

use ark_ff::BigInteger;
use zkhash::{ark_ff::PrimeField, fields::bn256::FpBN256 as Scalar};

use crate::db::UserNote;

/// Print derived keys.
pub fn print_keys(note_privkey: &Scalar, note_pubkey: &Scalar, enc_pubkey: &[u8; 32]) {
    println!(
        "  Note private key (LE hex): {}",
        hex::encode(note_privkey.into_bigint().to_bytes_le())
    );
    println!(
        "  Note public key  (BE hex): {}",
        hex::encode(note_pubkey.into_bigint().to_bytes_be())
    );
    println!("  Encryption public key:     {}", hex::encode(enc_pubkey));
}

/// Print a list of notes.
pub fn print_notes(notes: &[UserNote]) {
    if notes.is_empty() {
        println!("No notes found.");
        return;
    }

    println!(
        "{:<8} {:<12} {:<8} {:<66}",
        "Index", "Amount", "Status", "Commitment"
    );
    println!("{}", "-".repeat(96));

    for note in notes {
        let status = if note.spent == 1 { "spent" } else { "unspent" };
        println!(
            "{:<8} {:<12} {:<8} {}",
            note.leaf_index, note.amount, status, note.id
        );
    }

    let total: u64 = notes
        .iter()
        .filter(|n| n.spent == 0)
        .map(|n| n.amount)
        .sum();
    println!("\nTotal unspent: {total} stroops");
}
