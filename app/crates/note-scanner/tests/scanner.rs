//! Integration tests for the `note-scanner` crate.

#![allow(missing_docs)]

use note_scanner::{
    compute_commitment, compute_nullifier, compute_signature, derive_nullifier_for_note,
    try_decrypt_note,
};
use utils::merkle::{FIELD_SIZE, scalar_to_array};
use zkhash::fields::bn256::FpBN256 as Scalar;

#[test]
fn commitment_is_deterministic() {
    let amount = scalar_to_array(&Scalar::from(1000u64));
    let pk = scalar_to_array(&Scalar::from(42u64));
    let blinding = scalar_to_array(&Scalar::from(99u64));

    let c1 = compute_commitment(&amount, &pk, &blinding).expect("ok");
    let c2 = compute_commitment(&amount, &pk, &blinding).expect("ok");
    assert_eq!(c1, c2);
}

#[test]
fn different_inputs_different_commitments() {
    let pk = scalar_to_array(&Scalar::from(42u64));
    let blinding = scalar_to_array(&Scalar::from(99u64));

    let c1 =
        compute_commitment(&scalar_to_array(&Scalar::from(100u64)), &pk, &blinding).expect("ok");
    let c2 =
        compute_commitment(&scalar_to_array(&Scalar::from(200u64)), &pk, &blinding).expect("ok");
    assert_ne!(c1, c2);
}

#[test]
fn nullifier_derivation_is_deterministic() {
    let sk = scalar_to_array(&Scalar::from(7u64));
    let cm = scalar_to_array(&Scalar::from(123u64));

    let n1 = derive_nullifier_for_note(&sk, &cm, 0).expect("ok");
    let n2 = derive_nullifier_for_note(&sk, &cm, 0).expect("ok");
    assert_eq!(n1, n2);
}

#[test]
fn different_leaf_index_different_nullifier() {
    let sk = scalar_to_array(&Scalar::from(7u64));
    let cm = scalar_to_array(&Scalar::from(123u64));

    let n1 = derive_nullifier_for_note(&sk, &cm, 0).expect("ok");
    let n2 = derive_nullifier_for_note(&sk, &cm, 1).expect("ok");
    assert_ne!(n1, n2);
}

#[test]
fn signature_uses_domain_4_nullifier_uses_domain_2() {
    let a = scalar_to_array(&Scalar::from(1u64));
    let b = scalar_to_array(&Scalar::from(2u64));
    let c = scalar_to_array(&Scalar::from(3u64));

    let sig = compute_signature(&a, &b, &c).expect("ok");
    let nul = compute_nullifier(&a, &b, &c).expect("ok");
    assert_ne!(sig, nul, "different domains must produce different outputs");
}

#[test]
fn decrypt_rejects_short_data() {
    let key = [0u8; FIELD_SIZE];
    assert!(try_decrypt_note(&key, &[0u8; 50]).is_none());
}

#[test]
fn decrypt_rejects_wrong_key() {
    let key = [0u8; FIELD_SIZE];
    let garbage = [0u8; 112];
    assert!(try_decrypt_note(&key, &garbage).is_none());
}
