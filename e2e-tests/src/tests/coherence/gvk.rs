//! Circuits GVK reference must stay bit-identical to the SDK off-chain copy.

use ark_bn254::Fr as Scalar;
use circuits::test::utils::global_view_key::{Note, admin_public_key, encrypt_note};
use stellar_private_payments::{
    types::{BabyJubJubPoint, Field, U256},
    zk::{
        gvk::GvkNote,
        serialization::{field_to_scalar, scalar_to_field},
    },
};

fn field(value: u64) -> Field {
    Field(U256::from(value))
}

#[test]
fn gvk_encrypt_matches_circuit_reference() {
    let d_priv = Scalar::from(987_654_321u64);
    let d = admin_public_key(d_priv);
    // codeql[rust/hard-coded-cryptographic-value]
    let nonce = Scalar::from(42u64);
    let idx = Scalar::from(0u64);

    let ref_note = Note {
        pk: Scalar::from(0xABCDu64),
        amount: Scalar::from(1_000_000u64),
        blinding: Scalar::from(0xDEAD_BEEFu64),
        salt: Scalar::from(0xCAFE_F00Du64),
    };
    let ref_ct = encrypt_note(&ref_note, d, nonce, idx);

    let sdk_note = GvkNote {
        pk: field(0xABCD),
        amount: field(1_000_000),
        blinding: field(0xDEAD_BEEF),
        salt: field(0xCAFE_F00D),
    };
    let admin =
        BabyJubJubPoint::from_priv_scalar(&scalar_to_field(&d_priv)).expect("valid admin key");
    let sdk_ct = sdk_note
        .encrypt(&admin, &field(42), 0)
        .expect("sdk encrypt");

    assert_eq!(field_to_scalar(&sdk_ct.r.x), ref_ct.r.0, "R.x diverged");
    assert_eq!(field_to_scalar(&sdk_ct.r.y), ref_ct.r.1, "R.y diverged");
    assert_eq!(field_to_scalar(&sdk_ct.c1), ref_ct.c1, "c1 diverged");
    assert_eq!(field_to_scalar(&sdk_ct.c2), ref_ct.c2, "c2 diverged");
    assert_eq!(field_to_scalar(&sdk_ct.c3), ref_ct.c3, "c3 diverged");
}
