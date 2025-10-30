use super::{
    circom_tester::{InputValue, prove_and_verify},
    keypair::{derive_public_key, sign},
    utils::general::scalar_to_bigint,
};

use anyhow::{Context, Result};
use std::{collections::HashMap, env, path::PathBuf};
use zkhash::fields::bn256::FpBN256 as Scalar;

fn run_keypair_case(wasm: &PathBuf, r1cs: &PathBuf, private_key: Scalar) -> Result<()> {
    // compute expected in Rust
    let expected_pk = derive_public_key(private_key);

    // build inputs, including the expected value
    let mut inputs: HashMap<String, InputValue> = HashMap::new();
    inputs.insert(
        "privateKey".into(),
        InputValue::Single(scalar_to_bigint(private_key)),
    );
    inputs.insert(
        "expectedPublicKey".into(),
        InputValue::Single(scalar_to_bigint(expected_pk)),
    );

    let res = prove_and_verify(wasm, r1cs, &inputs)?;
    anyhow::ensure!(res.verified, "Keypair proof did not verify");
    Ok(())
}

fn run_signature_case(
    wasm: &PathBuf,
    r1cs: &PathBuf,
    private_key: Scalar,
    commitment: Scalar,
    merkle_path: Scalar,
) -> Result<()> {
    // compute expected in Rust
    let expected_sig = sign(private_key, commitment, merkle_path);

    //inputs incl. expected
    let mut inputs: HashMap<String, InputValue> = HashMap::new();
    inputs.insert(
        "privateKey".into(),
        InputValue::Single(scalar_to_bigint(private_key)),
    );
    inputs.insert(
        "commitment".into(),
        InputValue::Single(scalar_to_bigint(commitment)),
    );
    inputs.insert(
        "merklePath".into(),
        InputValue::Single(scalar_to_bigint(merkle_path)),
    );
    inputs.insert(
        "expectedSig".into(),
        InputValue::Single(scalar_to_bigint(expected_sig)),
    );

    let res = prove_and_verify(wasm, r1cs, &inputs)?;
    anyhow::ensure!(res.verified, "Signature proof did not verify");
    Ok(())
}

#[tokio::test]
async fn test_keypair_test_matrix() -> anyhow::Result<()> {
    // === PATH SETUP ===
    let out_dir = PathBuf::from(env!("CIRCUIT_OUT_DIR"));
    let wasm = out_dir.join("wasm/keypair_test_js/keypair_test.wasm");
    let r1cs = out_dir.join("keypair_test.r1cs");

    if !wasm.exists() {
        return Err(anyhow::anyhow!("WASM file not found at {}", wasm.display()));
    }
    if !r1cs.exists() {
        return Err(anyhow::anyhow!("R1CS file not found at {}", r1cs.display()));
    }

    // Simple test set
    let cases: [u64; 8] = [0, 1, 2, 7, 8, 15, 16, 23];

    for &x in &cases {
        let sk = Scalar::from(x);
        run_keypair_case(&wasm, &r1cs, sk)
            .with_context(|| format!("Keypair case failed for sk={x}"))?;
    }

    Ok(())
}

#[tokio::test]
async fn test_signature_test_matrix() -> anyhow::Result<()> {
    // === PATH SETUP ===
    let out_dir = PathBuf::from(env!("CIRCUIT_OUT_DIR"));
    let wasm = out_dir.join("wasm/signature_test_js/signature_test.wasm");
    let r1cs = out_dir.join("signature_test.r1cs");

    if !wasm.exists() {
        return Err(anyhow::anyhow!("WASM file not found at {}", wasm.display()));
    }
    if !r1cs.exists() {
        return Err(anyhow::anyhow!("R1CS file not found at {}", r1cs.display()));
    }

    let triples: [(u64, u64, u64); 8] = [
        (0, 0, 0),
        (1, 2, 3),
        (7, 8, 9),
        (15, 16, 17),
        (23, 24, 25),
        (31, 1, 2),
        (127, 255, 511),
        (0xDEAD, 0xBEEF, 0xCAFE),
    ];

    for &(sk_u, cm_u, mp_u) in &triples {
        let sk = Scalar::from(sk_u);
        let cm = Scalar::from(cm_u);
        let mp = Scalar::from(mp_u);

        run_signature_case(&wasm, &r1cs, sk, cm, mp).with_context(|| {
            format!("Signature case failed for (sk,cm,mp)=({sk_u},{cm_u},{mp_u})")
        })?;
    }

    Ok(())
}
