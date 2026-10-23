//! The committed `keyOwnership` proving key and witness graph prove against
//! the built R1CS.

use anyhow::Result;
use stellar_private_payments::{
    prover::ProverEngine,
    types::{Field, KEY_OWNERSHIP_CIRCUIT, NotePrivateKey, NotePublicKey},
    zk::{
        crypto::derive_public_key,
        encryption::{registration_digest, registration_hash},
        flows::KeyOwnershipParams,
    },
};

fn engine() -> Result<ProverEngine> {
    let repo = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let keys = repo.join("deployments/testnet/circuit_keys");
    let circuits = repo.join("target/circuits-artifacts");
    ProverEngine::new(
        &std::fs::read(keys.join(format!("{KEY_OWNERSHIP_CIRCUIT}_proving_key.bin")))?,
        &std::fs::read(keys.join(format!("{KEY_OWNERSHIP_CIRCUIT}.graph.bin")))?,
        &std::fs::read(circuits.join(format!("{KEY_OWNERSHIP_CIRCUIT}.r1cs")))?,
    )
}

fn params(private_key: u8, registration_hash: Field) -> Result<KeyOwnershipParams> {
    let mut note_private_key = [0u8; 32];
    note_private_key[0] = private_key;
    let note_public_key: [u8; 32] = derive_public_key(&note_private_key)?
        .try_into()
        .map_err(|_| anyhow::anyhow!("public key is not 32 bytes"))?;
    Ok(KeyOwnershipParams {
        note_private_key: NotePrivateKey(note_private_key),
        note_public_key: NotePublicKey(note_public_key),
        registration_hash,
    })
}

#[test]
fn committed_artifacts_prove_key_ownership() -> Result<()> {
    let engine = engine()?;
    let digest = registration_digest("Privacy Pool Key Registration [v1]");
    // [0xff; 32] is above r, so the hash is reduced as on-chain.
    for (private_key, hash) in [
        (1, registration_hash(&digest)),
        (7, registration_hash(&[0xff; 32])),
    ] {
        let proof = engine.prove_key_ownership(params(private_key, hash)?)?;
        assert_eq!(proof.len(), 256);
    }
    Ok(())
}

#[test]
fn a_public_key_of_another_private_key_is_refused() -> Result<()> {
    let mut params = params(7, Field::ONE)?;
    params.note_public_key = self::params(8, Field::ONE)?.note_public_key;

    assert!(engine()?.prove_key_ownership(params).is_err());
    Ok(())
}
