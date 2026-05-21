//! Deployment key export helpers.
//!
//! Converts a final snarkjs `.zkey` into the binary and JSON formats used by
//! this repository (deployments + web prover).

use crate::{
    CommandRunner, ExportDeploymentArgs, assert_dir_exists, assert_output_allowed,
    assert_readable_file,
};
use anyhow::{Context, Result, anyhow, bail};
use ark_bn254::Bn254;
use ark_circom::read_zkey;
use ark_groth16::ProvingKey;
use ark_serialize::CanonicalDeserialize;
use std::{fs, io::BufReader, path::Path};

pub(crate) fn export_deployment(
    args: ExportDeploymentArgs,
    _runner: &dyn CommandRunner,
) -> Result<()> {
    assert_readable_file(&args.zkey, "zkey")?;
    assert_dir_exists(&args.out_dir)?;

    let pk_path = args
        .out_dir
        .join(format!("{}_proving_key.bin", args.basename));
    let vk_json_path = args.out_dir.join(format!("{}_vk.json", args.basename));
    let vk_soroban_path = args
        .out_dir
        .join(format!("{}_vk_soroban.bin", args.basename));
    let vk_const_path = args.out_dir.join(format!("{}_vk_const.rs", args.basename));

    for path in [&pk_path, &vk_json_path, &vk_soroban_path, &vk_const_path] {
        assert_output_allowed(path, args.force)?;
    }

    // Prefer parsing the snarkjs `.zkey` directly, without a JSON roundtrip.
    // This avoids subtle format/ordering issues (e.g. sparse query vectors).
    let pk = proving_key_from_zkey(&args.zkey)?;

    // Sanity check: proving key bytes must round-trip before writing to disk.
    // This ensures our reconstructed structure matches arkworks' canonical
    // encoding expectations.
    {
        use ark_serialize::CanonicalSerialize as _;
        let mut pk_bytes = Vec::new();
        pk.serialize_compressed(&mut pk_bytes)
            .map_err(|e| anyhow!("failed to serialize proving key: {e}"))?;
        ProvingKey::<Bn254>::deserialize_compressed_unchecked(&pk_bytes[..])
            .map_err(|e| anyhow!("failed to round-trip proving key bytes: {e}"))?;
    }

    circuit_keys::write_proving_key_bin(&pk, &pk_path)?;
    circuit_keys::write_vk_snarkjs_json(&pk.vk, &vk_json_path)?;
    circuit_keys::write_vk_soroban_bin(&pk.vk, &vk_soroban_path)?;
    circuit_keys::write_vk_rust_const(&pk.vk, &vk_const_path)?;

    // Validate emitted proving key by checking the on-disk verifying key matches.
    // We deserialize unchecked here because the proving key is derived from a
    // trusted ceremony.
    let written_pk = ProvingKey::<Bn254>::deserialize_compressed_unchecked(
        &fs::read(&pk_path).with_context(|| format!("failed to read {}", pk_path.display()))?[..],
    )
    .map_err(|e| anyhow!("failed to read back {}: {e}", pk_path.display()))?;

    if circuit_keys::vk_to_snarkjs_json(&written_pk.vk) != circuit_keys::vk_to_snarkjs_json(&pk.vk)
    {
        bail!("validation failed: proving key contains a different verification key");
    }

    println!("Generated:");
    println!("  {}", pk_path.display());
    println!("  {}", vk_json_path.display());
    println!("  {}", vk_soroban_path.display());
    println!("  {}", vk_const_path.display());

    Ok(())
}

fn proving_key_from_zkey(zkey_path: &Path) -> Result<ProvingKey<Bn254>> {
    let file = fs::File::open(zkey_path)
        .with_context(|| format!("failed to open {}", zkey_path.display()))?;
    let mut reader = BufReader::new(file);
    let (pk, _matrices) = read_zkey(&mut reader)
        .map_err(|e| anyhow!("failed to parse snarkjs zkey {}: {e}", zkey_path.display()))?;
    Ok(pk)
}
