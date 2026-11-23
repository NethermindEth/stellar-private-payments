//! Deployment key export helpers.
//!
//! Converts a final snarkjs `.zkey` into the binary and JSON formats used by
//! this repository (deployments + web prover).

use crate::{
    CommandRunner, ExportDeploymentArgs, assert_dir_exists, assert_output_allowed,
    assert_readable_file, verify_zkey, zkey::read_zkey,
};
use anyhow::{Context, Result, anyhow, bail};
use ark_bn254::Bn254;
use ark_groth16::ProvingKey;
use ark_serialize::CanonicalDeserialize;
use std::{fs, io::BufReader, path::Path};

pub(crate) fn export_deployment(
    args: ExportDeploymentArgs,
    runner: &dyn CommandRunner,
) -> Result<()> {
    assert_readable_file(&args.zkey, "zkey")?;
    assert_dir_exists(&args.out_dir)?;
    let circuit = args.setup.resolve()?;

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

    // Parsing is cheap and writes nothing, so malformed keys fail before the
    // much slower `zkey verify`.
    let pk = proving_key_from_zkey(&args.zkey)?;
    verify_zkey(runner, &circuit, &args.setup.ptau, &args.zkey)?;

    circuit_keys::write_proving_key_bin(&pk, &pk_path)?;
    circuit_keys::write_vk_snarkjs_json(&pk.vk, &vk_json_path)?;
    circuit_keys::write_vk_soroban_bin(&pk.vk, &vk_soroban_path)?;
    circuit_keys::write_vk_rust_const(&pk.vk, &vk_const_path)?;

    // Unchecked deserialization is enough here: the points were already
    // validated when parsing the zkey.
    let written = fs::File::open(&pk_path)
        .with_context(|| format!("failed to open {}", pk_path.display()))?;
    let written_pk = ProvingKey::<Bn254>::deserialize_compressed_unchecked(BufReader::new(written))
        .map_err(|e| anyhow!("failed to read back {}: {e}", pk_path.display()))?;
    if written_pk != pk {
        bail!("validation failed: written proving key differs from the zkey");
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
    read_zkey(&mut reader)
        .map_err(|e| anyhow!("failed to parse snarkjs zkey {}: {e}", zkey_path.display()))
}
