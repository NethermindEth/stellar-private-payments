//! Circuit input assembly, witness generation, Groth16 proving.
//!
//! Reuses the circuit test utilities directly, following the pattern in
//! `e2e-tests/src/tests/utils.rs:280-414`.

use anyhow::{Result, bail};
use ark_bn254::{Bn254, Fr};
use ark_circom::{CircomBuilder, CircomConfig};
use ark_groth16::{Groth16, PreparedVerifyingKey, Proof, ProvingKey, VerifyingKey};
use ark_serialize::CanonicalDeserialize;
use ark_snark::SNARK;
use ark_std::rand::thread_rng;
use num_bigint::{BigInt, BigUint};
use zkhash::{
    ark_ff::{BigInteger, PrimeField, Zero},
    fields::bn256::FpBN256 as Scalar,
};

use crate::crypto;
use crate::merkle;

/// Embedded circuit artifacts.
const CIRCUIT_WASM: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/policy_test.wasm"));
const CIRCUIT_R1CS: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/policy_test.r1cs"));
const PROVING_KEY: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/policy_test_proving_key.bin"));

/// Number of membership proofs per input.
const N_MEM_PROOFS: usize = 1;

/// Number of non-membership proofs per input.
const N_NON_PROOFS: usize = 1;

/// Input note for proof generation.
pub struct InputNote {
    /// Leaf index in the pool Merkle tree.
    pub leaf_index: usize,
    /// Note private key.
    pub priv_key: Scalar,
    /// Note blinding factor.
    pub blinding: Scalar,
    /// Note amount (0 for dummy inputs).
    pub amount: Scalar,
}

/// Output note for proof generation.
pub struct OutputNote {
    /// Recipient's note public key.
    pub pub_key: Scalar,
    /// Random blinding factor.
    pub blinding: Scalar,
    /// Output amount.
    pub amount: Scalar,
}

/// Result of proof generation.
pub struct ProofResult {
    /// The Groth16 proof (a, b, c curve points).
    pub proof: Proof<Bn254>,
    /// Public inputs vector from the circuit.
    pub public_inputs: Vec<Fr>,
    /// Verification key (for local re-verification).
    pub vk: VerifyingKey<Bn254>,
    /// Pool Merkle root used in the proof.
    pub root: Scalar,
    /// Input nullifiers.
    pub nullifiers: Vec<Scalar>,
    /// Output commitments.
    pub output_commitments: Vec<Scalar>,
    /// ASP membership roots (one per input × membership proof).
    pub membership_roots: Vec<Scalar>,
    /// ASP non-membership roots (one per input × non-membership proof).
    pub non_membership_roots: Vec<Scalar>,
}

/// Convert a scalar field element to a `BigInt` for circuit inputs.
pub fn scalar_to_bigint(s: Scalar) -> BigInt {
    let bi = s.into_bigint();
    let bytes_le = bi.to_bytes_le();
    let u = BigUint::from_bytes_le(&bytes_le);
    BigInt::from(u)
}

/// Write temporary files and create CircomConfig.
fn load_circom_config() -> Result<CircomConfig<Fr>> {
    if CIRCUIT_WASM.is_empty() || CIRCUIT_R1CS.is_empty() {
        bail!("Circuit artifacts not embedded. Build the circuits crate first (cargo build -p circuits).");
    }

    // Write to temp files (ark-circom needs file paths)
    let tmp = std::env::temp_dir().join("stellar-spp-circuits");
    std::fs::create_dir_all(&tmp)?;
    let wasm_path = tmp.join("policy_test.wasm");
    let r1cs_path = tmp.join("policy_test.r1cs");
    std::fs::write(&wasm_path, CIRCUIT_WASM)?;
    std::fs::write(&r1cs_path, CIRCUIT_R1CS)?;

    CircomConfig::<Fr>::new(&wasm_path, &r1cs_path)
        .map_err(|e| anyhow::anyhow!("CircomConfig error: {e}"))
}

/// Load the embedded proving key.
fn load_proving_key() -> Result<(ProvingKey<Bn254>, VerifyingKey<Bn254>, PreparedVerifyingKey<Bn254>)> {
    if PROVING_KEY.is_empty() {
        bail!("Proving key not embedded. Ensure scripts/testdata/policy_test_proving_key.bin exists.");
    }

    let pk: ProvingKey<Bn254> = ProvingKey::deserialize_compressed(&mut &PROVING_KEY[..])
        .map_err(|e| anyhow::anyhow!("Failed to deserialize proving key: {e}"))?;
    let vk = pk.vk.clone();
    let pvk = Groth16::<Bn254>::process_vk(&vk)
        .map_err(|e| anyhow::anyhow!("process_vk failed: {e}"))?;

    Ok((pk, vk, pvk))
}

/// Generate a Groth16 proof for a transaction.
///
/// Follows the pattern from `e2e-tests/src/tests/utils.rs`.
///
/// For zero-amount (dummy) inputs, the Merkle inclusion check is disabled by
/// the circuit's `ForceEqualIfEnabled` component, so the pool tree is not
/// modified for those inputs.
#[allow(clippy::too_many_arguments)]
pub fn generate_proof(
    inputs: &[InputNote],
    outputs: &[OutputNote],
    pool_leaves: &[Scalar],
    public_amount: Scalar,
    ext_data_hash: Option<BigInt>,
    asp_membership_leaves: &[Scalar],
    asp_membership_index: usize,
    asp_membership_blinding: Scalar,
) -> Result<ProofResult> {
    let cfg = load_circom_config()?;
    let (pk, vk, pvk) = load_proving_key()?;

    let n_inputs = inputs.len();

    // Build input commitments. Only place non-zero-amount inputs in the pool
    // tree — for zero-amount (dummy) inputs the circuit's Merkle root check
    // is gated off by `ForceEqualIfEnabled(enabled=amount)`.
    let mut leaves = pool_leaves.to_vec();
    let mut commitments = Vec::with_capacity(n_inputs);
    let mut public_keys = Vec::with_capacity(n_inputs);

    for note in inputs {
        let pk_scalar = crypto::derive_public_key(&note.priv_key);
        let cm = crypto::commitment(note.amount, pk_scalar, note.blinding);
        public_keys.push(pk_scalar);
        commitments.push(cm);
        if !note.amount.is_zero() {
            leaves[note.leaf_index] = cm;
        }
    }

    // Pool Merkle root and proofs
    let root = merkle::merkle_root(&leaves);
    let mut path_indices = Vec::with_capacity(n_inputs);
    let mut nullifiers = Vec::with_capacity(n_inputs);

    let mut builder = CircomBuilder::new(cfg);

    // Set root
    builder.push_input("root", scalar_to_bigint(root));
    builder.push_input("publicAmount", scalar_to_bigint(public_amount));
    builder.push_input(
        "extDataHash",
        ext_data_hash.clone().unwrap_or(BigInt::from(0u32)),
    );

    // Input notes
    for (i, note) in inputs.iter().enumerate() {
        let (siblings, path_idx_u64, _depth) = merkle::merkle_proof(&leaves, note.leaf_index);
        let path_idx = Scalar::from(path_idx_u64);
        path_indices.push(path_idx);

        let sig = crypto::sign(note.priv_key, commitments[i], path_idx);
        let nul = crypto::nullifier(commitments[i], path_idx, sig);
        nullifiers.push(nul);

        builder.push_input("inputNullifier", scalar_to_bigint(nul));
        builder.push_input("inAmount", scalar_to_bigint(note.amount));
        builder.push_input("inPrivateKey", scalar_to_bigint(note.priv_key));
        builder.push_input("inBlinding", scalar_to_bigint(note.blinding));
        builder.push_input("inPathIndices", scalar_to_bigint(path_idx));
        for sib in &siblings {
            builder.push_input("inPathElements", scalar_to_bigint(*sib));
        }
    }

    // Output commitments
    let mut output_commitments = Vec::with_capacity(outputs.len());
    for out in outputs {
        let cm = crypto::commitment(out.amount, out.pub_key, out.blinding);
        output_commitments.push(cm);
        builder.push_input("outputCommitment", scalar_to_bigint(cm));
        builder.push_input("outAmount", scalar_to_bigint(out.amount));
        builder.push_input("outPubkey", scalar_to_bigint(out.pub_key));
        builder.push_input("outBlinding", scalar_to_bigint(out.blinding));
    }

    // Membership proofs
    let mut membership_roots_bigint = Vec::new();
    let mut membership_roots_scalar = Vec::new();
    for _j in 0..N_MEM_PROOFS {
        // Build membership tree with all public keys
        let mut mem_leaves = asp_membership_leaves.to_vec();
        for pk_scalar in &public_keys {
            let leaf = crypto::membership_leaf(*pk_scalar, asp_membership_blinding);
            mem_leaves[asp_membership_index] = leaf;
        }
        let mem_root = merkle::merkle_root(&mem_leaves);

        for (i, pk_scalar) in public_keys.iter().enumerate() {
            let leaf = crypto::membership_leaf(*pk_scalar, asp_membership_blinding);
            let (siblings, path_idx_u64, _depth) =
                merkle::merkle_proof(&mem_leaves, asp_membership_index);

            let key_prefix = format!("membershipProofs[{i}][0]");
            builder.push_input(format!("{key_prefix}.leaf"), scalar_to_bigint(leaf));
            builder.push_input(
                format!("{key_prefix}.blinding"),
                scalar_to_bigint(asp_membership_blinding),
            );
            builder.push_input(
                format!("{key_prefix}.pathIndices"),
                scalar_to_bigint(Scalar::from(path_idx_u64)),
            );
            for sib in &siblings {
                builder.push_input(
                    format!("{key_prefix}.pathElements"),
                    scalar_to_bigint(*sib),
                );
            }

            membership_roots_bigint.push(scalar_to_bigint(mem_root));
            membership_roots_scalar.push(mem_root);
        }
    }
    for mr in &membership_roots_bigint {
        builder.push_input("membershipRoots", mr.clone());
    }

    // Non-membership proofs — prove each input's public key is NOT in the
    // sanctioned set (the ASP non-membership sparse Merkle tree).
    // We use empty overrides so the proof root matches the on-chain root.
    // If the on-chain tree is empty (root=0), an empty-tree non-inclusion
    // proof trivially proves non-membership for any key.
    let mut non_membership_roots_bigint = Vec::new();
    let mut non_membership_roots_scalar = Vec::new();
    for _j in 0..N_NON_PROOFS {
        for (i, pk_scalar) in public_keys.iter().enumerate() {
            let nm_key = scalar_to_bigint(*pk_scalar);
            let proof = circuits::test::utils::sparse_merkle_tree::prepare_smt_proof_with_overrides(
                &nm_key,
                &[],
                merkle::POOL_LEVELS,
            );

            let key_prefix = format!("nonMembershipProofs[{i}][0]");
            builder.push_input(format!("{key_prefix}.key"), scalar_to_bigint(*pk_scalar));

            if proof.is_old0 {
                builder.push_input(format!("{key_prefix}.oldKey"), BigInt::from(0u32));
                builder.push_input(format!("{key_prefix}.oldValue"), BigInt::from(0u32));
                builder.push_input(format!("{key_prefix}.isOld0"), BigInt::from(1u32));
            } else {
                builder.push_input(format!("{key_prefix}.oldKey"), proof.not_found_key.clone());
                builder.push_input(
                    format!("{key_prefix}.oldValue"),
                    proof.not_found_value.clone(),
                );
                builder.push_input(format!("{key_prefix}.isOld0"), BigInt::from(0u32));
            }
            for sib in &proof.siblings {
                builder.push_input(format!("{key_prefix}.siblings"), sib.clone());
            }

            // Convert root BigInt to Scalar for the result
            let root_bu = proof.root.to_biguint()
                .unwrap_or_default();
            non_membership_roots_scalar.push(Scalar::from(root_bu.clone()));
            non_membership_roots_bigint.push(proof.root.clone());
        }
    }
    for nmr in &non_membership_roots_bigint {
        builder.push_input("nonMembershipRoots", nmr.clone());
    }

    // Build and prove
    let circuit = builder
        .build()
        .map_err(|e| anyhow::anyhow!("Circuit build failed: {e}"))?;
    let mut rng = thread_rng();

    let proof = Groth16::<Bn254>::prove(&pk, circuit.clone(), &mut rng)
        .map_err(|e| anyhow::anyhow!("Proof generation failed: {e}"))?;

    let public_inputs = circuit
        .get_public_inputs()
        .ok_or_else(|| anyhow::anyhow!("get_public_inputs returned None"))?;

    let verified = Groth16::<Bn254>::verify_with_processed_vk(&pvk, &public_inputs, &proof)
        .map_err(|e| anyhow::anyhow!("Verification failed: {e}"))?;

    if !verified {
        bail!("Generated proof failed self-verification");
    }

    Ok(ProofResult {
        proof,
        public_inputs,
        vk,
        root,
        nullifiers,
        output_commitments,
        membership_roots: membership_roots_scalar,
        non_membership_roots: non_membership_roots_scalar,
    })
}
